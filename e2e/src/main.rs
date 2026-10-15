//! End-to-end tests for ssh-vpn. Compiles the app's real tunnel/proxy/vpn modules against a
//! test SSH server (password auth, logs every direct-tcpip forward). See ../README.md.
#![allow(dead_code)]

#[path = "../../src/proxy.rs"]
mod proxy;
#[path = "../../src/settings.rs"]
mod settings;
#[path = "../../src/tunnel.rs"]
mod tunnel;
#[path = "../../src/vpn.rs"]
mod vpn;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use russh::server::{Auth, ChannelOpenHandle, Msg, Server as _, Session};
use russh::Channel;
use tokio::net::{TcpListener, TcpSocket, TcpStream};

/// Hostnames the tests fetch. Resolved before the VPN starts, so the test server (which runs on
/// the same machine as the VPN) can reach them without going back into the tunnel.
const TEST_HOSTS: &[&str] = &["example.com", "example.org"];

/// How the in-process test server keeps its own outgoing connections off the tunnel.
#[derive(Clone, Default)]
struct Egress {
    hosts: HashMap<String, IpAddr>,
    /// macOS: bind to the physical interface's address (scoped routing picks its gateway).
    src: Option<IpAddr>,
    /// Windows: pin sockets to the physical interface with IP_UNICAST_IF.
    ifindex: Option<u32>,
    /// Linux: SO_BINDTODEVICE to the physical interface (needs root, as the VPN tests do).
    device: Option<String>,
}

#[derive(Clone)]
struct Srv {
    log: Arc<Mutex<Vec<String>>>,
    egress: Egress,
}

impl russh::server::Server for Srv {
    type Handler = Srv;
    fn new_client(&mut self, _: Option<SocketAddr>) -> Srv {
        self.clone()
    }
}

impl russh::server::Handler for Srv {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, pw: &str) -> Result<Auth, Self::Error> {
        let ok = user == "test" && pw == "secret";
        eprintln!("[server] AUTH {user} {}", if ok { "accepted" } else { "rejected" });
        Ok(if ok { Auth::Accept } else { Auth::reject() })
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host: &str,
        port: u32,
        _: &str,
        _: u32,
        reply: ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        let line = format!("{host}:{port}");
        eprintln!("[server] FWD {line}");
        self.log.lock().unwrap().push(line);
        let (host, egress) = (host.to_string(), self.egress.clone());
        reply.accept().await;
        tokio::spawn(async move {
            match connect_out(&host, port as u16, &egress).await {
                Ok(mut out) => {
                    let mut ch = channel.into_stream();
                    let _ = tokio::io::copy_bidirectional(&mut ch, &mut out).await;
                }
                Err(e) => {
                    eprintln!("[server] connect {host}:{port} failed: {e:#}");
                    let _ = channel.close().await;
                }
            }
        });
        Ok(())
    }
}

async fn connect_out(host: &str, port: u16, egress: &Egress) -> Result<TcpStream> {
    let ip = match host.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => match egress.hosts.get(host) {
            Some(ip) => *ip,
            None => tokio::net::lookup_host((host, port)).await?.next().context("no address")?.ip(),
        },
    };
    let sock = if ip.is_ipv4() { TcpSocket::new_v4()? } else { TcpSocket::new_v6()? };
    if let Some(src) = egress.src {
        sock.bind(SocketAddr::new(src, 0))?;
    }
    #[cfg(windows)]
    if let Some(idx) = egress.ifindex {
        unicast_if(&sock, idx)?;
    }
    #[cfg(target_os = "linux")]
    if let Some(dev) = &egress.device {
        sock.bind_device(Some(dev.as_bytes()))?;
    }
    Ok(sock.connect(SocketAddr::new(ip, port)).await?)
}

#[cfg(windows)]
fn unicast_if(sock: &TcpSocket, idx: u32) -> std::io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{setsockopt, IPPROTO_IP, IP_UNICAST_IF, SOCKET_ERROR};
    // IPv4 takes the interface index in network byte order.
    let v = idx.to_be();
    let r = unsafe { setsockopt(sock.as_raw_socket() as _, IPPROTO_IP, IP_UNICAST_IF, (&v as *const u32).cast(), 4) };
    if r == SOCKET_ERROR {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

async fn egress() -> Result<Egress> {
    let mut hosts = HashMap::new();
    for h in TEST_HOSTS {
        if let Some(a) = tokio::net::lookup_host((*h, 443)).await?.find(SocketAddr::is_ipv4) {
            hosts.insert(h.to_string(), a.ip());
        }
    }
    let mut e = Egress { hosts, ..Default::default() };
    #[cfg(target_os = "macos")]
    {
        let iface = sh("route -n get default | awk '/interface:/{print $2}'");
        e.src = Some(sh(&format!("ipconfig getifaddr {iface}")).parse().with_context(|| format!("no IPv4 on {iface}"))?);
    }
    #[cfg(target_os = "linux")]
    {
        e.device = Some(sh("ip -4 route show default | awk '{print $5; exit}'")).filter(|d| !d.is_empty());
        // Replies to those pinned connections arrive on the physical interface while the route
        // back to their source points into the tunnel; strict reverse-path filtering would drop them.
        if let Some(dev) = &e.device {
            sh(&format!("sysctl -qw net.ipv4.conf.all.rp_filter=2 net.ipv4.conf.{dev}.rp_filter=2"));
        }
    }
    #[cfg(windows)]
    {
        let idx = sh("(Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Sort-Object RouteMetric | Select-Object -First 1).InterfaceIndex");
        e.ifindex = Some(idx.parse().with_context(|| format!("default route interface index: {idx:?}"))?);
    }
    Ok(e)
}

fn hostkey() -> Result<PathBuf> {
    let path = std::env::temp_dir().join("ssh-vpn-e2e-hostkey");
    if !path.exists() {
        let ok = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&path)
            .status()
            .context("ssh-keygen")?
            .success();
        if !ok {
            bail!("ssh-keygen failed");
        }
    }
    Ok(path)
}

async fn start_server(addr: &str, egress: Egress) -> Result<(u16, Arc<Mutex<Vec<String>>>)> {
    let key = russh::keys::load_secret_key(hostkey()?, None)?;
    let config = Arc::new(russh::server::Config {
        keys: vec![key],
        auth_rejection_time: Duration::from_millis(50),
        auth_rejection_time_initial: Some(Duration::ZERO),
        ..Default::default()
    });
    let log = Arc::new(Mutex::new(Vec::new()));
    let mut srv = Srv { log: log.clone(), egress };
    let listener = TcpListener::bind(addr).await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        let _ = srv.run_on_socket(config, &listener).await;
    });
    Ok((port, log))
}

fn settings(port: u16, password: &str) -> settings::Settings {
    settings::Settings {
        ip: "127.0.0.1".into(),
        port,
        username: "test".into(),
        password: password.into(),
        full_vpn: true,
        known_hosts: HashMap::new(),
    }
}

fn sh(cmd: &str) -> String {
    #[cfg(windows)]
    let out = Command::new("powershell").args(["-NoProfile", "-Command", cmd]).output();
    #[cfg(not(windows))]
    let out = Command::new("sh").args(["-c", cmd]).output();
    out.map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default()
}

fn curl(extra: &str, url: &str) -> String {
    let bin = if cfg!(windows) { "curl.exe" } else { "curl" };
    sh(&format!("{bin} -s -m 15 -o {} -w '%{{http_code}}' {extra} {url}", if cfg!(windows) { "NUL" } else { "/dev/null" }))
}

fn dns_a(name: &str) -> String {
    if cfg!(windows) {
        sh(&format!("(Resolve-DnsName {name} -Type A -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue | Where-Object IPAddress | Select-Object -First 1).IPAddress"))
    } else {
        sh(&format!("dig +short +time=3 +tries=1 {name} A | head -1"))
    }
}

fn check(name: &str, ok: bool, detail: impl std::fmt::Display) -> bool {
    println!("{} {name}: {detail}", if ok { "PASS" } else { "FAIL" });
    ok
}

fn count(log: &Mutex<Vec<String>>, needle: &str) -> usize {
    log.lock().unwrap().iter().filter(|l| l.contains(needle)).count()
}

/// Default route(s) and DNS servers, for before/after comparisons.
fn net_state() -> String {
    if cfg!(windows) {
        sh("$r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue | Sort-Object RouteMetric | ForEach-Object { \"$($_.InterfaceAlias)->$($_.NextHop)\" }; \
            $d = Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } | ForEach-Object { \"$($_.InterfaceAlias)=$($_.ServerAddresses -join ',')\" }; \
            \"routes: $($r -join ' ') dns: $($d -join ' ')\"")
    } else if cfg!(target_os = "macos") {
        sh("networksetup -getdnsservers Wi-Fi 2>/dev/null | tr '\\n' ' '; route -n get default | grep -E 'gateway|interface' | tr -s ' ' | tr '\\n' ' '; \
            scutil --dns | grep 'nameserver\\[0\\]' | head -1 | tr -s ' '")
    } else {
        sh("ip -4 route show | sort | tr '\\n' ';'; grep nameserver /etc/resolv.conf | tr '\\n' ' '")
    }
}

fn routed_via_tun(state: &str) -> bool {
    if cfg!(windows) {
        // Highest-priority default route is the Wintun adapter.
        state.trim_start_matches("routes: ").starts_with("wintun")
    } else {
        state.contains("utun") || state.contains("tun0")
    }
}

async fn tunnel_basic() -> Result<bool> {
    let (port, log) = start_server("127.0.0.1:0", Egress::default()).await?;
    let mut ok = true;

    let started = tunnel::Tunnel::start(&settings(port, "secret")).await?;
    ok &= check("first connect returns host fingerprint", started.new_fingerprint.is_some(), format!("{:?}", started.new_fingerprint));
    ok &= check("server ip recorded", started.tunnel.server_ip().to_string() == "127.0.0.1", started.tunnel.server_ip());
    let code = curl("--socks5-hostname 127.0.0.1:9000", "https://example.com");
    ok &= check("HTTPS via SOCKS5 (remote DNS)", code == "200", &code);
    ok &= check("server forwarded example.com:443", count(&log, "example.com:443") >= 1, format!("{:?}", log.lock().unwrap()));
    let code = curl("--socks4a 127.0.0.1:9000", "http://example.com");
    ok &= check("HTTP via SOCKS4a", code == "200", &code);
    let code = curl("--socks5 127.0.0.1:9000", "http://1.1.1.1");
    ok &= check("IP target via SOCKS5", code == "301" || code == "200", &code);
    ok &= check("is_connected", started.tunnel.is_connected(), "");
    let fp = started.new_fingerprint.clone().unwrap();
    started.tunnel.stop().await;
    let code = curl("--socks5-hostname 127.0.0.1:9000", "https://example.com");
    ok &= check("SOCKS closed after stop", code == "000", &code);

    let mut s = settings(port, "secret");
    s.known_hosts.insert(s.host_id(), fp);
    let again = tunnel::Tunnel::start(&s).await?;
    ok &= check("reconnect with trusted key", again.new_fingerprint.is_none(), "no new fingerprint");
    again.tunnel.stop().await;

    let err = tunnel::Tunnel::start(&settings(port, "wrong")).await.err().map(|e| format!("{e:#}")).unwrap_or_default();
    ok &= check("wrong password rejected", err.contains("authentication failed"), &err);

    let mut s = settings(port, "secret");
    s.known_hosts.insert(s.host_id(), "SHA256:not-the-key".into());
    let err = tunnel::Tunnel::start(&s).await.err().map(|e| format!("{e:#}")).unwrap_or_default();
    ok &= check("changed host key refused", err.contains("HOST KEY CHANGED"), err.lines().next().unwrap_or(""));

    let err = tunnel::Tunnel::start(&settings(1, "secret")).await.err().map(|e| format!("{e:#}")).unwrap_or_default();
    ok &= check("unreachable server error", err.contains("could not connect"), &err);
    Ok(ok)
}

/// (SOCKS proxy enabled, description) as the OS reports it.
fn proxy_state() -> (bool, String) {
    #[cfg(windows)]
    {
        use winreg::enums::HKEY_CURRENT_USER;
        let key = winreg::RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
            .unwrap();
        let enable: u32 = key.get_value("ProxyEnable").unwrap_or(0);
        let server: String = key.get_value("ProxyServer").unwrap_or_default();
        (enable == 1, format!("ProxyEnable={enable} ProxyServer={server}"))
    }
    #[cfg(not(windows))]
    {
        let s = sh("scutil --proxy | grep -E 'SOCKS(Enable|Port|Proxy)' | tr -s ' ' | tr '\\n' ' '");
        (s.contains("SOCKSEnable : 1"), s)
    }
}

async fn proxy_test() -> Result<bool> {
    if cfg!(target_os = "linux") {
        println!("SKIP proxy test: needs a GNOME session");
        return Ok(true);
    }
    let (enabled, before) = proxy_state();
    if enabled {
        bail!("a proxy is already enabled ({before}); not touching it");
    }
    let mut ok = true;
    let set = proxy::set();
    ok &= check("proxy::set", set.is_ok(), format!("{set:?}"));
    let (enabled, during) = proxy_state();
    ok &= check("system proxy points at 127.0.0.1:9000", enabled && during.contains("9000"), &during);
    let unset = proxy::unset();
    ok &= check("proxy::unset", unset.is_ok(), format!("{unset:?}"));
    let (enabled, after) = proxy_state();
    ok &= check("proxy disabled again", !enabled, &after);
    Ok(ok)
}

/// mode: "full" (approve the prompt), "cancel" (cancel it), "crash" (approve, then abort).
async fn vpn_test(mode: &str) -> Result<bool> {
    // E2E_SERVER=ip:port: use a server outside this network namespace; the caller checks its log.
    let remote = std::env::var("E2E_SERVER").ok();
    let (cfg, log) = match &remote {
        Some(addr) => {
            let addr: SocketAddr = addr.parse()?;
            let mut s = settings(addr.port(), "secret");
            s.ip = addr.ip().to_string();
            (s, Arc::new(Mutex::new(Vec::new())))
        }
        None => {
            let (port, log) = start_server("127.0.0.1:0", egress().await?).await?;
            (settings(port, "secret"), log)
        }
    };
    let remote = remote.is_some();
    let started = tunnel::Tunnel::start(&cfg).await?;
    let before = net_state();
    println!("network before: {before}");
    let mut ok = true;

    println!(">>> admin prompt: {}", if mode == "cancel" { "CANCEL it" } else { "APPROVE it" });
    let res = vpn::Vpn::start(started.tunnel.server_ip()).await;
    if mode == "cancel" {
        let err = res.err().map(|e| format!("{e:#}")).unwrap_or_else(|| "started!".into());
        ok &= check("cancelled prompt reported", err.contains("cancelled"), &err);
        ok &= check("network untouched", net_state() == before, net_state());
        return Ok(ok);
    }
    let v = match res {
        Ok(v) => v,
        Err(e) => return Ok(check("Vpn::start", false, format!("{e:#}"))),
    };
    ok &= check("Vpn::start", true, "helper reported ok");
    let during = net_state();
    println!("network during: {during}");
    ok &= check("default route via TUN", routed_via_tun(&during), &during);
    ok &= check("ssh server still reachable", started.tunnel.is_connected(), "");

    let n = count(&log, "example.com:443");
    let code = curl("", "https://example.com");
    ok &= check("plain HTTPS (no proxy flag) works", code == "200", &code);
    ok &= check("…and went through SSH by hostname", remote || count(&log, "example.com:443") > n, format!("{:?}", log.lock().unwrap()));
    let n = count(&log, "example.org:80");
    let code = curl("", "http://example.org");
    ok &= check("plain HTTP works", code == "200", &code);
    ok &= check("…and went through SSH", remote || count(&log, "example.org:80") > n, "");
    let ip = dns_a("example.org");
    ok &= check("DNS answers via virtual DNS pool (198.18/15)", ip.starts_with("198.18.") || ip.starts_with("198.19."), &ip);
    let n = log.lock().unwrap().len();
    let code = curl("", "http://1.1.1.1");
    ok &= check(
        "IP literal goes through SSH",
        (remote || log.lock().unwrap().len() > n) && (code == "301" || code == "200"),
        format!("{code} {:?}", log.lock().unwrap().last()),
    );
    ok &= check("helper alive", v.is_alive(), "");

    if mode == "crash" {
        println!("aborting while the VPN is up (the helper must restore the network)");
        std::process::abort();
    }

    v.stop().await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let after = net_state();
    println!("network after: {after}");
    ok &= check("routes + DNS restored", after == before, &after);
    let n = log.lock().unwrap().len();
    let code = curl("", "https://example.com");
    ok &= check("direct HTTPS after stop", code == "200", &code);
    ok &= check("…not through SSH any more", remote || log.lock().unwrap().len() == n, "");
    started.tunnel.stop().await;
    Ok(ok)
}

#[tokio::main]
async fn run(args: Vec<String>) -> Result<bool> {
    match args.first().map(String::as_str) {
        Some("server") => {
            let addr = args.get(1).map(String::as_str).unwrap_or("0.0.0.0:2222");
            let (port, _) = start_server(addr, Egress::default()).await?;
            eprintln!("[server] listening on {port}");
            std::future::pending::<()>().await;
            Ok(true)
        }
        Some("tunnel") => tunnel_basic().await,
        Some("proxy") => proxy_test().await,
        Some("vpn") => vpn_test(args.get(1).map(String::as_str).unwrap_or("full")).await,
        _ => bail!("usage: e2e server [addr] | tunnel | proxy | vpn [full|cancel|crash]"),
    }
}

struct FileLog(Mutex<std::fs::File>);

impl log::Log for FileLog {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }
    fn log(&self, r: &log::Record) {
        use std::io::Write;
        let _ = writeln!(self.0.lock().unwrap(), "{} {} {}", r.level(), r.target(), r.args());
    }
    fn flush(&self) {}
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some(vpn::HELPER_ARG) {
        // The helper runs elevated and detached; leave a log to debug from.
        if let Ok(f) = std::fs::File::create(std::env::temp_dir().join("ssh-vpn-e2e-helper.log")) {
            let _ = log::set_boxed_logger(Box::new(FileLog(Mutex::new(f))));
            log::set_max_level(log::LevelFilter::Debug);
        }
        std::process::exit(vpn::helper_main(&args[1..]));
    }
    match run(args) {
        Ok(true) => println!("ALL PASSED"),
        Ok(false) => {
            println!("SOME FAILED");
            std::process::exit(1)
        }
        Err(e) => {
            println!("ERROR {e:#}");
            std::process::exit(2)
        }
    }
}
