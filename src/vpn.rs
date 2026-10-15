//! Full-device tunnelling on desktop. Changing routes needs admin rights, so a copy of this
//! executable is started elevated as a helper (`--tun-helper`). The helper creates a TUN
//! interface, points the default route and DNS at it (tproxy-config) and feeds it to tun2proxy,
//! which turns every connection into a request to our SOCKS server.
//!
//! The helper connects back to a localhost control socket opened by the app. It undoes all
//! network changes when told to stop or when that socket closes, so a crashed app never
//! leaves the machine without a working network.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tproxy_config::{IpCidr, TproxyArgs, TUN_GATEWAY, TUN_IPV4, TUN_NETMASK};
use tun2proxy::{ArgDns, Args, CancellationToken, ProxyParameters};

use crate::tunnel::SOCKS_ADDR;

pub const HELPER_ARG: &str = "--tun-helper";

const MTU: u16 = 1500;
/// Time for the user to answer the password / UAC prompt.
const ELEVATION_TIMEOUT: Duration = Duration::from_secs(120);
const SETUP_TIMEOUT: Duration = Duration::from_secs(30);

/// A running helper. Dropping it without `stop` still shuts the helper down (socket closes).
pub struct Vpn {
    control: OwnedWriteHalf,
    alive: watch::Receiver<bool>,
}

impl Vpn {
    /// Start the elevated helper and wait until all traffic is routed through the tunnel.
    /// `server` is the SSH server's address, which must keep using the real network.
    pub async fn start(server: IpAddr) -> Result<Vpn> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let token = random_token();
        let args = [HELPER_ARG.to_string(), port.to_string(), token.clone(), server.to_string()];

        let mut launch = elevate(&args).await?;
        let stream = tokio::select! {
            accepted = listener.accept() => accepted?.0,
            err = launch.failed() => return Err(err),
            _ = tokio::time::sleep(ELEVATION_TIMEOUT) => bail!("timed out waiting for administrator approval"),
        };

        let (reader, control) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();
        if read_line(&mut lines).await? != token {
            bail!("unexpected process on the VPN control socket");
        }
        let status = read_line(&mut lines).await?;
        if let Some(err) = status.strip_prefix("err ") {
            bail!("{err}");
        } else if status != "ok" {
            bail!("unexpected reply from the VPN helper: {status}");
        }

        // The helper never writes again; EOF means it has finished cleaning up and exited.
        let (tx, alive) = watch::channel(true);
        tokio::spawn(async move {
            // Hold the launcher process handle (osascript/pkexec) as long as the helper runs.
            let _launch = launch;
            while let Ok(Some(_)) = lines.next_line().await {}
            let _ = tx.send(false);
        });
        Ok(Vpn { control, alive })
    }

    pub fn is_alive(&self) -> bool {
        *self.alive.borrow()
    }

    /// Ask the helper to restore the network and wait until it has.
    pub async fn stop(mut self) {
        let _ = self.control.write_all(b"stop\n").await;
        let _ = tokio::time::timeout(Duration::from_secs(15), self.alive.wait_for(|alive| !alive)).await;
    }
}

async fn read_line(lines: &mut Lines<BufReader<OwnedReadHalf>>) -> Result<String> {
    let line = tokio::time::timeout(SETUP_TIMEOUT, lines.next_line())
        .await
        .context("the VPN helper did not respond")??;
    line.ok_or_else(|| anyhow!("the VPN helper exited unexpectedly"))
}

fn random_token() -> String {
    // RandomState is seeded from the OS RNG; good enough to tell our helper from a stray connection.
    let mut h = RandomState::new().build_hasher();
    h.write_u64(std::process::id().into());
    format!("{:016x}{:016x}", h.finish(), RandomState::new().build_hasher().finish())
}

/// The process that was asked to run the helper with admin rights.
struct Launch {
    #[cfg(unix)]
    child: tokio::process::Child,
}

impl Launch {
    /// Resolves only if the helper can no longer start (prompt dismissed, wrong password, ...).
    async fn failed(&mut self) -> anyhow::Error {
        #[cfg(unix)]
        {
            let status = self.child.wait().await;
            let mut stderr = String::new();
            if let Some(mut e) = self.child.stderr.take() {
                use tokio::io::AsyncReadExt;
                let _ = e.read_to_string(&mut stderr).await;
            }
            let stderr = stderr.trim();
            match status {
                Ok(_) if stderr.contains("-128") => anyhow!("administrator access was cancelled"),
                Ok(s) if s.code() == Some(126) => anyhow!("administrator access was cancelled"),
                Ok(s) if s.code() == Some(127) => anyhow!("no polkit agent available to ask for administrator access"),
                Ok(s) if stderr.is_empty() => anyhow!("the VPN helper exited ({s})"),
                Ok(_) => anyhow!("the VPN helper failed: {stderr}"),
                Err(e) => anyhow!("the VPN helper failed: {e}"),
            }
        }
        // ShellExecuteEx already reported a refused UAC prompt; the helper reports anything later.
        #[cfg(windows)]
        std::future::pending().await
    }
}

#[cfg(unix)]
async fn elevate(args: &[String]) -> Result<Launch> {
    extern "C" {
        fn geteuid() -> u32;
    }
    let exe = std::env::current_exe()?;
    // Already root (e.g. started with sudo, as the e2e tests in CI are): nothing to ask for.
    let (mut cmd, what) = if unsafe { geteuid() } == 0 {
        let mut cmd = tokio::process::Command::new(&exe);
        cmd.args(args);
        (cmd, "the VPN helper")
    } else {
        prompt_command(&exe, args)
    };
    let child = cmd
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("could not run {what}"))?;
    Ok(Launch { child })
}

/// Runs the helper behind the macOS administrator password dialog.
#[cfg(target_os = "macos")]
fn prompt_command(exe: &std::path::Path, args: &[String]) -> (tokio::process::Command, &'static str) {
    let mut cmd = shell_quote(&exe.to_string_lossy());
    for a in args {
        cmd.push(' ');
        cmd.push_str(&shell_quote(a));
    }
    let script = format!(
        "do shell script \"{}\" with prompt \"SSH VPN needs administrator rights to route all traffic \
         through the tunnel.\" with administrator privileges",
        cmd.replace('\\', "\\\\").replace('"', "\\\"")
    );
    // osascript keeps running as long as the helper does.
    let mut osascript = tokio::process::Command::new("/usr/bin/osascript");
    osascript.args(["-e", &script]);
    (osascript, "osascript")
}

#[cfg(target_os = "macos")]
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Runs the helper through polkit, which asks for the password.
#[cfg(all(unix, not(target_os = "macos")))]
fn prompt_command(exe: &std::path::Path, args: &[String]) -> (tokio::process::Command, &'static str) {
    let mut pkexec = tokio::process::Command::new("pkexec");
    pkexec.arg(exe).args(args);
    (pkexec, "pkexec (is polkit installed?)")
}

#[cfg(windows)]
async fn elevate(args: &[String]) -> Result<Launch> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOASYNC, SHELLEXECUTEINFOW};
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
        s.encode_wide().chain(Some(0)).collect()
    }
    let exe = wide(std::env::current_exe()?.as_os_str());
    // The arguments are a flag, numbers, hex and an IP address: nothing that needs quoting.
    let params = wide(args.join(" ").as_ref());
    let verb = wide("runas".as_ref());

    // Blocks while the UAC prompt is shown.
    tokio::task::spawn_blocking(move || {
        let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
        info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_NOASYNC;
        info.lpVerb = verb.as_ptr();
        info.lpFile = exe.as_ptr();
        info.lpParameters = params.as_ptr();
        info.nShow = SW_HIDE;
        if unsafe { ShellExecuteExW(&mut info) } == 0 {
            let err = std::io::Error::last_os_error();
            // ERROR_CANCELLED: the user said no to the UAC prompt.
            if err.raw_os_error() == Some(1223) {
                bail!("administrator access was cancelled");
            }
            bail!("could not start the VPN helper: {err}");
        }
        Ok(Launch {})
    })
    .await?
}

/// Entry point of the elevated helper process. Returns the process exit code.
pub fn helper_main(args: &[String]) -> i32 {
    let (Some(port), Some(token), Some(server)) = (args.first(), args.get(1), args.get(2)) else {
        return 2;
    };
    let (Ok(port), Ok(server)) = (port.parse::<u16>(), server.parse::<IpAddr>()) else {
        return 2;
    };
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return 1,
    };
    let result = rt.block_on(helper(port, token, server));
    // The network is already restored here. Don't wait on the TUN device's blocking reader,
    // which a plain runtime drop would do forever.
    rt.shutdown_timeout(Duration::from_secs(1));
    match result {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

async fn helper(port: u16, token: &str, server: IpAddr) -> Result<()> {
    let stream = TcpStream::connect(("127.0.0.1", port)).await?;
    let (reader, mut control) = stream.into_split();
    control.write_all(format!("{token}\n").as_bytes()).await?;

    #[cfg(target_os = "macos")]
    let dns = macos_dns::save();
    let (device, state) = match setup(server).await {
        Ok(v) => v,
        Err(e) => {
            #[cfg(target_os = "macos")]
            dns.restore();
            let msg = format!("{e:#}").replace('\n', " ");
            control.write_all(format!("err {msg}\n").as_bytes()).await?;
            return Err(e);
        }
    };
    control.write_all(b"ok\n").await?;

    let token = CancellationToken::new();
    let mut args = Args::default();
    args.proxy(ProxyParameters::try_from(format!("socks5://{SOCKS_ADDR}").as_str())?)
        // Hand hostnames to the SOCKS server so DNS is resolved on the SSH server side.
        .dns(ArgDns::Virtual)
        .setup(false);
    args.max_sessions = 1000;
    let run = tokio::spawn(tun2proxy::run(device, MTU, args, token.clone()));

    // Run until the app says stop, its socket closes (app quit or crashed) or we are signalled.
    let mut lines = BufReader::new(reader).lines();
    tokio::select! {
        _ = async { while let Ok(Some(line)) = lines.next_line().await { if line == "stop" { break } } } => {}
        _ = tokio::signal::ctrl_c() => {}
        _ = terminated() => {}
    }

    token.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), run).await;
    let removed = tproxy_config::tproxy_remove(Some(state)).await;
    #[cfg(target_os = "macos")]
    dns.restore();
    #[cfg(windows)]
    windows_dns::remove();
    removed?;
    Ok(())
}

/// tproxy-config's macOS cleanup writes the DNS servers it found back with
/// `networksetup -setdnsservers`, which turns DHCP-provided servers into a permanent manual
/// setting. Snapshot every service's own setting first and put it back exactly afterwards.
#[cfg(target_os = "macos")]
mod macos_dns {
    use std::process::Command;

    pub struct Saved(Vec<(String, Vec<String>)>);

    fn networksetup(args: &[&str]) -> String {
        Command::new("/usr/sbin/networksetup")
            .args(args)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default()
    }

    pub fn save() -> Saved {
        let services = networksetup(&["-listallnetworkservices"]);
        Saved(
            services
                .lines()
                .skip(1) // "An asterisk (*) denotes that a network service is disabled."
                .map(|l| l.trim_start_matches('*').to_string())
                .filter(|s| !s.is_empty())
                .map(|svc| {
                    // Either one server per line or "There aren't any DNS Servers set on ...".
                    let servers = networksetup(&["-getdnsservers", &svc])
                        .lines()
                        .filter(|l| l.parse::<std::net::IpAddr>().is_ok())
                        .map(str::to_owned)
                        .collect();
                    (svc, servers)
                })
                .collect(),
        )
    }

    impl Saved {
        pub fn restore(&self) {
            for (svc, servers) in &self.0 {
                let mut args = vec!["-setdnsservers", svc.as_str()];
                if servers.is_empty() {
                    args.push("Empty");
                } else {
                    args.extend(servers.iter().map(String::as_str));
                }
                networksetup(&args);
            }
        }
    }
}

#[cfg(unix)]
async fn terminated() {
    use tokio::signal::unix::{signal, SignalKind};
    match signal(SignalKind::terminate()) {
        Ok(mut s) => {
            s.recv().await;
        }
        Err(_) => std::future::pending().await,
    }
}

#[cfg(windows)]
async fn terminated() {
    std::future::pending().await
}

async fn setup(server: IpAddr) -> Result<(tun::AsyncDevice, tproxy_config::TproxyState)> {
    let mut config = tun::Configuration::default();
    config.address(TUN_IPV4).netmask(TUN_NETMASK).destination(TUN_GATEWAY).mtu(MTU).up();

    #[cfg(target_os = "linux")]
    config.platform_config(|cfg| {
        #[allow(deprecated)]
        cfg.packet_information(true);
        cfg.ensure_root_privileges(true);
    });
    // macOS utun frames carry a 4-byte protocol header; the platform default (on) handles it.
    #[cfg(windows)]
    {
        let dll = install_wintun()?;
        config.platform_config(|cfg| {
            cfg.wintun_file(&dll);
            // Fixed GUID so Windows reuses one adapter instead of adding a new one every time.
            cfg.device_guid(0x5348_5650_4e00_4d2d_8a5e_7f3c_1d2b_9e01);
        });
    }

    let device = tun::create_as_async(&config).context("could not create the TUN interface")?;
    let tun_name = tun::AbstractDevice::tun_name(&*device).context("could not name the TUN interface")?;

    let socks: SocketAddr = SOCKS_ADDR.parse()?;
    // Only IPv4 traffic is routed into the tunnel, so only an IPv4 server needs a bypass route.
    // Never for loopback (e.g. SSH through a local port forward): routing 127.0.0.1 to the
    // gateway would also cut tun2proxy off from the SOCKS server.
    let bypass: Vec<IpCidr> = match server {
        IpAddr::V4(ip) if !ip.is_loopback() => vec![IpCidr::new_host(server)],
        _ => vec![],
    };
    let tproxy = TproxyArgs::new().tun_name(&tun_name).proxy_addr(socks).bypass_ips(&bypass);
    let state = tproxy_config::tproxy_setup(&tproxy).await.context("could not change the network routes")?;
    #[cfg(windows)]
    if let Err(e) = windows_dns::send_all_to(TUN_GATEWAY) {
        let _ = tproxy_config::tproxy_remove(Some(state)).await;
        return Err(e);
    }
    Ok((device, state))
}

/// Windows asks the DNS servers of every adapter, not only the tunnel's, so lookups would still
/// leak to the local network. A catch-all Name Resolution Policy Table rule (what Windows' own
/// VPN client uses) sends every lookup to the tunnel's DNS instead.
#[cfg(windows)]
mod windows_dns {
    use std::net::IpAddr;
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    use anyhow::{bail, Result};

    /// Marks our rule, so a rule left behind by a killed helper can be found and removed.
    const COMMENT: &str = "ssh-vpn";
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    fn powershell(script: &str) -> std::io::Result<std::process::Output> {
        Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
    }

    pub fn send_all_to(server: IpAddr) -> Result<()> {
        remove();
        let out = powershell(&format!(
            "Add-DnsClientNrptRule -Namespace '.' -NameServers '{server}' -Comment '{COMMENT}'; Clear-DnsClientCache"
        ))?;
        if !out.status.success() || !out.stderr.is_empty() {
            bail!("could not redirect DNS into the tunnel: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(())
    }

    pub fn remove() {
        let _ = powershell(&format!(
            "Get-DnsClientNrptRule | Where-Object Comment -eq '{COMMENT}' | Remove-DnsClientNrptRule -Force; Clear-DnsClientCache"
        ));
    }
}

/// The Wintun driver DLL, embedded so the app stays a single .exe; written next to it on first use.
#[cfg(windows)]
fn install_wintun() -> Result<std::path::PathBuf> {
    const DLL: &[u8] = include_bytes!("../assets/wintun/wintun.dll");
    let path = std::env::current_exe()?.with_file_name("wintun.dll");
    if std::fs::read(&path).ok().as_deref() != Some(DLL) {
        std::fs::write(&path, DLL).with_context(|| format!("could not write {}", path.display()))?;
    }
    Ok(path)
}
