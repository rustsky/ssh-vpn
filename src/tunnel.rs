//! SSH dynamic port forwarding: a local SOCKS4/4a/5 server whose connections are
//! tunnelled through `direct-tcpip` channels (equivalent of SSH.NET's `ForwardedPortDynamic`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use russh::client;
use russh::keys::{HashAlg, PublicKeyOrCertificate};
use russh::Disconnect;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::settings::Settings;

pub const SOCKS_ADDR: &str = "127.0.0.1:9000";

#[derive(Debug, Clone, PartialEq)]
enum HostKeyCheck {
    Pending,
    /// Unknown host; the fingerprint should be remembered once auth succeeds.
    New(String),
    Trusted,
    Mismatch { expected: String, got: String },
}

struct Client {
    expected: Option<String>,
    result: Arc<Mutex<HostKeyCheck>>,
}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let got = match key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key.fingerprint(HashAlg::Sha256),
            PublicKeyOrCertificate::Certificate(cert) => cert.public_key().fingerprint(HashAlg::Sha256),
        }
        .to_string();

        let (check, ok) = match &self.expected {
            None => (HostKeyCheck::New(got), true),
            Some(expected) if *expected == got => (HostKeyCheck::Trusted, true),
            Some(expected) => (HostKeyCheck::Mismatch { expected: expected.clone(), got }, false),
        };
        *self.result.lock().unwrap() = check;
        Ok(ok)
    }
}

pub struct Tunnel {
    session: Arc<client::Handle<Client>>,
    listener: JoinHandle<()>,
    server_ip: IpAddr,
}

pub struct Started {
    pub tunnel: Tunnel,
    /// Set when the server was seen for the first time; caller should persist it.
    pub new_fingerprint: Option<String>,
}

impl Tunnel {
    pub async fn start(settings: &Settings) -> Result<Started> {
        let config = Arc::new(client::Config {
            nodelay: true,
            keepalive_interval: Some(Duration::from_secs(15)),
            keepalive_max: 3,
            ..Default::default()
        });

        let host_key = Arc::new(Mutex::new(HostKeyCheck::Pending));
        let handler = Client {
            expected: settings.known_hosts.get(&settings.host_id()).cloned(),
            result: host_key.clone(),
        };

        let addr = (settings.ip.trim(), settings.port);
        let connect = async {
            // Connect ourselves rather than via `client::connect` to learn the server's IP,
            // which the full VPN must route around the tunnel.
            let stream = TcpStream::connect(addr).await.map_err(russh::Error::from)?;
            let _ = stream.set_nodelay(true);
            let server_ip = stream.peer_addr().map_err(russh::Error::from)?.ip();
            client::connect_stream(config, stream, handler).await.map(|s| (s, server_ip))
        };
        let (mut session, server_ip) = match tokio::time::timeout(Duration::from_secs(20), connect).await {
            Err(_) => bail!("timed out connecting to {}", settings.host_id()),
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                if let HostKeyCheck::Mismatch { expected, got } = &*host_key.lock().unwrap() {
                    bail!(
                        "HOST KEY CHANGED for {}!\nexpected {expected}\ngot      {got}\n\
                         This may be a man-in-the-middle attack. If the server key really changed, \
                         remove it from known_hosts in the settings file.",
                        settings.host_id()
                    );
                }
                return Err(anyhow!(e).context(format!("could not connect to {}", settings.host_id())));
            }
        };

        let auth = session
            .authenticate_password(&settings.username, &settings.password)
            .await
            .context("authentication error")?;
        if !auth.success() {
            bail!("authentication failed (wrong username or password)");
        }

        let listener = TcpListener::bind(SOCKS_ADDR)
            .await
            .with_context(|| format!("could not listen on {SOCKS_ADDR}"))?;

        let session = Arc::new(session);
        let accept_session = session.clone();
        let listener = tokio::spawn(async move {
            while let Ok((stream, peer)) = listener.accept().await {
                let session = accept_session.clone();
                tokio::spawn(async move {
                    let _ = handle_socks(stream, peer, session).await;
                });
            }
        });

        let new_fingerprint = match &*host_key.lock().unwrap() {
            HostKeyCheck::New(fp) => Some(fp.clone()),
            _ => None,
        };
        Ok(Started { tunnel: Tunnel { session, listener, server_ip }, new_fingerprint })
    }

    pub fn server_ip(&self) -> IpAddr {
        self.server_ip
    }

    pub fn is_connected(&self) -> bool {
        !self.session.is_closed()
    }

    pub async fn stop(self) {
        self.listener.abort();
        let _ = self.session.disconnect(Disconnect::ByApplication, "", "en").await;
    }
}

enum Target {
    Ip(std::net::IpAddr),
    Domain(String),
}

impl Target {
    fn host(&self) -> String {
        match self {
            Target::Ip(ip) => ip.to_string(),
            Target::Domain(d) => d.clone(),
        }
    }
}

async fn handle_socks(
    mut stream: TcpStream,
    peer: SocketAddr,
    session: Arc<client::Handle<Client>>,
) -> Result<()> {
    stream.set_nodelay(true)?;
    let version = stream.read_u8().await?;
    let (target, port) = match version {
        5 => socks5_request(&mut stream).await?,
        4 => socks4_request(&mut stream).await?,
        v => bail!("unsupported SOCKS version {v}"),
    };

    let channel = session
        .channel_open_direct_tcpip(target.host(), port as u32, peer.ip().to_string(), peer.port() as u32)
        .await;

    let channel = match channel {
        Ok(c) => {
            reply(&mut stream, version, true).await?;
            c
        }
        Err(e) => {
            let _ = reply(&mut stream, version, false).await;
            return Err(e.into());
        }
    };

    let mut remote = channel.into_stream();
    let _ = tokio::io::copy_bidirectional(&mut stream, &mut remote).await;
    Ok(())
}

async fn socks5_request(s: &mut TcpStream) -> Result<(Target, u16)> {
    let nmethods = s.read_u8().await? as usize;
    let mut methods = vec![0u8; nmethods];
    s.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        s.write_all(&[5, 0xFF]).await?;
        bail!("client requires SOCKS5 authentication");
    }
    s.write_all(&[5, 0x00]).await?;

    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[0] != 5 {
        bail!("bad SOCKS5 request");
    }
    if head[1] != 0x01 {
        // Only CONNECT is supported: reply "command not supported".
        s.write_all(&[5, 0x07, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        bail!("unsupported SOCKS5 command {}", head[1]);
    }
    let target = match head[3] {
        0x01 => {
            let mut b = [0u8; 4];
            s.read_exact(&mut b).await?;
            Target::Ip(Ipv4Addr::from(b).into())
        }
        0x03 => {
            let len = s.read_u8().await? as usize;
            let mut b = vec![0u8; len];
            s.read_exact(&mut b).await?;
            Target::Domain(String::from_utf8(b)?)
        }
        0x04 => {
            let mut b = [0u8; 16];
            s.read_exact(&mut b).await?;
            Target::Ip(Ipv6Addr::from(b).into())
        }
        t => bail!("unsupported SOCKS5 address type {t}"),
    };
    let port = s.read_u16().await?;
    Ok((target, port))
}

async fn socks4_request(s: &mut TcpStream) -> Result<(Target, u16)> {
    let cmd = s.read_u8().await?;
    let port = s.read_u16().await?;
    let mut ip = [0u8; 4];
    s.read_exact(&mut ip).await?;
    read_cstr(s).await?; // user id, ignored
    if cmd != 0x01 {
        s.write_all(&[0, 0x5B, 0, 0, 0, 0, 0, 0]).await?;
        bail!("unsupported SOCKS4 command {cmd}");
    }
    // SOCKS4a: 0.0.0.x (x != 0) means a domain name follows.
    let target = if ip[..3] == [0, 0, 0] && ip[3] != 0 {
        Target::Domain(read_cstr(s).await?)
    } else {
        Target::Ip(Ipv4Addr::from(ip).into())
    };
    Ok((target, port))
}

async fn read_cstr(s: &mut TcpStream) -> Result<String> {
    let mut out = Vec::new();
    loop {
        match s.read_u8().await? {
            0 => break,
            b if out.len() < 255 => out.push(b),
            _ => bail!("SOCKS4 string too long"),
        }
    }
    Ok(String::from_utf8(out)?)
}

async fn reply(s: &mut TcpStream, version: u8, ok: bool) -> Result<()> {
    if version == 5 {
        let code = if ok { 0x00 } else { 0x01 };
        s.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    } else {
        let code = if ok { 0x5A } else { 0x5B };
        s.write_all(&[0, code, 0, 0, 0, 0, 0, 0]).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(l.local_addr().unwrap()).await.unwrap();
        let (server, _) = l.accept().await.unwrap();
        (client, server)
    }

    #[tokio::test]
    async fn socks5_domain() {
        let (mut c, mut s) = pair().await;
        c.write_all(&[5, 1, 0, 5, 1, 0, 3, 11]).await.unwrap();
        c.write_all(b"example.com").await.unwrap();
        c.write_all(&443u16.to_be_bytes()).await.unwrap();
        assert_eq!(s.read_u8().await.unwrap(), 5);
        let (t, port) = socks5_request(&mut s).await.unwrap();
        assert_eq!((t.host().as_str(), port), ("example.com", 443));
        let mut greet = [0u8; 2];
        c.read_exact(&mut greet).await.unwrap();
        assert_eq!(greet, [5, 0]);
    }

    #[tokio::test]
    async fn socks5_ipv6() {
        let (mut c, mut s) = pair().await;
        c.write_all(&[5, 1, 0, 5, 1, 0, 4]).await.unwrap();
        c.write_all(&Ipv6Addr::LOCALHOST.octets()).await.unwrap();
        c.write_all(&80u16.to_be_bytes()).await.unwrap();
        s.read_u8().await.unwrap();
        let (t, port) = socks5_request(&mut s).await.unwrap();
        assert_eq!((t.host().as_str(), port), ("::1", 80));
    }

    #[tokio::test]
    async fn socks5_requires_noauth() {
        let (mut c, mut s) = pair().await;
        c.write_all(&[5, 1, 2]).await.unwrap();
        s.read_u8().await.unwrap();
        assert!(socks5_request(&mut s).await.is_err());
        let mut r = [0u8; 2];
        c.read_exact(&mut r).await.unwrap();
        assert_eq!(r, [5, 0xFF]);
    }

    #[tokio::test]
    async fn socks4_ip_and_4a_domain() {
        let (mut c, mut s) = pair().await;
        c.write_all(&[4, 1, 0, 80, 10, 0, 0, 1, b'u', 0]).await.unwrap();
        s.read_u8().await.unwrap();
        let (t, port) = socks4_request(&mut s).await.unwrap();
        assert_eq!((t.host().as_str(), port), ("10.0.0.1", 80));

        let (mut c, mut s) = pair().await;
        c.write_all(&[4, 1, 1, 187, 0, 0, 0, 1, 0]).await.unwrap();
        c.write_all(b"example.org\0").await.unwrap();
        s.read_u8().await.unwrap();
        let (t, port) = socks4_request(&mut s).await.unwrap();
        assert_eq!((t.host().as_str(), port), ("example.org", 443));
    }
}
