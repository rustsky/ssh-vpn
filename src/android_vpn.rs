//! Android system-wide tunnelling: `SshVpnService` (android/MainActivity.kt) creates a TUN
//! interface routing every app except this one, and tun2proxy turns its packets into
//! connections to our local SOCKS server, which forwards them over SSH.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use jni::objects::{JClass, JObject, JString};
use jni::sys::jint;
use jni::{JNIEnv, JavaVM};
use tokio::sync::oneshot;
use tun2proxy::{ArgDns, Args, CancellationToken, ProxyParameters};

use crate::tunnel::SOCKS_ADDR;

const MTU: u16 = 1500;

/// Waiting for `SshVpnService` to hand over the TUN fd (or report why it could not).
static PENDING: Mutex<Option<oneshot::Sender<Result<i32, String>>>> = Mutex::new(None);
static RUNNING: Mutex<Option<CancellationToken>> = Mutex::new(None);
static REVOKED: AtomicBool = AtomicBool::new(false);

/// Ask for VPN permission if needed, bring up the TUN interface and start routing it.
pub async fn start() -> Result<()> {
    android_logger::init_once(
        android_logger::Config::default().with_tag("ssh-vpn").with_max_level(log::LevelFilter::Info),
    );
    let (tx, rx) = oneshot::channel();
    *PENDING.lock().unwrap() = Some(tx);
    REVOKED.store(false, Ordering::SeqCst);
    call_activity("startVpn")?;

    // Generous timeout: the user may be reading the system consent dialog.
    let fd = tokio::time::timeout(Duration::from_secs(120), rx)
        .await
        .context("timed out waiting for VPN permission")?
        .context("VPN service went away")?
        .map_err(|e| anyhow!(e))?;
    log::info!("TUN ready (fd {fd}), starting tun2proxy");

    let mut args = Args::default();
    args.proxy(ProxyParameters::try_from(format!("socks5://{SOCKS_ADDR}").as_str())?)
        .tun_fd(Some(fd))
        .close_fd_on_drop(true)
        // Hand hostnames to the SOCKS server so DNS is resolved on the SSH server side.
        .dns(ArgDns::Virtual)
        .ipv6_enabled(true)
        .setup(false);
    args.max_sessions = 1000;

    let token = CancellationToken::new();
    *RUNNING.lock().unwrap() = Some(token.clone());
    tokio::spawn(async move {
        match tun2proxy::general_run_async(args, MTU, false, token).await {
            Ok(sessions) => log::info!("tun2proxy finished after {sessions} sessions"),
            Err(e) => log::error!("tun2proxy failed: {e}"),
        }
    });
    Ok(())
}

/// Tear down the TUN interface. Safe to call when not running.
pub fn stop() {
    if let Some(token) = RUNNING.lock().unwrap().take() {
        // tun2proxy owns the fd and closes it on shutdown, which removes the VPN.
        token.cancel();
    }
    let _ = call_activity("stopVpn");
}

/// True once if the user revoked the VPN from system settings (or another VPN took over).
pub fn take_revoked() -> bool {
    REVOKED.swap(false, Ordering::SeqCst)
}

fn call_activity(method: &str) -> Result<()> {
    let ctx = ndk_context::android_context();
    let vm = unsafe { JavaVM::from_raw(ctx.vm().cast()) }?;
    let mut env = vm.attach_current_thread()?;
    let activity = unsafe { JObject::from_raw(ctx.context().cast()) };
    let res = env.call_method(&activity, method, "()V", &[]);
    if env.exception_check()? {
        env.exception_describe()?;
        env.exception_clear()?;
        bail!("MainActivity.{method}() threw");
    }
    res?;
    Ok(())
}

fn finish_pending(result: Result<i32, String>) {
    match PENDING.lock().unwrap().take() {
        Some(tx) => {
            if let Err(Ok(fd)) = tx.send(result) {
                // Nobody is waiting any more; don't leak the interface.
                unsafe { libc_close(fd) };
            }
        }
        None => {
            if let Ok(fd) = result {
                unsafe { libc_close(fd) };
            }
        }
    }
}

extern "C" {
    #[link_name = "close"]
    fn libc_close(fd: i32) -> i32;
}

#[no_mangle]
pub extern "system" fn Java_dev_dioxus_main_VpnBridge_onTunReady(_env: JNIEnv, _class: JClass, fd: jint) {
    finish_pending(Ok(fd));
}

#[no_mangle]
pub extern "system" fn Java_dev_dioxus_main_VpnBridge_onTunFailed(mut env: JNIEnv, _class: JClass, reason: JString) {
    let reason: String = env.get_string(&reason).map(Into::into).unwrap_or_else(|_| "VPN failed".into());
    finish_pending(Err(reason));
}

#[no_mangle]
pub extern "system" fn Java_dev_dioxus_main_VpnBridge_onRevoked(_env: JNIEnv, _class: JClass) {
    REVOKED.store(true, Ordering::SeqCst);
}
