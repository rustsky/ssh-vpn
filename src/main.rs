#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
#![cfg_attr(target_os = "android", allow(dead_code, unused_imports))]

#[cfg(target_os = "android")]
mod android_vpn;
#[cfg(not(target_os = "android"))]
mod proxy;
mod settings;
mod tunnel;
#[cfg(not(target_os = "android"))]
mod vpn;

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[cfg(feature = "desktop")]
use dioxus::desktop::{
    tao::event::{Event, WindowEvent},
    use_wry_event_handler, Config, LogicalSize, WindowBuilder, WindowCloseBehaviour,
};
use dioxus::prelude::*;

use settings::Settings;
use tunnel::Tunnel;

const REPO_URL: &str = "https://github.com/omidmousavi/csharp-ssh-vpn";
const CSS: &str = include_str!("style.css");

/// Whether we changed the system proxy, so it can be restored on any exit path.
static PROXY_ACTIVE: AtomicBool = AtomicBool::new(false);

#[cfg(feature = "desktop")]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some(vpn::HELPER_ARG) {
        std::process::exit(vpn::helper_main(&args[1..]));
    }

    let window = WindowBuilder::new()
        .with_title("SSH VPN")
        .with_inner_size(LogicalSize::new(360.0, 520.0))
        .with_resizable(false);

    dioxus::LaunchBuilder::desktop()
        .with_cfg(
            Config::new()
                .with_window(window)
                .with_menu(None)
                // Lets us intercept closing while connected; see the wry handler in `App`.
                .with_close_behaviour(WindowCloseBehaviour::WindowHides),
        )
        .launch(App);

    restore_proxy();
}

#[cfg(not(feature = "desktop"))]
fn main() {
    dioxus::launch(App);
}

/// Disconnected and confirmed: really close the app.
fn quit() {
    #[cfg(feature = "desktop")]
    {
        let window = dioxus::desktop::window();
        window.set_close_behavior(WindowCloseBehaviour::WindowCloses);
        window.close();
    }
}

fn restore_proxy() {
    #[cfg(not(target_os = "android"))]
    if PROXY_ACTIVE.swap(false, Ordering::SeqCst) {
        let _ = proxy::unset();
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Status {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
}

/// How traffic reaches the tunnel while connected.
#[derive(Clone, Copy, PartialEq)]
enum Routing {
    /// Every app, through a TUN interface (VpnService on Android).
    Vpn,
    /// Only apps that honour the system proxy setting.
    Proxy,
    /// Only apps pointed at the SOCKS server by hand.
    Manual,
}

#[derive(Clone, PartialEq)]
enum Dialog {
    Message { title: &'static str, text: String, error: bool },
    ConfirmExit,
}

#[component]
fn App() -> Element {
    let mut status = use_signal(|| Status::Disconnected);
    let mut tunnel = use_signal(|| None::<Tunnel>);
    let mut since = use_signal(|| None::<Instant>);
    let mut elapsed = use_signal(|| 0u64);
    let mut dialog = use_signal(|| None::<Dialog>);
    let mut show_settings = use_signal(|| false);
    let mut saved = use_signal(Settings::load);
    let mut routing = use_signal(|| None::<Routing>);
    #[cfg(not(target_os = "android"))]
    let mut vpn = use_signal(|| None::<vpn::Vpn>);

    let mut message = move |title: &'static str, text: String, error: bool| {
        dialog.set(Some(Dialog::Message { title, text, error }));
    };

    let disconnect = move || async move {
        status.set(Status::Disconnecting);
        // Restore the network before the tunnel goes, so traffic is never black-holed.
        #[cfg(target_os = "android")]
        android_vpn::stop();
        #[cfg(not(target_os = "android"))]
        if let Some(v) = vpn.write().take() {
            v.stop().await;
        }
        if let Some(t) = tunnel.write().take() {
            t.stop().await;
        }
        #[cfg(not(target_os = "android"))]
        if PROXY_ACTIVE.swap(false, Ordering::SeqCst) {
            if let Err(e) = tokio::task::spawn_blocking(proxy::unset).await.unwrap() {
                message("Proxy Error", format!("Could not restore system proxy: {e:#}"), true);
            }
        }
        since.set(None);
        elapsed.set(0);
        routing.set(None);
        status.set(Status::Disconnected);
    };

    let connect = move || async move {
        let mut cfg = Settings::load();
        if !cfg.is_complete() {
            message("Setup needed", "Enter your SSH server details first.".into(), true);
            show_settings.set(true);
            return;
        }

        status.set(Status::Connecting);
        let started = match Tunnel::start(&cfg).await {
            Ok(s) => s,
            Err(e) => {
                status.set(Status::Disconnected);
                message("Connection Error", format!("{e:#}"), true);
                return;
            }
        };

        if let Some(fp) = started.new_fingerprint {
            cfg.known_hosts.insert(cfg.host_id(), fp);
            let _ = cfg.save();
        }
        #[cfg(not(target_os = "android"))]
        let server_ip = started.tunnel.server_ip();
        tunnel.set(Some(started.tunnel));

        #[cfg(target_os = "android")]
        {
            if let Err(e) = android_vpn::start().await {
                disconnect().await;
                message("VPN Error", format!("{e:#}"), true);
                return;
            }
            routing.set(Some(Routing::Vpn));
        }

        // Desktop: full VPN first, the system proxy if that is refused or fails.
        #[cfg(not(target_os = "android"))]
        {
            let mut vpn_error = None;
            if cfg.full_vpn {
                match vpn::Vpn::start(server_ip).await {
                    Ok(v) => {
                        vpn.set(Some(v));
                        routing.set(Some(Routing::Vpn));
                    }
                    Err(e) => vpn_error = Some(e),
                }
            }
            if routing.peek().is_none() {
                let proxy = tokio::task::spawn_blocking(proxy::set).await.unwrap();
                let fallback = vpn_error.map(|e| format!("Full VPN could not start: {e:#}\n\n"));
                match proxy {
                    Ok(()) => {
                        PROXY_ACTIVE.store(true, Ordering::SeqCst);
                        routing.set(Some(Routing::Proxy));
                        if let Some(why) = fallback {
                            message(
                                "Using system proxy",
                                format!("{why}Only apps that use the system proxy are tunnelled."),
                                true,
                            );
                        }
                    }
                    Err(e) => {
                        routing.set(Some(Routing::Manual));
                        message(
                            "Proxy Warning",
                            format!(
                                "{}The tunnel is up, but the system proxy could not be set: {e:#}\n\
                                 Configure SOCKS proxy {} manually.",
                                fallback.unwrap_or_default(),
                                tunnel::SOCKS_ADDR
                            ),
                            true,
                        );
                    }
                }
            }
        }

        since.set(Some(Instant::now()));
        status.set(Status::Connected);
    };

    // Status timer: update the clock and notice dropped connections.
    use_future(move || async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if *status.peek() != Status::Connected {
                continue;
            }
            #[cfg(target_os = "android")]
            if android_vpn::take_revoked() {
                disconnect().await;
                message("Disconnected", "The VPN was turned off in system settings.".into(), true);
                continue;
            }
            #[cfg(not(target_os = "android"))]
            if vpn.peek().as_ref().is_some_and(|v| !v.is_alive()) {
                disconnect().await;
                message("Disconnected", "The VPN helper stopped unexpectedly.".into(), true);
                continue;
            }
            let alive = tunnel.peek().as_ref().is_some_and(Tunnel::is_connected);
            if alive {
                if let Some(t) = *since.peek() {
                    elapsed.set(t.elapsed().as_secs());
                }
            } else {
                disconnect().await;
                message("Disconnected", "The SSH connection was lost.".into(), true);
            }
        }
    });

    // Closing the window: exit straight away when idle, ask first when connected.
    #[cfg(feature = "desktop")]
    use_wry_event_handler(move |event, _| match event {
        Event::WindowEvent { event: WindowEvent::CloseRequested, .. } => {
            let window = dioxus::desktop::window();
            if *status.peek() == Status::Disconnected {
                window.set_close_behavior(WindowCloseBehaviour::WindowCloses);
            } else {
                // The window gets hidden right after this handler; bring it back and ask.
                spawn(async move { window.set_visible(true) });
                dialog.set(Some(Dialog::ConfirmExit));
            }
        }
        Event::LoopDestroyed => restore_proxy(),
        _ => {}
    });

    let st = *status.read();
    let (state_class, headline) = match st {
        Status::Disconnected => ("off", "Not connected"),
        Status::Connecting => ("busy", "Connecting…"),
        Status::Connected => ("on", "Connected"),
        Status::Disconnecting => ("busy", "Disconnecting…"),
    };
    let detail = match st {
        Status::Connected => {
            let s = *elapsed.read();
            format!("{:02}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
        }
        Status::Disconnected => "Tap to connect".to_string(),
        _ => "Please wait".to_string(),
    };
    let busy = matches!(st, Status::Connecting | Status::Disconnecting);
    let full_vpn = cfg!(target_os = "android") || saved.read().full_vpn;
    let mode = match *routing.read() {
        Some(Routing::Vpn) => "Full VPN · all apps".to_string(),
        Some(Routing::Proxy) => "System proxy".to_string(),
        Some(Routing::Manual) => format!("SOCKS5 · {}", tunnel::SOCKS_ADDR),
        None if full_vpn => "Full VPN".to_string(),
        None => "System proxy".to_string(),
    };
    let server = server_label(&saved.read());

    rsx! {
        style { {CSS} }
        main { class: "app {state_class}",
            header {
                div { class: "brand",
                    Icon { d: SHIELD }
                    span { "SSH VPN" }
                }
                button {
                    class: "icon-btn",
                    title: "Settings",
                    onclick: move |_| show_settings.set(true),
                    Icon { d: GEAR }
                }
            }

            section { class: "hero",
                button {
                    class: "power",
                    disabled: busy,
                    title: if st == Status::Connected { "Disconnect" } else { "Connect" },
                    onclick: move |_| async move {
                        if *status.peek() == Status::Connected { disconnect().await } else { connect().await }
                    },
                    Icon { d: POWER }
                }
                div { class: "headline", "{headline}" }
                div { class: "detail", "{detail}" }
            }

            section { class: "info",
                div { class: "info-row",
                    span { "Server" }
                    strong { "{server}" }
                }
                div { class: "info-row",
                    span { "Mode" }
                    strong { "{mode}" }
                }
            }

            footer {
                button { class: "link", onclick: move |_| { let _ = open::that(REPO_URL); }, "Based on CSharp-SSH-VPN ↗" }
            }
        }

        if show_settings() {
            SettingsDialog {
                on_close: move |_| show_settings.set(false),
                on_saved: move |_| {
                    saved.set(Settings::load());
                    message("Saved", "Server settings were saved.".into(), false);
                },
                on_error: move |e: String| message("Error", e, true),
            }
        }

        match dialog() {
            Some(Dialog::Message { title, text, error }) => rsx! {
                div { class: "overlay",
                    div { class: if error { "dialog error" } else { "dialog" },
                        h3 { "{title}" }
                        pre { "{text}" }
                        div { class: "actions", button { class: "primary", onclick: move |_| dialog.set(None), "OK" } }
                    }
                }
            },
            Some(Dialog::ConfirmExit) => rsx! {
                div { class: "overlay",
                    div { class: "dialog",
                        h3 { "Exit SSH VPN?" }
                        p { "The connection will be stopped." }
                        div { class: "actions",
                            button { onclick: move |_| dialog.set(None), "Cancel" }
                            button {
                                class: "primary danger",
                                onclick: move |_| async move {
                                    dialog.set(None);
                                    disconnect().await;
                                    quit();
                                },
                                "Exit"
                            }
                        }
                    }
                }
            },
            None => rsx! {},
        }
    }
}

fn server_label(cfg: &Settings) -> String {
    if cfg.ip.trim().is_empty() {
        "Not configured".into()
    } else {
        cfg.host_id()
    }
}

// Stroke icon paths (Lucide, ISC licence).
const POWER: &str = "M12 2v10M18.4 6.6a9 9 0 1 1-12.77.04";
const SHIELD: &str = "M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z";
const GEAR: &str = "M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2zM15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0z";

#[component]
fn Icon(d: &'static str) -> Element {
    rsx! {
        svg {
            class: "icon",
            view_box: "0 0 24 24",
            fill: "none",
            stroke: "currentColor",
            stroke_width: "2",
            stroke_linecap: "round",
            stroke_linejoin: "round",
            path { d }
        }
    }
}

#[component]
fn SettingsDialog(on_close: EventHandler, on_saved: EventHandler, on_error: EventHandler<String>) -> Element {
    let mut form = use_signal(Settings::load);

    rsx! {
        div { class: "overlay",
            form {
                class: "dialog settings",
                onsubmit: move |e| {
                    e.prevent_default();
                    // Re-read so known_hosts edits made elsewhere are not clobbered.
                    let mut cfg = Settings::load();
                    let f = form.read();
                    if cfg.ip.trim() != f.ip.trim() || cfg.port != f.port {
                        cfg.known_hosts.remove(&cfg.host_id());
                    }
                    cfg.ip = f.ip.trim().to_string();
                    cfg.port = f.port;
                    cfg.username = f.username.clone();
                    cfg.password = f.password.clone();
                    cfg.full_vpn = f.full_vpn;
                    match cfg.save() {
                        Ok(()) => { on_saved.call(()); on_close.call(()); }
                        Err(e) => on_error.call(format!("Could not save settings: {e:#}")),
                    }
                },
                h3 { "SSH server" }
                div { class: "field-row",
                    label { class: "grow", "Host"
                        input {
                            placeholder: "example.com",
                            initial_value: "{form.peek().ip}",
                            oninput: move |e| form.write().ip = e.value(),
                        }
                    }
                    label { class: "port", "Port"
                        input {
                            r#type: "number", min: "1", max: "65535",
                            initial_value: "{form.peek().port}",
                            oninput: move |e| if let Ok(p) = e.value().parse() { form.write().port = p },
                        }
                    }
                }
                label { "Username"
                    input { initial_value: "{form.peek().username}", oninput: move |e| form.write().username = e.value() }
                }
                label { "Password"
                    input {
                        r#type: "password",
                        initial_value: "{form.peek().password}",
                        oninput: move |e| form.write().password = e.value(),
                    }
                }
                if cfg!(not(target_os = "android")) {
                    label { class: "check",
                        input {
                            r#type: "checkbox",
                            initial_checked: form.peek().full_vpn,
                            onchange: move |e| form.write().full_vpn = e.checked(),
                        }
                        span {
                            strong { "Full VPN" }
                            "Route every app. Asks for administrator rights; falls back to the system proxy."
                        }
                    }
                }
                div { class: "actions",
                    button { r#type: "button", onclick: move |_| on_close.call(()), "Cancel" }
                    button { class: "primary", r#type: "submit", "Save" }
                }
            }
        }
    }
}
