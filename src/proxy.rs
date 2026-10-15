//! Point the OS-wide proxy at the local SOCKS server and back.

use anyhow::Result;

pub const HOST: &str = "127.0.0.1";
pub const PORT: u16 = 9000;

#[cfg(windows)]
mod imp {
    use super::*;
    use anyhow::Context;
    use windows_sys::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };
    use winreg::enums::{HKEY_CURRENT_USER, KEY_SET_VALUE};
    use winreg::RegKey;

    const KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    fn write(enable: u32, server: &str) -> Result<()> {
        let key = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(KEY, KEY_SET_VALUE)
            .context("could not open Internet Settings registry key")?;
        key.set_value("ProxyEnable", &enable)?;
        key.set_value("ProxyServer", &server)?;
        unsafe {
            InternetSetOptionW(std::ptr::null(), INTERNET_OPTION_SETTINGS_CHANGED, std::ptr::null(), 0);
            InternetSetOptionW(std::ptr::null(), INTERNET_OPTION_REFRESH, std::ptr::null(), 0);
        }
        Ok(())
    }

    pub fn set() -> Result<()> {
        write(1, &format!("socks5://{HOST}:{PORT}"))
    }

    pub fn unset() -> Result<()> {
        write(0, "")
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    use anyhow::{bail, Context};
    use std::process::Command;

    fn networksetup(args: &[&str]) -> Result<String> {
        let out = Command::new("/usr/sbin/networksetup")
            .args(args)
            .output()
            .context("could not run networksetup")?;
        if !out.status.success() {
            bail!("networksetup {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// Enabled network services ("Wi-Fi", "Ethernet", ...). Disabled ones are prefixed with '*'.
    fn services() -> Result<Vec<String>> {
        Ok(networksetup(&["-listallnetworkservices"])?
            .lines()
            .skip(1)
            .filter(|l| !l.is_empty() && !l.starts_with('*'))
            .map(str::to_owned)
            .collect())
    }

    pub fn set() -> Result<()> {
        let port = PORT.to_string();
        for svc in services()? {
            networksetup(&["-setsocksfirewallproxy", &svc, HOST, &port])?;
            networksetup(&["-setsocksfirewallproxystate", &svc, "on"])?;
        }
        Ok(())
    }

    pub fn unset() -> Result<()> {
        for svc in services()? {
            networksetup(&["-setsocksfirewallproxystate", &svc, "off"])?;
        }
        Ok(())
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
mod imp {
    use super::*;
    use anyhow::{bail, Context};
    use std::process::Command;

    fn gsettings(args: &[&str]) -> Result<()> {
        let status = Command::new("gsettings")
            .args(args)
            .status()
            .context("could not run gsettings (only GNOME-style desktops are supported)")?;
        if !status.success() {
            bail!("gsettings {} failed", args.join(" "));
        }
        Ok(())
    }

    pub fn set() -> Result<()> {
        gsettings(&["set", "org.gnome.system.proxy.socks", "host", HOST])?;
        gsettings(&["set", "org.gnome.system.proxy.socks", "port", &PORT.to_string()])?;
        gsettings(&["set", "org.gnome.system.proxy", "mode", "manual"])
    }

    pub fn unset() -> Result<()> {
        gsettings(&["set", "org.gnome.system.proxy", "mode", "none"])
    }
}

pub use imp::{set, unset};
