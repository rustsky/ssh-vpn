//! Persistent SSH server settings (replaces the `HKCU\ssh_vpn` registry key of the C# version).

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use anyhow::Result;
#[cfg(not(target_os = "android"))]
use anyhow::Context;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Settings {
    pub ip: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    /// Desktop: route every app through a TUN interface (needs admin rights) instead of only
    /// setting the system proxy. Falls back to the proxy if the VPN cannot start.
    pub full_vpn: bool,
    /// Trust-on-first-use host keys: "host:port" -> SHA256 fingerprint.
    pub known_hosts: HashMap<String, String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            ip: String::new(),
            port: 22,
            username: String::new(),
            password: String::new(),
            full_vpn: true,
            known_hosts: HashMap::new(),
        }
    }
}

impl Settings {
    pub fn is_complete(&self) -> bool {
        !self.ip.trim().is_empty() && !self.username.is_empty() && !self.password.is_empty()
    }

    pub fn host_id(&self) -> String {
        format!("{}:{}", self.ip.trim(), self.port)
    }

    fn path() -> Result<PathBuf> {
        // App-private storage; must match `bundle.identifier` in Dioxus.toml.
        #[cfg(target_os = "android")]
        return Ok(PathBuf::from("/data/data/io.github.sshvpn/files/settings.json"));

        #[cfg(not(target_os = "android"))]
        {
            let dirs = directories::ProjectDirs::from("", "", "ssh-vpn")
                .context("could not determine config directory")?;
            Ok(dirs.config_dir().join("settings.json"))
        }
    }

    pub fn load() -> Self {
        Self::path()
            .ok()
            .and_then(|p| fs::read_to_string(p).ok())
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::path()?;
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        fs::write(&path, serde_json::to_string_pretty(self)?)?;
        // The password is stored in plain text (as the original did), so at least keep it private.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
}
