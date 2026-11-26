use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Proxy core managed by `sboxtui`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum CoreKind {
    #[default]
    Auto,
    Shoes,
    SingBox,
}

/// User-level configuration for `sboxtui`, stored in `~/.config/sboxtui/config.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub core: CoreKind,
    pub clash_api_url: String,
    pub api_secret: Option<String>,
    pub api_secret_file: Option<PathBuf>,
    pub shoes_config_path: PathBuf,
    pub singbox_config_path: PathBuf,
    pub rules_dir: PathBuf,
    pub subscription_url: Option<String>,
    pub default_group: String,
    pub default_interface: String,
    pub wg_lan_connection: String,
    pub wg_remote_connection: String,
    pub tun_mtu: u16,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            core: CoreKind::Auto,
            clash_api_url: "http://127.0.0.1:9097".to_string(),
            api_secret: None,
            api_secret_file: Some(PathBuf::from("/etc/shoes/api.secret")),
            shoes_config_path: PathBuf::from("/etc/shoes/desktop.yaml"),
            singbox_config_path: PathBuf::from("/etc/sing-box/config.json"),
            rules_dir: PathBuf::from("/usr/local/share/sing-box"),
            subscription_url: None,
            default_group: "proxy".to_string(),
            default_interface: "auto".to_string(),
            wg_lan_connection: "wg-lan".to_string(),
            wg_remote_connection: "wg_mw".to_string(),
            tun_mtu: 1400,
        }
    }
}

impl AppConfig {
    /// Returns `~/.config/sboxtui/config.toml`.
    pub fn default_path() -> Result<PathBuf> {
        let home = std::env::var_os("HOME").context("HOME environment variable is not set")?;
        Ok(PathBuf::from(home)
            .join(".config")
            .join("sboxtui")
            .join("config.toml"))
    }

    pub fn load_or_default(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let cfg: Self =
            toml::from_str(&raw).with_context(|| format!("invalid TOML in {}", path.display()))?;
        Ok(cfg)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let body = toml::to_string_pretty(self).context("failed to serialize config")?;
        fs::write(path, body).with_context(|| format!("failed to write {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    /// Resolves which concrete core (`Shoes` or `SingBox`) is active.
    pub fn effective_core(&self, engine_version: Option<&str>) -> CoreKind {
        match self.core {
            CoreKind::Shoes => CoreKind::Shoes,
            CoreKind::SingBox => CoreKind::SingBox,
            CoreKind::Auto => {
                if engine_version.is_some_and(|v| v.to_ascii_lowercase().contains("shoes"))
                    || self.shoes_config_path.exists()
                {
                    CoreKind::Shoes
                } else {
                    CoreKind::SingBox
                }
            }
        }
    }

    pub fn active_config_path(&self, core: CoreKind) -> &Path {
        match core {
            CoreKind::Shoes => &self.shoes_config_path,
            CoreKind::SingBox | CoreKind::Auto => &self.singbox_config_path,
        }
    }

    pub fn resolve_secret(&self) -> Result<String> {
        if let Some(s) = &self.api_secret {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return Ok(trimmed.to_string());
            }
        }
        let candidates = self
            .api_secret_file
            .iter()
            .map(PathBuf::as_path)
            .chain([
                Path::new("/etc/shoes/api.secret"),
                Path::new("/etc/sing-box/api.secret"),
            ]);
        for p in candidates {
            if p.exists()
                && let Ok(content) = fs::read_to_string(p)
            {
                let trimmed = content.trim();
                if !trimmed.is_empty() {
                    return Ok(trimmed.to_string());
                }
            }
        }
        anyhow::bail!(
            "No Clash API secret configured; set `api_secret` or readable `api_secret_file` in ~/.config/sboxtui/config.toml"
        )
    }
}
