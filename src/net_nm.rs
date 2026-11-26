use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::fs;
use std::process::Command;

/// Represents a NetworkManager connection relevant to WireGuard or Wi-Fi uplinks.
#[derive(Debug, Clone)]
pub struct NmConnection {
    pub name: String,
    pub conn_type: String,
    pub device: String,
    pub state: String,
}

impl NmConnection {
    pub fn is_active(&self) -> bool {
        self.state == "activated" || !self.device.is_empty() && self.device != "--"
    }
}

/// Lists WireGuard and Wi-Fi connections managed by NetworkManager (`nmcli`).
pub fn list_nm_connections() -> Result<Vec<NmConnection>> {
    let out = Command::new("nmcli")
        .args([
            "-t",
            "-f",
            "NAME,UUID,TYPE,DEVICE,STATE",
            "connection",
            "show",
        ])
        .output()
        .context("failed to execute nmcli")?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("nmcli failed: {}", stderr.trim());
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut conns = Vec::new();
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 5 {
            continue;
        }
        let conn_type = parts[2].to_string();
        if conn_type != "wireguard" && conn_type != "802-11-wireless" {
            continue;
        }
        conns.push(NmConnection {
            name: parts[0].to_string(),
            conn_type,
            device: parts[3].to_string(),
            state: parts[4].to_string(),
        });
    }
    Ok(conns)
}

/// Brings a NetworkManager connection up or down without requiring `run0`.
pub fn set_connection_state(name: &str, up: bool) -> Result<String> {
    let action = if up { "up" } else { "down" };
    let out = Command::new("nmcli")
        .args(["connection", action, name])
        .output()
        .with_context(|| format!("failed to run nmcli connection {action} {name}"))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("nmcli connection {action} {name}: {}", stderr.trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Returns active network interfaces from `ip -brief addr show` for diagnostics and uplink picking.
pub fn list_interfaces() -> Result<Vec<String>> {
    let out = Command::new("ip")
        .args(["-brief", "link", "show"])
        .output()
        .context("failed to execute ip")?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut ifaces = Vec::new();
    for line in stdout.lines() {
        if let Some(name) = line.split_whitespace().next()
            && name != "lo"
        {
            ifaces.push(name.to_string());
        }
    }
    Ok(ifaces)
}

/// Extracts active Wi-Fi connection/SSID name from already-queried NetworkManager connections
/// without triggering a `nmcli dev wifi` radio scan.
pub fn active_wifi_from_connections(conns: &[NmConnection]) -> Option<String> {
    conns
        .iter()
        .find(|c| c.conn_type == "802-11-wireless" && c.is_active())
        .map(|c| c.name.clone())
}

/// Collects sorted unique running process names (`/proc/<pid>/comm`) for `pname(...)` rule picking.
pub fn list_process_names() -> Vec<String> {
    let mut names = BTreeSet::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(s) = file_name.to_str() else {
            continue;
        };
        if !s.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let comm_path = entry.path().join("comm");
        if let Ok(comm) = fs::read_to_string(comm_path) {
            let name = comm.trim();
            if !name.is_empty() {
                names.insert(name.to_string());
            }
        }
    }
    names.into_iter().collect()
}
