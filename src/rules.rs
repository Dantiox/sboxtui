use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::fs;
use std::path::Path;
use std::process::Command;

/// Supported rule matcher kinds inside `sboxtui`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleKind {
    ProcessName,
    GeoIp,
    GeoSite,
    DomainSuffix,
    Cidr,
}

impl RuleKind {
    pub const ALL: [RuleKind; 5] = [
        RuleKind::ProcessName,
        RuleKind::GeoIp,
        RuleKind::GeoSite,
        RuleKind::DomainSuffix,
        RuleKind::Cidr,
    ];

    pub fn label(self) -> &'static str {
        match self {
            RuleKind::ProcessName => "Process (process_name)",
            RuleKind::GeoIp => "GeoIP rule_set (e.g. geoip-ru)",
            RuleKind::GeoSite => "GeoSite rule_set (e.g. geosite-category-ru)",
            RuleKind::DomainSuffix => "Domain suffix (e.g. example.com)",
            RuleKind::Cidr => "IP / CIDR (e.g. 10.20.0.0/16)",
        }
    }

    pub fn to_rule_json(self, value: &str, target: &str) -> Value {
        let v = value.trim();
        let mut obj = match self {
            RuleKind::ProcessName => json!({ "process_name": [v] }),
            RuleKind::GeoIp => {
                let tag = if v.starts_with("geoip-") {
                    v.to_string()
                } else {
                    format!("geoip-{v}")
                };
                json!({ "rule_set": [tag] })
            }
            RuleKind::GeoSite => {
                let tag = if v.starts_with("geosite-") {
                    v.to_string()
                } else {
                    format!("geosite-{v}")
                };
                json!({ "rule_set": [tag] })
            }
            RuleKind::DomainSuffix => json!({ "domain_suffix": [v] }),
            RuleKind::Cidr => json!({ "ip_cidr": [v] }),
        };
        let map = obj.as_object_mut().unwrap();
        if target == "reject" {
            map.insert("action".to_string(), json!("reject"));
        } else {
            map.insert("outbound".to_string(), json!(target));
        }
        obj
    }
}

/// Human-friendly view of one `route.rules[i]` entry in `sing-box`.
#[derive(Debug, Clone)]
pub struct RuleSummary {
    pub index: usize,
    pub matcher: String,
    pub target: String,
    pub is_builtin: bool,
}

pub fn summarize_rules(cfg: &Value) -> Vec<RuleSummary> {
    let Some(arr) = cfg.pointer("/route/rules").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .enumerate()
        .map(|(index, item)| {
            let action = item.get("action").and_then(|v| v.as_str());
            let outbound = item.get("outbound").and_then(|v| v.as_str());
            let target = action
                .map(|a| format!("action:{a}"))
                .or_else(|| outbound.map(str::to_string))
                .unwrap_or_else(|| "-".to_string());

            let is_builtin = matches!(action, Some("sniff" | "hijack-dns"));

            let matcher = if let Some(a) = action
                && (a == "sniff" || a == "hijack-dns")
            {
                if let Some(proto) = item.get("protocol") {
                    format!("protocol={proto}")
                } else {
                    a.to_string()
                }
            } else if let Some(p) = item.get("process_name") {
                format!("process_name={p}")
            } else if let Some(rs) = item.get("rule_set") {
                format!("rule_set={rs}")
            } else if let Some(ds) = item.get("domain_suffix") {
                format!("domain_suffix={ds}")
            } else if let Some(cidr) = item.get("ip_cidr") {
                format!("ip_cidr={cidr}")
            } else if item.get("ip_is_private").and_then(|v| v.as_bool()) == Some(true) {
                "ip_is_private=true".to_string()
            } else {
                item.to_string()
            };

            RuleSummary {
                index,
                matcher,
                target,
                is_builtin,
            }
        })
        .collect()
}

pub fn insert_user_rule(cfg: &mut Value, rule: Value) -> Result<()> {
    let rules = cfg
        .pointer_mut("/route/rules")
        .and_then(|v| v.as_array_mut())
        .context("missing /route/rules array in sing-box config")?;
    // Keep sniff & hijack-dns at the very top
    let insert_pos = rules
        .iter()
        .take_while(|r| {
            matches!(
                r.get("action").and_then(|v| v.as_str()),
                Some("sniff" | "hijack-dns")
            )
        })
        .count();
    rules.insert(insert_pos, rule);
    Ok(())
}

pub fn delete_rule(cfg: &mut Value, index: usize) -> Result<()> {
    let rules = cfg
        .pointer_mut("/route/rules")
        .and_then(|v| v.as_array_mut())
        .context("missing /route/rules array")?;
    if index < rules.len() {
        rules.remove(index);
    }
    Ok(())
}

pub fn swap_rules(cfg: &mut Value, a: usize, b: usize) -> Result<()> {
    let rules = cfg
        .pointer_mut("/route/rules")
        .and_then(|v| v.as_array_mut())
        .context("missing /route/rules array")?;
    if a < rules.len() && b < rules.len() {
        rules.swap(a, b);
    }
    Ok(())
}

pub fn read_default_interface(cfg: &Value) -> String {
    if cfg
        .pointer("/route/auto_detect_interface")
        .and_then(|v| v.as_bool())
        == Some(true)
    {
        return "auto".to_string();
    }
    cfg.pointer("/route/default_interface")
        .and_then(|v| v.as_str())
        .unwrap_or("auto")
        .to_string()
}

pub fn set_default_interface(cfg: &mut Value, iface: &str, tun_mtu: u16) -> Result<()> {
    let route = cfg
        .get_mut("route")
        .and_then(|v| v.as_object_mut())
        .context("missing route object")?;
    if iface == "auto" {
        route.remove("default_interface");
        route.insert("auto_detect_interface".to_string(), json!(true));
    } else {
        route.remove("auto_detect_interface");
        route.insert("default_interface".to_string(), json!(iface));
    }
    if let Some(inbounds) = cfg.get_mut("inbounds").and_then(|v| v.as_array_mut()) {
        for ib in inbounds {
            if ib.get("type").and_then(|v| v.as_str()) == Some("tun")
                && let Some(m) = ib.as_object_mut()
            {
                m.insert("mtu".to_string(), json!(tun_mtu));
            }
        }
    }
    Ok(())
}

/// Validates a candidate `sing-box` config JSON with `sing-box check -c <tmp>`.
pub fn validate_singbox_json(cfg: &Value) -> Result<()> {
    let tmp = std::env::temp_dir().join(format!("sboxtui-check-{}.json", std::process::id()));
    let body = serde_json::to_string_pretty(cfg)?;
    fs::write(&tmp, body)?;
    let out = Command::new("sing-box")
        .args(["check", "-c"])
        .arg(&tmp)
        .output()
        .context("failed to invoke `sing-box check`")?;
    let _ = fs::remove_file(&tmp);
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("sing-box check failed: {}", stderr.trim());
    }
    Ok(())
}

/// Saves validated config to `dest` directly if writable, or stages to `~/.local/state/sboxtui/pending-config.json`.
pub fn save_or_stage_config(cfg: &Value, dest: &Path) -> Result<SaveOutcome> {
    validate_singbox_json(cfg)?;
    let body = serde_json::to_string_pretty(cfg)?;
    if fs::write(dest, &body).is_ok() {
        Ok(SaveOutcome::WrittenDirect)
    } else {
        let home = std::env::var_os("HOME").context("HOME not set")?;
        let staged = Path::new(&home)
            .join(".local")
            .join("state")
            .join("sboxtui")
            .join("pending-config.json");
        if let Some(parent) = staged.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&staged, body)?;
        Ok(SaveOutcome::Staged { staged })
    }
}

pub enum SaveOutcome {
    WrittenDirect,
    Staged { staged: std::path::PathBuf },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clash_sub::build_singbox_config;

    #[test]
    fn inserts_and_deletes_user_rules_preserving_sniff() {
        let mut cfg = build_singbox_config(
            "proxy",
            &["n1".into()],
            vec![],
            Path::new("/usr/local/share/sing-box"),
            "sec",
            "auto",
            "wg_mw",
            1400,
        );
        let initial_len = summarize_rules(&cfg).len();
        let r = RuleKind::ProcessName.to_rule_json("firefox", "wg_mw");
        insert_user_rule(&mut cfg, r).unwrap();
        let after = summarize_rules(&cfg);
        assert_eq!(after.len(), initial_len + 1);
        assert_eq!(after[2].target, "wg_mw");
        delete_rule(&mut cfg, 2).unwrap();
        assert_eq!(summarize_rules(&cfg).len(), initial_len);
    }
}
