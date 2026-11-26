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

    pub fn to_shoes_rule_yaml(self, value: &str, target: &str) -> Result<serde_yaml_ng::Value> {
        let v = value.trim();
        let mut rule = serde_yaml_ng::Mapping::new();
        match self {
            RuleKind::ProcessName => {
                anyhow::bail!(
                    "shoes does not support process_name rules; use IP/CIDR or domain masks"
                );
            }
            RuleKind::GeoIp => {
                let tag = if v.starts_with("geoip-") {
                    v.to_string()
                } else {
                    format!("geoip-{v}")
                };
                let mut cond = serde_yaml_ng::Mapping::new();
                cond.insert("rule_source_group".into(), tag.into());
                rule.insert("conditions".into(), serde_yaml_ng::Value::Mapping(cond));
            }
            RuleKind::GeoSite => {
                let tag = if v.starts_with("geosite-") {
                    v.to_string()
                } else {
                    format!("geosite-{v}")
                };
                let mut cond = serde_yaml_ng::Mapping::new();
                cond.insert("rule_source_group".into(), tag.into());
                rule.insert("conditions".into(), serde_yaml_ng::Value::Mapping(cond));
            }
            RuleKind::DomainSuffix | RuleKind::Cidr => {
                rule.insert(
                    "masks".into(),
                    serde_yaml_ng::Value::Sequence(vec![v.into()]),
                );
            }
        }

        if target == "reject" || target == "block" {
            rule.insert("action".into(), "block".into());
        } else {
            rule.insert("action".into(), "allow".into());
            if target == "direct" {
                let mut proto = serde_yaml_ng::Mapping::new();
                proto.insert("type".into(), "direct".into());
                let mut chain = serde_yaml_ng::Mapping::new();
                chain.insert("protocol".into(), serde_yaml_ng::Value::Mapping(proto));
                rule.insert("client_chain".into(), serde_yaml_ng::Value::Mapping(chain));
            } else {
                rule.insert("client_chain".into(), target.into());
            }
        }
        Ok(serde_yaml_ng::Value::Mapping(rule))
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

/// Validates a candidate `shoes` config YAML with `shoes check <tmp>`.
pub fn validate_shoes_yaml(doc: &serde_yaml_ng::Value) -> Result<()> {
    let tmp = std::env::temp_dir().join(format!("sboxtui-check-{}.yaml", std::process::id()));
    let body = serde_yaml_ng::to_string(doc)?;
    fs::write(&tmp, body)?;
    let bin = if Path::new("/usr/local/bin/shoes").exists() {
        "/usr/local/bin/shoes"
    } else {
        "shoes"
    };
    let out = Command::new(bin)
        .arg("check")
        .arg(&tmp)
        .output()
        .with_context(|| format!("failed to invoke `{bin} check`"))?;
    let _ = fs::remove_file(&tmp);
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        anyhow::bail!(
            "shoes check failed: {} {}",
            stderr.trim(),
            stdout.trim()
        );
    }
    Ok(())
}

fn write_or_stage_text(body: &str, dest: &Path, staged_name: &str) -> Result<SaveOutcome> {
    if fs::write(dest, body).is_ok() {
        Ok(SaveOutcome::WrittenDirect)
    } else {
        let home = std::env::var_os("HOME").context("HOME not set")?;
        let staged = Path::new(&home)
            .join(".local")
            .join("state")
            .join("sboxtui")
            .join(staged_name);
        if let Some(parent) = staged.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&staged, body)?;
        Ok(SaveOutcome::Staged { staged })
    }
}

/// Saves validated `sing-box` config to `dest` directly if writable, or stages it.
pub fn save_or_stage_config(cfg: &Value, dest: &Path) -> Result<SaveOutcome> {
    validate_singbox_json(cfg)?;
    let body = serde_json::to_string_pretty(cfg)?;
    write_or_stage_text(&body, dest, "pending-config.json")
}

/// Saves validated `shoes` YAML config to `dest` directly if writable, or stages it.
pub fn save_or_stage_shoes_config(doc: &serde_yaml_ng::Value, dest: &Path) -> Result<SaveOutcome> {
    validate_shoes_yaml(doc)?;
    let body = serde_yaml_ng::to_string(doc)?;
    write_or_stage_text(&body, dest, "pending-desktop.yaml")
}

fn shoes_rules_seq_mut(
    doc: &mut serde_yaml_ng::Value,
) -> Result<&mut Vec<serde_yaml_ng::Value>> {
    let entries = doc
        .as_sequence_mut()
        .context("shoes config root must be a YAML sequence")?;
    for item in entries.iter_mut() {
        if item.get("rule_group").is_some()
            && let Some(seq) = item.get_mut("rules").and_then(|v| v.as_sequence_mut())
        {
            return Ok(seq);
        }
    }
    anyhow::bail!("missing rule_group rules array in shoes config")
}

pub fn summarize_shoes_rules(doc: &serde_yaml_ng::Value) -> Vec<RuleSummary> {
    let Some(entries) = doc.as_sequence() else {
        return Vec::new();
    };
    let Some(rules) = entries
        .iter()
        .find(|item| item.get("rule_group").is_some())
        .and_then(|item| item.get("rules"))
        .and_then(|v| v.as_sequence())
    else {
        return Vec::new();
    };

    rules
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let action = item.get("action").and_then(|v| v.as_str());
            let chain = item.get("client_chain");
            let target = if action == Some("block") {
                "action:block".to_string()
            } else if let Some(s) = chain.and_then(|v| v.as_str()) {
                s.to_string()
            } else if chain
                .and_then(|v| v.get("protocol"))
                .and_then(|v| v.get("type"))
                .and_then(|v| v.as_str())
                == Some("direct")
            {
                "direct".to_string()
            } else {
                action.unwrap_or("-").to_string()
            };

            let any_dest = item
                .get("conditions")
                .and_then(|c| c.get("any_destination"))
                .and_then(|v| v.as_bool())
                == Some(true);
            let is_builtin = any_dest;

            let matcher = if let Some(masks) = item.get("masks") {
                format!("masks={}", compact_yaml(masks))
            } else if let Some(cond) = item.get("conditions") {
                if any_dest {
                    "any_destination=true".to_string()
                } else {
                    format!("conditions={}", compact_yaml(cond))
                }
            } else {
                compact_yaml(item)
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

fn compact_yaml(val: &serde_yaml_ng::Value) -> String {
    serde_json::to_string(val).unwrap_or_else(|_| "<yaml>".to_string())
}

pub fn insert_shoes_user_rule(
    doc: &mut serde_yaml_ng::Value,
    rule: serde_yaml_ng::Value,
) -> Result<()> {
    let rules = shoes_rules_seq_mut(doc)?;
    let insert_pos = rules
        .iter()
        .position(|r| {
            r.get("conditions")
                .and_then(|c| c.get("any_destination"))
                .and_then(|v| v.as_bool())
                == Some(true)
        })
        .unwrap_or(rules.len());
    rules.insert(insert_pos, rule);
    Ok(())
}

pub fn delete_shoes_rule(doc: &mut serde_yaml_ng::Value, index: usize) -> Result<()> {
    let rules = shoes_rules_seq_mut(doc)?;
    if index < rules.len() {
        rules.remove(index);
    }
    Ok(())
}

pub fn swap_shoes_rules(doc: &mut serde_yaml_ng::Value, a: usize, b: usize) -> Result<()> {
    let rules = shoes_rules_seq_mut(doc)?;
    if a < rules.len() && b < rules.len() {
        rules.swap(a, b);
    }
    Ok(())
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

    #[test]
    fn manages_shoes_rules_preserving_catch_all() {
        use crate::clash_sub::build_shoes_config;
        let mut doc = build_shoes_config(
            "proxy",
            &["n1".into()],
            vec![],
            Path::new("/usr/local/share/sing-box"),
            "sec",
            1400,
            None,
        )
        .unwrap();
        let initial_len = summarize_shoes_rules(&doc).len();
        let rule = RuleKind::Cidr.to_shoes_rule_yaml("198.51.100.0/24", "direct").unwrap();
        insert_shoes_user_rule(&mut doc, rule).unwrap();
        let after = summarize_shoes_rules(&doc);
        assert_eq!(after.len(), initial_len + 1);
        assert_eq!(after[initial_len - 1].target, "direct");
        assert!(after[initial_len].is_builtin);
        assert!(RuleKind::ProcessName.to_shoes_rule_yaml("firefox", "direct").is_err());
        delete_shoes_rule(&mut doc, initial_len - 1).unwrap();
        assert_eq!(summarize_shoes_rules(&doc).len(), initial_len);
    }
}
