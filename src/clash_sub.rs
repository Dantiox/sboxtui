use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;

/// Subset of Clash YAML profile needed to generate `sing-box` outbounds.
#[derive(Debug, Deserialize)]
pub struct ClashProfile {
    #[serde(default)]
    pub proxies: Vec<ClashProxy>,
}

#[derive(Debug, Deserialize)]
pub struct ClashProxy {
    pub name: String,
    #[serde(rename = "type")]
    pub proxy_type: String,
    pub server: String,
    pub port: u16,
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub flow: Option<String>,
    #[serde(default)]
    pub tls: Option<bool>,
    #[serde(default)]
    pub servername: Option<String>,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(rename = "skip-cert-verify", default)]
    pub skip_cert_verify: Option<bool>,
    #[serde(rename = "client-fingerprint", default)]
    pub client_fingerprint: Option<String>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(rename = "packet-encoding", default)]
    pub packet_encoding: Option<String>,
    #[serde(rename = "reality-opts", default)]
    pub reality_opts: Option<RealityOpts>,
    #[serde(rename = "ws-opts", default)]
    pub ws_opts: Option<WsOpts>,
    #[serde(rename = "grpc-opts", default)]
    pub grpc_opts: Option<GrpcOpts>,
    #[serde(rename = "grpc-service-name", default)]
    pub grpc_service_name: Option<String>,
    #[serde(default)]
    pub obfs: Option<String>,
    #[serde(rename = "obfs-password", default)]
    pub obfs_password: Option<String>,
    #[serde(default)]
    pub alpn: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct RealityOpts {
    #[serde(rename = "public-key")]
    pub public_key: String,
    #[serde(rename = "short-id", default)]
    pub short_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct WsOpts {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub headers: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
pub struct GrpcOpts {
    #[serde(rename = "grpc-service-name", default)]
    pub grpc_service_name: Option<String>,
}

/// Fetches a Clash YAML subscription from URL and parses it.
pub fn fetch_clash_subscription(url: &str) -> Result<ClashProfile> {
    let client = reqwest::blocking::Client::builder()
        .user_agent("clash-verge/v2.0.0")
        .timeout(std::time::Duration::from_secs(20))
        .build()?;
    let body = client
        .get(url)
        .send()
        .with_context(|| format!("failed to GET subscription {url}"))?
        .error_for_status()
        .context("subscription endpoint returned error status")?
        .text()
        .context("failed to read subscription body")?;
    parse_clash_yaml(&body)
}

pub fn parse_clash_yaml(yaml_text: &str) -> Result<ClashProfile> {
    serde_yaml_ng::from_str(yaml_text).context("failed to parse Clash YAML subscription")
}

/// Converts Clash `vless` and `hysteria2` proxies into `sing-box` outbound JSON objects.
pub fn convert_proxies_to_singbox(proxies: &[ClashProxy]) -> (Vec<String>, Vec<Value>) {
    let mut used_tags = HashSet::new();
    let mut tags = Vec::new();
    let mut outbounds = Vec::new();

    for p in proxies {
        let base_tag = p.name.trim();
        if base_tag.is_empty() {
            continue;
        }
        let mut tag = base_tag.to_string();
        let mut n = 2usize;
        while !used_tags.insert(tag.clone()) {
            tag = format!("{base_tag} #{n}");
            n += 1;
        }

        let ob = match p.proxy_type.as_str() {
            "vless" => build_vless_outbound(&tag, p),
            "hysteria2" => build_hysteria2_outbound(&tag, p),
            _ => None,
        };
        if let Some(val) = ob {
            tags.push(tag);
            outbounds.push(val);
        }
    }

    (tags, outbounds)
}

fn build_vless_outbound(tag: &str, p: &ClashProxy) -> Option<Value> {
    let uuid = p.uuid.as_deref()?;
    let mut obj = json!({
        "type": "vless",
        "tag": tag,
        "server": p.server,
        "server_port": p.port,
        "uuid": uuid,
    });
    let map = obj.as_object_mut()?;
    if let Some(flow) = &p.flow
        && !flow.is_empty()
    {
        map.insert("flow".to_string(), json!(flow));
    }
    if let Some(pe) = &p.packet_encoding
        && !pe.is_empty()
    {
        map.insert("packet_encoding".to_string(), json!(pe));
    }

    let sni = p
        .servername
        .as_deref()
        .or(p.sni.as_deref())
        .unwrap_or(&p.server);
    if p.reality_opts.is_some() || p.tls.unwrap_or(false) {
        let mut tls = json!({
            "enabled": true,
            "server_name": sni,
            "insecure": p.skip_cert_verify.unwrap_or(false),
        });
        let fp = p
            .client_fingerprint
            .as_deref()
            .or(p.fingerprint.as_deref())
            .filter(|f| !f.is_empty())
            .unwrap_or("chrome");
        tls.as_object_mut()?
            .insert("utls".to_string(), json!({ "enabled": true, "fingerprint": fp }));
        if let Some(r) = &p.reality_opts {
            let mut robj = json!({
                "enabled": true,
                "public_key": r.public_key,
            });
            if let Some(sid) = &r.short_id
                && !sid.is_empty()
            {
                robj.as_object_mut()?
                    .insert("short_id".to_string(), json!(sid));
            }
            tls.as_object_mut()?.insert("reality".to_string(), robj);
        }
        map.insert("tls".to_string(), tls);
    }

    let network = p.network.as_deref().unwrap_or("tcp");
    if network == "ws" {
        let mut ws = json!({ "type": "ws" });
        if let Some(opts) = &p.ws_opts {
            if let Some(path) = &opts.path {
                ws.as_object_mut()?.insert("path".to_string(), json!(path));
            }
            if let Some(headers) = &opts.headers {
                ws.as_object_mut()?
                    .insert("headers".to_string(), json!(headers));
            }
        }
        map.insert("transport".to_string(), ws);
    } else if network == "grpc" {
        let svc = p
            .grpc_opts
            .as_ref()
            .and_then(|g| g.grpc_service_name.as_deref())
            .or(p.grpc_service_name.as_deref())
            .unwrap_or("");
        map.insert(
            "transport".to_string(),
            json!({ "type": "grpc", "service_name": svc }),
        );
    }

    Some(obj)
}

fn build_hysteria2_outbound(tag: &str, p: &ClashProxy) -> Option<Value> {
    let password = p.password.as_deref()?;
    let sni = p
        .sni
        .as_deref()
        .or(p.servername.as_deref())
        .unwrap_or(&p.server);
    let mut tls = json!({
        "enabled": true,
        "server_name": sni,
        "insecure": p.skip_cert_verify.unwrap_or(false),
    });
    if let Some(alpn) = &p.alpn
        && !alpn.is_empty()
    {
        tls.as_object_mut()?.insert("alpn".to_string(), json!(alpn));
    }

    let mut obj = json!({
        "type": "hysteria2",
        "tag": tag,
        "server": p.server,
        "server_port": p.port,
        "password": password,
        "tls": tls,
    });
    if let Some(obfs) = &p.obfs
        && !obfs.is_empty()
    {
        let mut o = json!({ "type": obfs });
        if let Some(pw) = &p.obfs_password {
            o.as_object_mut()?.insert("password".to_string(), json!(pw));
        }
        obj.as_object_mut()?.insert("obfs".to_string(), o);
    }
    Some(obj)
}

/// Builds a complete battery-friendly `sing-box` 1.14+ configuration JSON.
#[allow(clippy::too_many_arguments)]
pub fn build_singbox_config(
    group_name: &str,
    node_tags: &[String],
    node_outbounds: Vec<Value>,
    rules_dir: &Path,
    clash_secret: &str,
    default_interface: &str,
    wg_remote_iface: &str,
    tun_mtu: u16,
) -> Value {
    let default_node = node_tags
        .first()
        .cloned()
        .unwrap_or_else(|| "direct".to_string());
    let mut selector_members = if node_tags.is_empty() {
        vec!["direct".to_string()]
    } else {
        node_tags.to_vec()
    };
    if !selector_members.iter().any(|t| t == "direct") {
        selector_members.push("direct".to_string());
    }

    let mut outbounds = vec![json!({
        "type": "selector",
        "tag": group_name,
        "outbounds": selector_members,
        "default": default_node
    })];
    outbounds.extend(node_outbounds);
    outbounds.push(json!({ "type": "direct", "tag": "direct" }));
    if !wg_remote_iface.trim().is_empty() {
        outbounds.push(json!({
            "type": "direct",
            "tag": wg_remote_iface,
            "bind_interface": wg_remote_iface
        }));
    }

    let mut route = json!({
        "default_domain_resolver": "dns-bootstrap",
        "rule_set": [
            {
                "tag": "geoip-ru",
                "type": "local",
                "format": "binary",
                "path": rules_dir.join("geoip-ru.srs").to_string_lossy()
            },
            {
                "tag": "geosite-category-ru",
                "type": "local",
                "format": "binary",
                "path": rules_dir.join("geosite-category-ru.srs").to_string_lossy()
            },
            {
                "tag": "geosite-category-ads-all",
                "type": "local",
                "format": "binary",
                "path": rules_dir.join("geosite-category-ads-all.srs").to_string_lossy()
            }
        ],
        "rules": [
            { "action": "sniff" },
            { "protocol": "dns", "action": "hijack-dns" },
            {
                "process_name": ["NetworkManager", "tailscaled", "wg-quick"],
                "outbound": "direct"
            },
            { "ip_is_private": true, "outbound": "direct" },
            { "ip_cidr": ["100.64.0.0/10"], "outbound": "direct" },
            { "ip_cidr": ["9.9.9.9/32"], "outbound": "direct" },
            { "rule_set": ["geosite-category-ads-all"], "action": "reject" },
            { "rule_set": ["geoip-ru", "geosite-category-ru"], "outbound": "direct" }
        ],
        "final": group_name
    });
    if default_interface == "auto" {
        route
            .as_object_mut()
            .unwrap()
            .insert("auto_detect_interface".to_string(), json!(true));
    } else {
        route
            .as_object_mut()
            .unwrap()
            .insert("default_interface".to_string(), json!(default_interface));
    }

    json!({
        "log": { "level": "info", "timestamp": true },
        "experimental": {
            "clash_api": {
                "external_controller": "127.0.0.1:9097",
                "secret": clash_secret,
                "default_mode": "rule"
            },
            "cache_file": {
                "enabled": true,
                "path": "/var/lib/sing-box/cache.db"
            }
        },
        "dns": {
            "servers": [
                { "tag": "dns-bootstrap", "type": "tls", "server": "9.9.9.9" },
                { "tag": "dns-remote", "type": "https", "server": "8.8.8.8", "detour": group_name }
            ],
            "rules": [],
            "final": "dns-remote",
            "strategy": "ipv4_only"
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": "sb0",
                "address": ["172.19.0.1/30"],
                "mtu": tun_mtu,
                "auto_route": true,
                "strict_route": true,
                "stack": "gvisor"
            }
        ],
        "outbounds": outbounds,
        "route": route
    })
}

/// Replaces the proxy nodes inside an existing `sing-box` `config.json` while keeping user rules.
pub fn replace_nodes_in_config(
    cfg: &mut Value,
    group_name: &str,
    node_tags: &[String],
    node_outbounds: Vec<Value>,
    wg_remote_iface: &str,
) -> Result<()> {
    let default_node = node_tags
        .first()
        .cloned()
        .unwrap_or_else(|| "direct".to_string());
    let mut selector_members = if node_tags.is_empty() {
        vec!["direct".to_string()]
    } else {
        node_tags.to_vec()
    };
    if !selector_members.iter().any(|t| t == "direct") {
        selector_members.push("direct".to_string());
    }

    let mut outbounds = vec![json!({
        "type": "selector",
        "tag": group_name,
        "outbounds": selector_members,
        "default": default_node
    })];
    outbounds.extend(node_outbounds);
    outbounds.push(json!({ "type": "direct", "tag": "direct" }));
    if !wg_remote_iface.trim().is_empty() {
        outbounds.push(json!({
            "type": "direct",
            "tag": wg_remote_iface,
            "bind_interface": wg_remote_iface
        }));
    }

    cfg.as_object_mut()
        .context("sing-box config root must be a JSON object")?
        .insert("outbounds".to_string(), Value::Array(outbounds));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_vless_reality_and_hysteria2_to_singbox() {
        let yaml = r#"
proxies:
  - name: "Test Reality"
    type: vless
    server: example.com
    port: 443
    network: tcp
    uuid: 11111111-2222-3333-4444-555555555555
    flow: xtls-rprx-vision
    tls: true
    servername: cdn.example.net
    reality-opts:
      public-key: pubkey123
      short-id: abcd
    client-fingerprint: edge
  - name: "Hy2 Node"
    type: hysteria2
    server: 192.0.2.10
    port: 30443
    password: secret:pass
    obfs: salamander
    obfs-password: obfspw
    sni: hy.example.net
    skip-cert-verify: false
"#;
        let profile = parse_clash_yaml(yaml).unwrap();
        let (tags, outbounds) = convert_proxies_to_singbox(&profile.proxies);
        assert_eq!(tags, vec!["Test Reality", "Hy2 Node"]);
        assert_eq!(outbounds[0]["type"], "vless");
        assert_eq!(outbounds[0]["tls"]["reality"]["public_key"], "pubkey123");
        assert_eq!(outbounds[0]["tls"]["utls"]["fingerprint"], "edge");
        assert_eq!(outbounds[1]["type"], "hysteria2");
        assert_eq!(outbounds[1]["obfs"]["type"], "salamander");
        assert_eq!(outbounds[1]["obfs"]["password"], "obfspw");
    }

    #[test]
    fn dns_uses_remote_doh_and_quad9_bootstrap_without_detour_direct() {
        let cfg = build_singbox_config(
            "proxy",
            &["n1".into()],
            vec![],
            Path::new("/usr/local/share/sing-box"),
            "sec",
            "auto",
            "wg_mw",
            1400,
        );
        let bootstrap = &cfg["dns"]["servers"][0];
        assert_eq!(bootstrap["tag"], "dns-bootstrap");
        assert_eq!(bootstrap["type"], "tls");
        assert_eq!(bootstrap["server"], "9.9.9.9");
        assert!(bootstrap.get("detour").is_none());
        assert_eq!(cfg["dns"]["final"], "dns-remote");
        assert_eq!(cfg["dns"]["rules"].as_array().unwrap().len(), 0);
    }
}
