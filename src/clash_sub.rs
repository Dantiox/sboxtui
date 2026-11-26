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

fn next_unique_tag(base_name: &str, used_tags: &mut HashSet<String>) -> Option<String> {
    let base_tag = base_name.trim();
    if base_tag.is_empty() {
        return None;
    }
    let mut tag = base_tag.to_string();
    let mut n = 2usize;
    while !used_tags.insert(tag.clone()) {
        tag = format!("{base_tag} #{n}");
        n += 1;
    }
    Some(tag)
}

/// Converts Clash `vless` and `hysteria2` proxies into `sing-box` outbound JSON objects.
pub fn convert_proxies_to_singbox(proxies: &[ClashProxy]) -> (Vec<String>, Vec<Value>) {
    let mut used_tags = HashSet::new();
    let mut tags = Vec::new();
    let mut outbounds = Vec::new();

    for p in proxies {
        let Some(tag) = next_unique_tag(&p.name, &mut used_tags) else {
            continue;
        };

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

/// Converts Clash `vless` (non-gRPC) and `hysteria2` proxies into `shoes` `client_chains` YAML entries.
pub fn convert_proxies_to_shoes(
    proxies: &[ClashProxy],
) -> (Vec<String>, Vec<serde_yaml_ng::Value>) {
    let mut used_tags = HashSet::new();
    let mut tags = Vec::new();
    let mut chains = Vec::new();

    for p in proxies {
        let Some(tag) = next_unique_tag(&p.name, &mut used_tags) else {
            continue;
        };

        let chain = match p.proxy_type.as_str() {
            "vless" => build_shoes_vless_chain(&tag, p),
            "hysteria2" => build_shoes_hy2_chain(&tag, p),
            _ => None,
        };
        if let Some(val) = chain {
            tags.push(tag);
            chains.push(val);
        }
    }

    (tags, chains)
}

fn build_shoes_vless_chain(tag: &str, p: &ClashProxy) -> Option<serde_yaml_ng::Value> {
    if p.network.as_deref() == Some("grpc") {
        return None;
    }
    let uuid = p.uuid.as_deref()?;
    let addr = format!("{}:{}", p.server, p.port);
    let mut inner = serde_yaml_ng::Mapping::new();
    inner.insert("type".into(), "vless".into());
    inner.insert("user_id".into(), uuid.into());
    inner.insert("udp_enabled".into(), true.into());
    let inner_val = serde_yaml_ng::Value::Mapping(inner);

    let sni = p
        .servername
        .as_deref()
        .or(p.sni.as_deref())
        .unwrap_or(&p.server);

    let protocol = if let Some(r) = &p.reality_opts {
        let mut proto = serde_yaml_ng::Mapping::new();
        proto.insert("type".into(), "reality".into());
        proto.insert("public_key".into(), r.public_key.as_str().into());
        proto.insert(
            "short_id".into(),
            r.short_id.as_deref().unwrap_or("").into(),
        );
        proto.insert("sni_hostname".into(), sni.into());
        proto.insert(
            "vision".into(),
            (p.flow.as_deref() == Some("xtls-rprx-vision")).into(),
        );
        proto.insert("protocol".into(), inner_val);
        serde_yaml_ng::Value::Mapping(proto)
    } else if p.tls.unwrap_or(false) {
        let mut proto = serde_yaml_ng::Mapping::new();
        proto.insert("type".into(), "tls".into());
        proto.insert("sni_hostname".into(), sni.into());
        proto.insert("verify".into(), (!p.skip_cert_verify.unwrap_or(false)).into());
        proto.insert("protocol".into(), inner_val);
        serde_yaml_ng::Value::Mapping(proto)
    } else {
        inner_val
    };

    let mut hop = serde_yaml_ng::Mapping::new();
    hop.insert("name".into(), tag.into());
    hop.insert("address".into(), addr.into());
    hop.insert("protocol".into(), protocol);

    let mut entry = serde_yaml_ng::Mapping::new();
    entry.insert(
        "chain".into(),
        serde_yaml_ng::Value::Sequence(vec![serde_yaml_ng::Value::Mapping(hop)]),
    );
    Some(serde_yaml_ng::Value::Mapping(entry))
}

fn build_shoes_hy2_chain(tag: &str, p: &ClashProxy) -> Option<serde_yaml_ng::Value> {
    let password = p.password.as_deref()?;
    let addr = format!("{}:{}", p.server, p.port);
    let sni = p
        .sni
        .as_deref()
        .or(p.servername.as_deref())
        .unwrap_or(&p.server);
    let alpn: Vec<serde_yaml_ng::Value> = p
        .alpn
        .as_ref()
        .filter(|a| !a.is_empty())
        .map(|a| a.iter().map(|s| s.as_str().into()).collect())
        .unwrap_or_else(|| vec!["h3".into()]);

    let mut quic = serde_yaml_ng::Mapping::new();
    quic.insert("sni_hostname".into(), sni.into());
    quic.insert("verify".into(), (!p.skip_cert_verify.unwrap_or(false)).into());
    quic.insert("alpn_protocols".into(), serde_yaml_ng::Value::Sequence(alpn));

    let mut proto = serde_yaml_ng::Mapping::new();
    proto.insert("type".into(), "hysteria2".into());
    proto.insert("password".into(), password.into());
    proto.insert("udp_enabled".into(), true.into());
    if p.obfs.as_deref() == Some("salamander")
        && let Some(pw) = &p.obfs_password
    {
        let mut obfs = serde_yaml_ng::Mapping::new();
        obfs.insert("type".into(), "salamander".into());
        obfs.insert("password".into(), pw.as_str().into());
        proto.insert("obfs".into(), serde_yaml_ng::Value::Mapping(obfs));
    }

    let mut hop = serde_yaml_ng::Mapping::new();
    hop.insert("name".into(), tag.into());
    hop.insert("address".into(), addr.into());
    hop.insert("quic_settings".into(), serde_yaml_ng::Value::Mapping(quic));
    hop.insert("protocol".into(), serde_yaml_ng::Value::Mapping(proto));

    let mut entry = serde_yaml_ng::Mapping::new();
    entry.insert(
        "chain".into(),
        serde_yaml_ng::Value::Sequence(vec![serde_yaml_ng::Value::Mapping(hop)]),
    );
    Some(serde_yaml_ng::Value::Mapping(entry))
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

/// Builds a complete `shoes` desktop YAML configuration from parsed chains.
pub fn build_shoes_config(
    group_name: &str,
    node_tags: &[String],
    node_chains: Vec<serde_yaml_ng::Value>,
    rules_dir: &Path,
    clash_secret: &str,
    tun_mtu: u16,
) -> Result<serde_yaml_ng::Value> {
    let default_node = node_tags
        .first()
        .cloned()
        .unwrap_or_else(|| "direct".to_string());
    let tun_mtu_val = serde_yaml_ng::Value::Number(serde_yaml_ng::Number::from(u64::from(tun_mtu)));

    let mut seq = Vec::new();
    let mut api = serde_yaml_ng::Mapping::new();
    api.insert("clash_api_address".into(), "127.0.0.1:9097".into());
    api.insert("secret".into(), clash_secret.into());
    seq.push(serde_yaml_ng::Value::Mapping(api));

    let mut cache = serde_yaml_ng::Mapping::new();
    cache.insert("cache_file_path".into(), "/var/lib/shoes/cache.db".into());
    seq.push(serde_yaml_ng::Value::Mapping(cache));

    for (name, file) in [
        ("geoip-ru", "geoip-ru.srs"),
        ("geosite-ru", "geosite-category-ru.srs"),
        ("geosite-ads", "geosite-category-ads-all.srs"),
    ] {
        let mut rs = serde_yaml_ng::Mapping::new();
        rs.insert("rule_source_group".into(), name.into());
        rs.insert(
            "rules".into(),
            serde_yaml_ng::Value::Sequence(vec![
                rules_dir.join(file).to_string_lossy().as_ref().into(),
            ]),
        );
        seq.push(serde_yaml_ng::Value::Mapping(rs));
    }

    let mut group = serde_yaml_ng::Mapping::new();
    group.insert("client_group".into(), group_name.into());
    group.insert("type".into(), "selector".into());
    group.insert("default".into(), default_node.into());
    group.insert("client_chains".into(), serde_yaml_ng::Value::Sequence(node_chains));
    seq.push(serde_yaml_ng::Value::Mapping(group));

    let rules_yaml = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(&format!(
        r#"
rule_group: "desktop-rules"
rules:
  - masks:
      - "10.0.0.0/8"
      - "172.16.0.0/12"
      - "192.168.0.0/16"
      - "100.64.0.0/10"
    action: "allow"
    client_chain:
      protocol:
        type: "direct"
  - conditions:
      rule_source_group: "geosite-ads"
    action: "block"
  - conditions:
      any:
        - rule_source_group: "geoip-ru"
        - rule_source_group: "geosite-ru"
    action: "allow"
    client_chain:
      protocol:
        type: "direct"
  - conditions:
      any_destination: true
    action: "allow"
    client_chain: "{group_name}"
"#
    ))?;
    seq.push(rules_yaml);

    let mut tun = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(&format!(
        r#"
name: "tun-in"
device_name: "shoes0"
auto_route: true
auto_redirect: true
auto_dns: false
dns_hijack: true
addresses:
  - "10.233.0.1/30"
route_address:
  - "0.0.0.0/0"
bootstrap_dns:
  - "9.9.9.9:53"
resource_limits:
  tcp_buffer_size: 32768
dns:
  servers:
    - url: "https://8.8.8.8/dns-query"
      client_chain: "{group_name}"
rules: "desktop-rules"
"#
    ))?;
    if let Some(m) = tun.as_mapping_mut() {
        m.insert("mtu".into(), tun_mtu_val);
    }
    seq.push(tun);

    Ok(serde_yaml_ng::Value::Sequence(seq))
}

/// Replaces the `client_chains` inside the matching `client_group` entry of a `shoes` config YAML.
pub fn replace_nodes_in_shoes_config(
    doc: &mut serde_yaml_ng::Value,
    group_name: &str,
    node_tags: &[String],
    node_chains: Vec<serde_yaml_ng::Value>,
) -> Result<()> {
    let entries = doc
        .as_sequence_mut()
        .context("shoes config root must be a YAML sequence")?;
    for item in entries.iter_mut() {
        let Some(map) = item.as_mapping_mut() else {
            continue;
        };
        if map
            .get(serde_yaml_ng::Value::String("client_group".to_string()))
            .and_then(|v| v.as_str())
            == Some(group_name)
        {
            let existing_default = map
                .get(serde_yaml_ng::Value::String("default".to_string()))
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let next_default = existing_default
                .filter(|d| node_tags.iter().any(|t| t == d))
                .or_else(|| node_tags.first().cloned())
                .unwrap_or_else(|| "direct".to_string());
            map.insert("default".into(), next_default.into());
            map.insert(
                "client_chains".into(),
                serde_yaml_ng::Value::Sequence(node_chains),
            );
            return Ok(());
        }
    }
    anyhow::bail!("missing client_group '{group_name}' in shoes config")
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

    #[test]
    fn converts_and_updates_shoes_yaml_skipping_grpc() {
        let yaml = r#"
proxies:
  - name: "Reality Non-V4"
    type: vless
    server: 198.51.100.1
    port: 443
    network: tcp
    uuid: 00000000-0000-0000-0000-000000000001
    flow: xtls-rprx-vision
    tls: true
    servername: cdn.example.net
    reality-opts:
      public-key: pubkey123
      short-id: abcd
  - name: "Skipped gRPC"
    type: vless
    server: 198.51.100.2
    port: 443
    network: grpc
    uuid: 11111111-2222-4333-8444-555555555555
    tls: true
  - name: "Hy2 Node"
    type: hysteria2
    server: 192.0.2.10
    port: 30443
    password: secret
    obfs: salamander
    obfs-password: obfspw
    sni: hy.example.net
"#;
        let profile = parse_clash_yaml(yaml).unwrap();
        let (tags, chains) = convert_proxies_to_shoes(&profile.proxies);
        assert_eq!(tags, vec!["Reality Non-V4", "Hy2 Node"]);
        let mut cfg = build_shoes_config(
            "proxy",
            &tags,
            chains,
            Path::new("/usr/local/share/sing-box"),
            "sec",
            1400,
        )
        .unwrap();
        replace_nodes_in_shoes_config(
            &mut cfg,
            "proxy",
            &["Hy2 Node".into()],
            vec![],
        )
        .unwrap();
        let group = cfg
            .as_sequence()
            .unwrap()
            .iter()
            .find(|e| e.get("client_group").and_then(|v| v.as_str()) == Some("proxy"))
            .unwrap();
        assert_eq!(group.get("default").and_then(|v| v.as_str()), Some("Hy2 Node"));
    }
}
