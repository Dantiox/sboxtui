use anyhow::{Context, Result};
use reqwest::blocking::Client;
use serde::Deserialize;
use std::collections::BTreeMap;

/// Blocking HTTP client for `sing-box`'s built-in Clash API (`127.0.0.1:9097`).
#[derive(Clone)]
pub struct ClashClient {
    base_url: String,
    token: String,
    http: Client,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VersionResp {
    #[serde(default)]
    pub version: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProxiesResp {
    #[serde(default)]
    pub proxies: BTreeMap<String, ProxyEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyEntry {
    #[serde(rename = "type", default)]
    pub proxy_type: String,
    #[serde(default)]
    pub now: Option<String>,
    #[serde(default)]
    pub all: Vec<String>,
    #[serde(default)]
    pub history: Vec<DelaySample>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DelaySample {
    #[serde(default)]
    pub delay: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DelayResp {
    #[serde(default)]
    pub delay: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConnectionsResp {
    #[serde(rename = "downloadTotal", default)]
    pub download_total: u64,
    #[serde(rename = "uploadTotal", default)]
    pub upload_total: u64,
    #[serde(default)]
    pub connections: Vec<ConnectionEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConnectionEntry {
    #[serde(default)]
    pub upload: u64,
    #[serde(default)]
    pub download: u64,
    #[serde(default)]
    pub rule: String,
    #[serde(default)]
    pub chains: Vec<String>,
    #[serde(default)]
    pub metadata: ConnectionMeta,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ConnectionMeta {
    #[serde(default)]
    pub host: String,
    #[serde(rename = "destinationIP", default)]
    pub destination_ip: String,
    #[serde(rename = "destinationPort", default)]
    pub destination_port: String,
    #[serde(rename = "processPath", default)]
    pub process_path: String,
}

impl ClashClient {
    pub fn new(base_url: &str, token: &str) -> Result<Self> {
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(6))
            .build()?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            token: token.to_string(),
            http,
        })
    }

    fn get_json<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .with_context(|| format!("GET {url} failed"))?;
        let status = resp.status();
        let text = resp.text()?;
        if !status.is_success() {
            anyhow::bail!("GET {path} -> HTTP {status}: {text}");
        }
        serde_json::from_str(&text)
            .with_context(|| format!("failed to decode JSON from {path}: {text}"))
    }

    pub fn get_version(&self) -> Result<VersionResp> {
        self.get_json("/version")
    }

    pub fn get_proxies(&self) -> Result<ProxiesResp> {
        self.get_json("/proxies")
    }

    pub fn get_connections(&self) -> Result<ConnectionsResp> {
        self.get_json("/connections")
    }

    pub fn select_proxy(&self, group: &str, node_name: &str) -> Result<()> {
        let encoded_group = percent_encode(group);
        let url = format!("{}/proxies/{encoded_group}", self.base_url);
        let resp = self
            .http
            .put(&url)
            .bearer_auth(&self.token)
            .json(&serde_json::json!({ "name": node_name }))
            .send()?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().unwrap_or_default();
            anyhow::bail!("PUT /proxies/{group} failed ({status}): {text}");
        }
        Ok(())
    }

    pub fn test_delay(&self, node_name: &str) -> Result<u64> {
        let encoded = percent_encode(node_name);
        let path = format!(
            "/proxies/{encoded}/delay?url=https%3A%2F%2Fcp.cloudflare.com%2Fgenerate_204&timeout=5000"
        );
        let res: DelayResp = self.get_json(&path)?;
        Ok(res.delay)
    }
}

fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
