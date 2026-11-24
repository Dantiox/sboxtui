mod clash_api;
mod clash_sub;
mod config;
mod net_nm;
mod rules;
mod tui;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use clash_api::ClashClient;
use clash_sub::{
    build_singbox_config, convert_proxies_to_singbox, fetch_clash_subscription, parse_clash_yaml,
    replace_nodes_in_config,
};
use config::AppConfig;
use rules::{SaveOutcome, save_or_stage_config};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "sboxtui",
    version,
    about = "Energy-efficient TUI controller for sing-box (system stack) + Clash subscriptions + WireGuard"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Fetch Clash YAML subscription and update sing-box config.json (or --output)
    Sync {
        /// Subscription URL (overrides subscription_url in config.toml)
        #[arg(long)]
        url: Option<String>,
        /// Read Clash YAML from a local file instead of fetching over HTTP
        #[arg(long)]
        file: Option<PathBuf>,
        /// Write complete sing-box config.json to a path instead of updating singbox_config_path
        #[arg(long)]
        output: Option<PathBuf>,
        /// Clash API secret to embed when generating a fresh config with --output
        #[arg(long)]
        secret: Option<String>,
    },
    /// Print current sing-box runtime, active node, and WireGuard connection states
    Status,
    /// Initialize ~/.config/sboxtui/config.toml if missing
    InitConfig,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg_path = AppConfig::default_path()?;
    let cfg = AppConfig::load_or_default(&cfg_path)?;

    match cli.command {
        None => {
            let secret = cfg.resolve_secret()?;
            let api = ClashClient::new(&cfg.clash_api_url, &secret)?;
            tui::run_tui(cfg, api)
        }
        Some(Commands::InitConfig) => {
            if cfg_path.exists() {
                println!("Config already exists at {}", cfg_path.display());
            } else {
                cfg.save(&cfg_path)?;
                println!("Wrote default config to {}", cfg_path.display());
            }
            Ok(())
        }
        Some(Commands::Sync {
            url,
            file,
            output,
            secret,
        }) => {
            let profile = if let Some(yaml_path) = file {
                let raw = fs::read_to_string(&yaml_path)
                    .with_context(|| format!("failed to read {}", yaml_path.display()))?;
                parse_clash_yaml(&raw)?
            } else {
                let sub_url = url
                    .or_else(|| cfg.subscription_url.clone())
                    .context("no subscription URL given; pass --url, --file, or set subscription_url in config.toml")?;
                fetch_clash_subscription(&sub_url)?
            };

            let (tags, outbounds) = convert_proxies_to_singbox(&profile.proxies);
            let count = tags.len();
            let target_path = output.unwrap_or_else(|| cfg.singbox_config_path.clone());

            let next_cfg = if target_path.exists() {
                let raw = fs::read_to_string(&target_path)
                    .with_context(|| format!("failed to read {}", target_path.display()))?;
                let mut existing: Value = serde_json::from_str(&raw)?;
                replace_nodes_in_config(
                    &mut existing,
                    &cfg.default_group,
                    &tags,
                    outbounds,
                    &cfg.wg_remote_connection,
                )?;
                existing
            } else {
                let sec = secret
                    .or_else(|| cfg.resolve_secret().ok())
                    .unwrap_or_else(|| "change-me".to_string());
                build_singbox_config(
                    &cfg.default_group,
                    &tags,
                    outbounds,
                    &cfg.rules_dir,
                    &sec,
                    &cfg.default_interface,
                    &cfg.wg_remote_connection,
                    cfg.tun_mtu,
                )
            };

            match save_or_stage_config(&next_cfg, &target_path)? {
                SaveOutcome::WrittenDirect => {
                    println!(
                        "Synced {count} nodes -> {} (sing-box check OK)",
                        target_path.display()
                    );
                }
                SaveOutcome::Staged { staged } => {
                    println!(
                        "Synced {count} nodes & validated, staged at {} (apply with root)",
                        staged.display()
                    );
                }
            }
            Ok(())
        }
        Some(Commands::Status) => {
            let secret = cfg.resolve_secret()?;
            let api = ClashClient::new(&cfg.clash_api_url, &secret)?;
            let ver = api.get_version()?;
            let proxies = api.get_proxies()?;
            println!("sing-box version: {}", ver.version);
            if let Some(grp) = proxies.proxies.get(&cfg.default_group) {
                println!(
                    "group [{}]: selected = {}",
                    cfg.default_group,
                    grp.now.as_deref().unwrap_or("none")
                );
            }
            for c in net_nm::list_nm_connections()? {
                println!(
                    "nm [{}] type={} state={} dev={}",
                    c.name, c.conn_type, c.state, c.device
                );
            }
            Ok(())
        }
    }
}
