mod clash_api;
mod clash_sub;
mod config;
mod net_nm;
mod rules;
mod tui;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use clash_api::ClashClient;
use clash_sub::{
    build_shoes_config, build_singbox_config, convert_proxies_to_shoes, convert_proxies_to_singbox,
    fetch_clash_subscription, parse_clash_yaml, replace_nodes_in_config,
    replace_nodes_in_shoes_config,
};
use config::{AppConfig, CoreKind};
use rules::{SaveOutcome, save_or_stage_config, save_or_stage_shoes_config};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

#[derive(Clone, Copy, ValueEnum)]
enum CliCore {
    Auto,
    Shoes,
    SingBox,
}

impl From<CliCore> for CoreKind {
    fn from(value: CliCore) -> Self {
        match value {
            CliCore::Auto => CoreKind::Auto,
            CliCore::Shoes => CoreKind::Shoes,
            CliCore::SingBox => CoreKind::SingBox,
        }
    }
}

#[derive(Parser)]
#[command(
    name = "sboxtui",
    version,
    about = "Energy-efficient TUI controller for shoes / sing-box + Clash subscriptions + WireGuard"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Fetch Clash YAML subscription and update proxy config (shoes YAML or sing-box JSON)
    Sync {
        /// Subscription URL (overrides subscription_url in config.toml)
        #[arg(long)]
        url: Option<String>,
        /// Read Clash YAML from a local file instead of fetching over HTTP
        #[arg(long)]
        file: Option<PathBuf>,
        /// Write complete config to a path instead of updating the active core config path
        #[arg(long)]
        output: Option<PathBuf>,
        /// Clash API secret to embed when generating a fresh config
        #[arg(long)]
        secret: Option<String>,
        /// Target proxy core (defaults to config/auto-detection)
        #[arg(long, value_enum, default_value = "auto")]
        core: CliCore,
    },
    /// Print current proxy core runtime, active node, and WireGuard connection states
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
            core,
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

            let target_core = match CoreKind::from(core) {
                CoreKind::Auto => cfg.effective_core(None),
                explicit => explicit,
            };
            let target_path = output.unwrap_or_else(|| cfg.active_config_path(target_core).to_path_buf());
            let live_active_node = cfg
                .resolve_secret()
                .ok()
                .and_then(|sec| ClashClient::new(&cfg.clash_api_url, &sec).ok())
                .and_then(|api| api.get_proxies().ok())
                .and_then(|p| p.proxies.get(&cfg.default_group).and_then(|g| g.now.clone()));

            match target_core {
                CoreKind::Shoes | CoreKind::Auto => {
                    let (tags, chains) = convert_proxies_to_shoes(&profile.proxies);
                    let count = tags.len();
                    let next_doc = if target_path.exists() {
                        let raw = fs::read_to_string(&target_path)
                            .with_context(|| format!("failed to read {}", target_path.display()))?;
                        let mut existing: serde_yaml_ng::Value = serde_yaml_ng::from_str(&raw)?;
                        replace_nodes_in_shoes_config(
                            &mut existing,
                            &cfg.default_group,
                            &tags,
                            chains,
                            live_active_node.as_deref(),
                        )?;
                        existing
                    } else {
                        let sec = secret
                            .or_else(|| cfg.resolve_secret().ok())
                            .unwrap_or_else(|| "change-me".to_string());
                        build_shoes_config(
                            &cfg.default_group,
                            &tags,
                            chains,
                            &cfg.rules_dir,
                            &sec,
                            cfg.tun_mtu,
                            live_active_node.as_deref(),
                        )?
                    };

                    match save_or_stage_shoes_config(&next_doc, &target_path)? {
                        SaveOutcome::WrittenDirect => {
                            println!(
                                "Synced {count} nodes -> {} (shoes check OK)",
                                target_path.display()
                            );
                        }
                        SaveOutcome::Staged { staged } => {
                            println!(
                                "Synced {count} nodes & validated, staged at {} (apply: run0 install -o root -g techpriest -m 0640 {} {})",
                                staged.display(),
                                staged.display(),
                                target_path.display()
                            );
                        }
                    }
                }
                CoreKind::SingBox => {
                    let (tags, outbounds) = convert_proxies_to_singbox(&profile.proxies);
                    let count = tags.len();
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
                }
            }
            Ok(())
        }
        Some(Commands::Status) => {
            let secret = cfg.resolve_secret()?;
            let api = ClashClient::new(&cfg.clash_api_url, &secret)?;
            let ver = api.get_version()?;
            let proxies = api.get_proxies()?;
            println!("core version: {}", ver.version);
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
