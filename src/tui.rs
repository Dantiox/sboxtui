use crate::clash_api::{ClashClient, ConnectionEntry, ProxyEntry};
use crate::clash_sub::{
    convert_proxies_to_shoes, convert_proxies_to_singbox, fetch_clash_subscription,
    replace_nodes_in_config, replace_nodes_in_shoes_config,
};
use crate::config::{AppConfig, CoreKind};
use crate::net_nm::{
    NmConnection, active_wifi_from_connections, list_interfaces, list_nm_connections,
    list_process_names, set_connection_state,
};
use crate::rules::{
    RuleKind, RuleSummary, SaveOutcome, delete_rule, delete_shoes_rule, insert_shoes_user_rule,
    insert_user_rule, read_default_interface, save_or_stage_config, save_or_stage_shoes_config,
    set_default_interface, summarize_rules, summarize_shoes_rules, swap_rules, swap_shoes_rules,
};
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, List, ListItem, ListState, Paragraph, Row, Table, TableState,
    Tabs, Wrap,
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Nodes = 0,
    Rules = 1,
    WireGuard = 2,
    Connections = 3,
}

impl Tab {
    const TITLES: [&'static str; 4] = [
        "1: Nodes & Stats",
        "2: Routing Rules",
        "3: WireGuard & Uplink",
        "4: Connections",
    ];
}

#[derive(Debug, Clone)]
enum Modal {
    None,
    AddRule {
        step: AddRuleStep,
        kind_idx: usize,
        value: String,
        target_idx: usize,
        procs: Vec<String>,
        proc_cursor: usize,
    },
    SetWan {
        ifaces: Vec<String>,
        cursor: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddRuleStep {
    Kind,
    Value,
    Target,
}

enum ConfigDoc {
    Shoes(serde_yaml_ng::Value),
    SingBox(Value),
}

impl ConfigDoc {
    fn summarize_rules(&self) -> Vec<RuleSummary> {
        match self {
            Self::Shoes(doc) => summarize_shoes_rules(doc),
            Self::SingBox(cfg) => summarize_rules(cfg),
        }
    }

    fn delete_rule(&mut self, index: usize) -> Result<()> {
        match self {
            Self::Shoes(doc) => delete_shoes_rule(doc, index),
            Self::SingBox(cfg) => delete_rule(cfg, index),
        }
    }

    fn swap_rules(&mut self, a: usize, b: usize) -> Result<()> {
        match self {
            Self::Shoes(doc) => swap_shoes_rules(doc, a, b),
            Self::SingBox(cfg) => swap_rules(cfg, a, b),
        }
    }
}

pub struct App {
    cfg: AppConfig,
    api: ClashClient,
    tab: Tab,
    status_msg: String,

    engine_version: Option<String>,
    proxies: BTreeMap<String, ProxyEntry>,
    group_nodes: Vec<String>,
    active_node: Option<String>,
    connections: Vec<ConnectionEntry>,
    upload_total: u64,
    download_total: u64,

    config_doc: Option<ConfigDoc>,
    default_interface: String,
    wifi_ssid: Option<String>,
    nm_conns: Vec<NmConnection>,

    node_filter: String,
    searching_nodes: bool,
    node_state: TableState,
    rule_state: TableState,
    wg_state: TableState,
    conn_state: TableState,

    modal: Modal,
    last_refresh: Instant,
    should_quit: bool,
    refresh_tx: Option<Sender<bool>>,
}

struct RefreshSnapshot {
    engine_version: Result<String, String>,
    proxies: Option<BTreeMap<String, ProxyEntry>>,
    group_nodes: Option<Vec<String>>,
    active_node: Option<String>,
    connections: Option<(Vec<ConnectionEntry>, u64, u64)>,
    nm_conns: Option<Vec<NmConnection>>,
}

impl App {
    pub fn new(cfg: AppConfig, api: ClashClient) -> Self {
        let mut config_doc = None;
        let mut default_interface = cfg.default_interface.clone();
        let mut rule_state = TableState::default();
        match cfg.effective_core(None) {
            CoreKind::Shoes => {
                if let Ok(raw) = fs::read_to_string(&cfg.shoes_config_path)
                    && let Ok(doc) = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(&raw)
                {
                    default_interface = "auto-route".to_string();
                    config_doc = Some(ConfigDoc::Shoes(doc));
                    rule_state.select(Some(0));
                }
            }
            CoreKind::SingBox | CoreKind::Auto => {
                if let Ok(raw) = fs::read_to_string(&cfg.singbox_config_path)
                    && let Ok(val) = serde_json::from_str::<Value>(&raw)
                {
                    default_interface = read_default_interface(&val);
                    config_doc = Some(ConfigDoc::SingBox(val));
                    rule_state.select(Some(0));
                }
            }
        }

        Self {
            default_interface,
            cfg,
            api,
            tab: Tab::Nodes,
            status_msg: "Loading telemetry...".to_string(),
            engine_version: None,
            proxies: BTreeMap::new(),
            group_nodes: Vec::new(),
            active_node: None,
            connections: Vec::new(),
            upload_total: 0,
            download_total: 0,
            config_doc,
            wifi_ssid: None,
            nm_conns: Vec::new(),
            node_filter: String::new(),
            searching_nodes: false,
            node_state: TableState::default(),
            rule_state,
            wg_state: TableState::default(),
            conn_state: TableState::default(),
            modal: Modal::None,
            last_refresh: Instant::now(),
            should_quit: false,
            refresh_tx: None,
        }
    }

    fn active_core(&self) -> CoreKind {
        self.cfg.effective_core(self.engine_version.as_deref())
    }

    pub fn refresh_all(&mut self) {
        self.last_refresh = Instant::now();
        if let Some(tx) = &self.refresh_tx {
            let _ = tx.send(true);
        }
    }

    fn apply_snapshot(&mut self, snap: RefreshSnapshot) {
        if let Some(conns) = snap.nm_conns {
            self.wifi_ssid = active_wifi_from_connections(&conns);
            self.nm_conns = conns;
            if self.wg_state.selected().is_none() && !self.nm_conns.is_empty() {
                self.wg_state.select(Some(0));
            }
        }
        match snap.engine_version {
            Ok(v) => {
                if self.engine_version.is_none() && self.status_msg == "Loading telemetry..." {
                    self.status_msg = "Ready. Use 1-4/Tab to navigate, / to search, q to quit.".to_string();
                }
                self.engine_version = Some(v);
            }
            Err(e) => {
                self.engine_version = None;
                self.status_msg = format!("Clash API unreachable: {e}");
                return;
            }
        }
        if let Some(nodes) = snap.group_nodes {
            self.group_nodes = nodes;
            if self.node_state.selected().is_none() && !self.group_nodes.is_empty() {
                self.node_state.select(Some(0));
            }
        }
        if snap.active_node.is_some() {
            self.active_node = snap.active_node;
        }
        if let Some(p) = snap.proxies {
            self.proxies = p;
        }
        if let Some((conns, up, down)) = snap.connections {
            self.upload_total = up;
            self.download_total = down;
            self.connections = conns;
            if self.conn_state.selected().is_none() && !self.connections.is_empty() {
                self.conn_state.select(Some(0));
            }
        }
    }

    fn filtered_nodes(&self) -> Vec<&String> {
        let tokens: Vec<String> = self
            .node_filter
            .split_whitespace()
            .map(str::to_lowercase)
            .collect();
        self.group_nodes
            .iter()
            .filter(|name| {
                let proto = self
                    .proxies
                    .get(name.as_str())
                    .map(|p| p.proxy_type.as_str())
                    .unwrap_or("");
                matches_node_query(name, proto, &tokens)
            })
            .collect()
    }

    fn available_targets(&self) -> Vec<String> {
        let mut t = vec![
            self.cfg.default_group.clone(),
            "direct".to_string(),
            "reject".to_string(),
        ];
        if !self.cfg.wg_remote_connection.trim().is_empty() {
            t.insert(2, self.cfg.wg_remote_connection.clone());
        }
        t
    }

    fn handle_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.should_quit = true;
            return;
        }
        if !matches!(self.modal, Modal::None) {
            self.handle_modal_key(key);
            return;
        }
        if self.searching_nodes && self.tab == Tab::Nodes {
            self.handle_node_search_key(key);
            return;
        }

        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('f') {
            self.tab = Tab::Nodes;
            self.searching_nodes = true;
            return;
        }

        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('1') => self.tab = Tab::Nodes,
            KeyCode::Char('2') => self.tab = Tab::Rules,
            KeyCode::Char('3') => self.tab = Tab::WireGuard,
            KeyCode::Char('4') => self.tab = Tab::Connections,
            KeyCode::Tab => {
                self.tab = match self.tab {
                    Tab::Nodes => Tab::Rules,
                    Tab::Rules => Tab::WireGuard,
                    Tab::WireGuard => Tab::Connections,
                    Tab::Connections => Tab::Nodes,
                };
            }
            KeyCode::Char('R') | KeyCode::F(5) => {
                self.refresh_all();
                self.status_msg = "Refreshed.".to_string();
            }
            _ => self.handle_tab_key(key),
        }
    }

    fn handle_tab_key(&mut self, key: KeyEvent) {
        match self.tab {
            Tab::Nodes => match key.code {
                KeyCode::Down | KeyCode::Char('j') => {
                    let len = self.filtered_nodes().len();
                    move_table(&mut self.node_state, len, 1);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    let len = self.filtered_nodes().len();
                    move_table(&mut self.node_state, len, -1);
                }
                KeyCode::Char('/') | KeyCode::Char('f') => {
                    self.searching_nodes = true;
                }
                KeyCode::Esc => {
                    if !self.node_filter.is_empty() {
                        self.node_filter.clear();
                        self.node_state.select((!self.group_nodes.is_empty()).then_some(0));
                        self.status_msg = "Filter cleared.".to_string();
                    }
                }
                KeyCode::Enter => {
                    let selected = self
                        .node_state
                        .selected()
                        .and_then(|i| self.filtered_nodes().get(i).copied())
                        .cloned();
                    if let Some(node) = selected {
                        self.status_msg =
                            match self.api.select_proxy(&self.cfg.default_group, &node) {
                                Ok(()) => format!("Switched -> {node}"),
                                Err(e) => format!("Switch failed: {e}"),
                            };
                        self.refresh_all();
                    }
                }
                KeyCode::Char('p') => {
                    let selected = self
                        .node_state
                        .selected()
                        .and_then(|i| self.filtered_nodes().get(i).copied())
                        .cloned();
                    if let Some(node) = selected {
                        self.status_msg = match self.api.test_delay(&node) {
                            Ok(ms) => format!("{node}: {ms} ms"),
                            Err(e) => format!("Probe {node} failed: {e}"),
                        };
                        self.refresh_all();
                    }
                }
                KeyCode::Char('s') => self.sync_subscription_in_tui(),
                _ => {}
            },
            Tab::Rules => {
                let rule_len = self
                    .config_doc
                    .as_ref()
                    .map(ConfigDoc::summarize_rules)
                    .map(|r| r.len())
                    .unwrap_or(0);
                match key.code {
                    KeyCode::Down | KeyCode::Char('j') => {
                        move_table(&mut self.rule_state, rule_len, 1);
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        move_table(&mut self.rule_state, rule_len, -1);
                    }
                    KeyCode::Char('a') => {
                        let default_kind = if self.active_core() == CoreKind::Shoes {
                            3
                        } else {
                            0
                        };
                        self.modal = Modal::AddRule {
                            step: AddRuleStep::Kind,
                            kind_idx: default_kind,
                            value: String::new(),
                            target_idx: 0,
                            procs: list_process_names(),
                            proc_cursor: 0,
                        };
                    }
                    KeyCode::Char('d') => {
                        if let (Some(idx), Some(doc)) =
                            (self.rule_state.selected(), self.config_doc.as_mut())
                        {
                            let summary = doc.summarize_rules();
                            if summary.get(idx).is_some_and(|r| !r.is_builtin) {
                                let _ = doc.delete_rule(idx);
                                self.status_msg =
                                    "Rule deleted in buffer. Press 'w' to validate & save."
                                        .to_string();
                            } else {
                                self.status_msg = "Built-in rules stay pinned.".to_string();
                            }
                        }
                    }
                    KeyCode::Char('K') => {
                        if let (Some(idx), Some(doc)) =
                            (self.rule_state.selected(), self.config_doc.as_mut())
                            && idx > 0
                        {
                            let summary = doc.summarize_rules();
                            if summary.get(idx - 1).is_some_and(|r| !r.is_builtin) {
                                let _ = doc.swap_rules(idx, idx - 1);
                                self.rule_state.select(Some(idx - 1));
                            }
                        }
                    }
                    KeyCode::Char('J') => {
                        if let (Some(idx), Some(doc)) =
                            (self.rule_state.selected(), self.config_doc.as_mut())
                            && idx + 1 < rule_len
                        {
                            let summary = doc.summarize_rules();
                            if summary.get(idx).is_some_and(|r| !r.is_builtin)
                                && summary.get(idx + 1).is_some_and(|r| !r.is_builtin)
                            {
                                let _ = doc.swap_rules(idx, idx + 1);
                                self.rule_state.select(Some(idx + 1));
                            }
                        }
                    }
                    KeyCode::Char('w') => self.save_active_config(),
                    _ => {}
                }
            }
            Tab::WireGuard => match key.code {
                KeyCode::Down | KeyCode::Char('j') => {
                    move_table(&mut self.wg_state, self.nm_conns.len(), 1);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    move_table(&mut self.wg_state, self.nm_conns.len(), -1);
                }
                KeyCode::Enter | KeyCode::Char(' ') => {
                    if let Some(idx) = self.wg_state.selected()
                        && let Some(conn) = self.nm_conns.get(idx).cloned()
                    {
                        let target_up = !conn.is_active();
                        self.status_msg = match set_connection_state(&conn.name, target_up) {
                            Ok(msg) => format!(
                                "{} -> {} ({msg})",
                                conn.name,
                                if target_up { "UP" } else { "DOWN" }
                            ),
                            Err(e) => format!("nmcli error: {e}"),
                        };
                        self.refresh_all();
                    }
                }
                KeyCode::Char('u') => {
                    if self.active_core() == CoreKind::Shoes {
                        self.status_msg =
                            "shoes auto_route automatically follows the kernel default route."
                                .to_string();
                        return;
                    }
                    let mut ifaces = list_interfaces().unwrap_or_default();
                    ifaces.insert(0, "auto".to_string());
                    if !ifaces.iter().any(|x| x == &self.cfg.wg_lan_connection) {
                        ifaces.push(self.cfg.wg_lan_connection.clone());
                    }
                    self.modal = Modal::SetWan { ifaces, cursor: 0 };
                }
                _ => {}
            },
            Tab::Connections => match key.code {
                KeyCode::Down | KeyCode::Char('j') => {
                    move_table(&mut self.conn_state, self.connections.len(), 1);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    move_table(&mut self.conn_state, self.connections.len(), -1);
                }
                KeyCode::Char('a') => {
                    if let Some(idx) = self.conn_state.selected()
                        && let Some(c) = self.connections.get(idx)
                    {
                        let pname = Path::new(&c.metadata.process_path)
                            .file_name()
                            .and_then(|s| s.to_str())
                            .unwrap_or("")
                            .to_string();
                        self.modal = Modal::AddRule {
                            step: AddRuleStep::Target,
                            kind_idx: 0,
                            value: pname,
                            target_idx: 1,
                            procs: list_process_names(),
                            proc_cursor: 0,
                        };
                    }
                }
                _ => {}
            },
        }
    }

    fn handle_node_search_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.node_filter.clear();
                self.searching_nodes = false;
                self.node_state
                    .select((!self.group_nodes.is_empty()).then_some(0));
                self.status_msg = "Search cleared.".to_string();
            }
            KeyCode::Enter => {
                self.searching_nodes = false;
                self.status_msg = if self.node_filter.is_empty() {
                    "Search closed.".to_string()
                } else {
                    format!("Filter active: '{}' (Esc to clear)", self.node_filter)
                };
            }
            KeyCode::Down => {
                let len = self.filtered_nodes().len();
                move_table(&mut self.node_state, len, 1);
            }
            KeyCode::Up => {
                let len = self.filtered_nodes().len();
                move_table(&mut self.node_state, len, -1);
            }
            KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                let len = self.filtered_nodes().len();
                move_table(&mut self.node_state, len, 1);
            }
            KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                let len = self.filtered_nodes().len();
                move_table(&mut self.node_state, len, -1);
            }
            KeyCode::Backspace => {
                self.node_filter.pop();
                let len = self.filtered_nodes().len();
                self.node_state.select((len > 0).then_some(0));
            }
            KeyCode::Char(c) => {
                self.node_filter.push(c);
                let len = self.filtered_nodes().len();
                self.node_state.select((len > 0).then_some(0));
            }
            _ => {}
        }
    }

    fn handle_modal_key(&mut self, key: KeyEvent) {
        let targets = self.available_targets();
        let mut next_modal = None;
        let mut add_rule_req: Option<(RuleKind, String, String)> = None;
        let mut new_iface: Option<String> = None;

        match &mut self.modal {
            Modal::None => {}
            Modal::SetWan { ifaces, cursor } => match key.code {
                KeyCode::Esc => next_modal = Some(Modal::None),
                KeyCode::Down | KeyCode::Char('j') => {
                    if !ifaces.is_empty() {
                        *cursor = (*cursor + 1) % ifaces.len();
                    }
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    if !ifaces.is_empty() {
                        *cursor = if *cursor == 0 {
                            ifaces.len() - 1
                        } else {
                            *cursor - 1
                        };
                    }
                }
                KeyCode::Enter => {
                    if let Some(sel) = ifaces.get(*cursor) {
                        new_iface = Some(sel.clone());
                    }
                    next_modal = Some(Modal::None);
                }
                _ => {}
            },
            Modal::AddRule {
                step,
                kind_idx,
                value,
                target_idx,
                procs,
                proc_cursor,
            } => match key.code {
                KeyCode::Esc => next_modal = Some(Modal::None),
                KeyCode::Tab => {
                    *step = match step {
                        AddRuleStep::Kind => AddRuleStep::Value,
                        AddRuleStep::Value => AddRuleStep::Target,
                        AddRuleStep::Target => AddRuleStep::Kind,
                    };
                }
                _ => match step {
                    AddRuleStep::Kind => match key.code {
                        KeyCode::Down | KeyCode::Char('j') => {
                            *kind_idx = (*kind_idx + 1) % RuleKind::ALL.len();
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            *kind_idx = if *kind_idx == 0 {
                                RuleKind::ALL.len() - 1
                            } else {
                                *kind_idx - 1
                            };
                        }
                        KeyCode::Enter => *step = AddRuleStep::Value,
                        _ => {}
                    },
                    AddRuleStep::Value => match key.code {
                        KeyCode::Enter => {
                            if !value.trim().is_empty() {
                                *step = AddRuleStep::Target;
                            }
                        }
                        KeyCode::Backspace => {
                            value.pop();
                        }
                        KeyCode::Down if RuleKind::ALL[*kind_idx] == RuleKind::ProcessName => {
                            let filtered: Vec<&String> = procs
                                .iter()
                                .filter(|p| {
                                    value.is_empty()
                                        || p.to_lowercase().contains(&value.to_lowercase())
                                })
                                .collect();
                            if !filtered.is_empty() {
                                *proc_cursor = (*proc_cursor + 1) % filtered.len();
                                value.clone_from(filtered[*proc_cursor]);
                            }
                        }
                        KeyCode::Up if RuleKind::ALL[*kind_idx] == RuleKind::ProcessName => {
                            let filtered: Vec<&String> = procs
                                .iter()
                                .filter(|p| {
                                    value.is_empty()
                                        || p.to_lowercase().contains(&value.to_lowercase())
                                })
                                .collect();
                            if !filtered.is_empty() {
                                *proc_cursor = if *proc_cursor == 0 {
                                    filtered.len() - 1
                                } else {
                                    *proc_cursor - 1
                                };
                                value.clone_from(filtered[*proc_cursor]);
                            }
                        }
                        KeyCode::Char(c) => {
                            value.push(c);
                            *proc_cursor = 0;
                        }
                        _ => {}
                    },
                    AddRuleStep::Target => match key.code {
                        KeyCode::Down | KeyCode::Char('j') => {
                            *target_idx = (*target_idx + 1) % targets.len();
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            *target_idx = if *target_idx == 0 {
                                targets.len() - 1
                            } else {
                                *target_idx - 1
                            };
                        }
                        KeyCode::Enter => {
                            if !value.trim().is_empty() {
                                add_rule_req = Some((
                                    RuleKind::ALL[*kind_idx],
                                    value.clone(),
                                    targets[*target_idx].clone(),
                                ));
                            }
                            next_modal = Some(Modal::None);
                        }
                        _ => {}
                    },
                },
            },
        }

        if let Some(m) = next_modal {
            self.modal = m;
        }
        if let Some((kind, val, target)) = add_rule_req {
            match self.config_doc.as_mut() {
                Some(ConfigDoc::SingBox(cfg)) => {
                    let rule = kind.to_rule_json(&val, &target);
                    if insert_user_rule(cfg, rule).is_ok() {
                        self.save_active_config();
                    }
                }
                Some(ConfigDoc::Shoes(doc)) => match kind.to_shoes_rule_yaml(&val, &target) {
                    Ok(rule) => {
                        if insert_shoes_user_rule(doc, rule).is_ok() {
                            self.save_active_config();
                        }
                    }
                    Err(e) => self.status_msg = format!("Rule not added: {e}"),
                },
                None => self.status_msg = "No config loaded.".to_string(),
            }
        }
        if let Some(iface) = new_iface {
            let mtu = if iface == self.cfg.wg_lan_connection {
                1340
            } else {
                self.cfg.tun_mtu
            };
            if let Some(ConfigDoc::SingBox(cfg)) = self.config_doc.as_mut()
                && set_default_interface(cfg, &iface, mtu).is_ok()
            {
                self.default_interface = iface;
                self.save_active_config();
            }
        }
    }

    fn save_active_config(&mut self) {
        let Some(doc) = &self.config_doc else {
            self.status_msg = "No config loaded.".to_string();
            return;
        };
        match doc {
            ConfigDoc::Shoes(yaml_doc) => {
                match save_or_stage_shoes_config(yaml_doc, &self.cfg.shoes_config_path) {
                    Ok(SaveOutcome::WrittenDirect) => {
                        self.status_msg = format!(
                            "Validated & saved {} (shoes auto-reloads).",
                            self.cfg.shoes_config_path.display()
                        );
                    }
                    Ok(SaveOutcome::Staged { staged }) => {
                        self.status_msg = format!(
                            "Validated & staged -> {} (run0 install -o root -g techpriest -m 0640 {} {})",
                            staged.display(),
                            staged.display(),
                            self.cfg.shoes_config_path.display()
                        );
                    }
                    Err(e) => {
                        self.status_msg = format!("Validation/save failed: {e}");
                    }
                }
            }
            ConfigDoc::SingBox(cfg) => {
                match save_or_stage_config(cfg, &self.cfg.singbox_config_path) {
                    Ok(SaveOutcome::WrittenDirect) => {
                        self.status_msg = format!(
                            "Validated & saved {}. Restart sing-box.service to apply.",
                            self.cfg.singbox_config_path.display()
                        );
                    }
                    Ok(SaveOutcome::Staged { staged }) => {
                        self.status_msg = format!(
                            "Validated & staged -> {} (run0 install + systemctl restart sing-box)",
                            staged.display()
                        );
                    }
                    Err(e) => {
                        self.status_msg = format!("Validation/save failed: {e}");
                    }
                }
            }
        }
    }

    fn sync_subscription_in_tui(&mut self) {
        let Some(url) = self.cfg.subscription_url.clone() else {
            self.status_msg =
                "No subscription_url in ~/.config/sboxtui/config.toml".to_string();
            return;
        };
        match fetch_clash_subscription(&url) {
            Ok(prof) => match self.config_doc.as_mut() {
                Some(ConfigDoc::Shoes(doc)) => {
                    let (tags, chains) = convert_proxies_to_shoes(&prof.proxies);
                    let count = tags.len();
                    if let Err(e) =
                        replace_nodes_in_shoes_config(doc, &self.cfg.default_group, &tags, chains)
                    {
                        self.status_msg = format!("Update nodes failed: {e}");
                        return;
                    }
                    self.save_active_config();
                    self.status_msg = format!("Synced {count} shoes nodes. {}", self.status_msg);
                }
                Some(ConfigDoc::SingBox(cfg)) => {
                    let (tags, outbounds) = convert_proxies_to_singbox(&prof.proxies);
                    let count = tags.len();
                    if let Err(e) = replace_nodes_in_config(
                        cfg,
                        &self.cfg.default_group,
                        &tags,
                        outbounds,
                        &self.cfg.wg_remote_connection,
                    ) {
                        self.status_msg = format!("Update nodes failed: {e}");
                        return;
                    }
                    self.save_active_config();
                    self.status_msg = format!("Synced {count} nodes. {}", self.status_msg);
                }
                None => {
                    self.status_msg = "No config file loaded to sync into.".to_string();
                }
            },
            Err(e) => self.status_msg = format!("Subscription fetch failed: {e}"),
        }
    }
}

fn spawn_poller(
    api: ClashClient,
    default_group: String,
) -> (Sender<bool>, Receiver<RefreshSnapshot>) {
    let (req_tx, req_rx) = mpsc::channel::<bool>();
    let (res_tx, res_rx) = mpsc::channel::<RefreshSnapshot>();

    thread::spawn(move || {
        let mut last_nm = Instant::now() - Duration::from_secs(60);
        while let Ok(mut force_nm) = req_rx.recv() {
            // Drain coalesced triggers
            while let Ok(f) = req_rx.try_recv() {
                force_nm |= f;
            }

            let nm_conns = if force_nm || last_nm.elapsed() >= Duration::from_secs(9) {
                last_nm = Instant::now();
                list_nm_connections().ok()
            } else {
                None
            };

            let engine_version = api
                .get_version()
                .map(|v| v.version)
                .map_err(|e| e.to_string());
            let (proxies, group_nodes, active_node, connections) = if engine_version.is_ok() {
                let (p, gn, an) = match api.get_proxies() {
                    Ok(resp) => {
                        let (gn, an) = resp
                            .proxies
                            .get(&default_group)
                            .map(|g| (Some(g.all.clone()), g.now.clone()))
                            .unwrap_or((None, None));
                        (Some(resp.proxies), gn, an)
                    }
                    Err(_) => (None, None, None),
                };
                let conns = api
                    .get_connections()
                    .ok()
                    .map(|c| (c.connections, c.upload_total, c.download_total));
                (p, gn, an, conns)
            } else {
                (None, None, None, None)
            };

            if res_tx
                .send(RefreshSnapshot {
                    engine_version,
                    proxies,
                    group_nodes,
                    active_node,
                    connections,
                    nm_conns,
                })
                .is_err()
            {
                break;
            }
        }
    });

    (req_tx, res_rx)
}

pub fn run_tui(cfg: AppConfig, api: ClashClient) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let (req_tx, res_rx) = spawn_poller(api.clone(), cfg.default_group.clone());
    let mut app = App::new(cfg, api);
    app.refresh_tx = Some(req_tx.clone());
    // Trigger immediate async load; first frame renders instantaneously without blocking.
    let _ = req_tx.send(true);

    let res = loop {
        while let Ok(snap) = res_rx.try_recv() {
            app.apply_snapshot(snap);
        }
        terminal.draw(|f| draw_ui(f, &mut app))?;
        if app.should_quit {
            break Ok(());
        }
        if event::poll(Duration::from_millis(80))?
            && let Event::Key(k) = event::read()?
        {
            app.handle_key(k);
        }
        if app.last_refresh.elapsed() >= Duration::from_secs(3) {
            app.last_refresh = Instant::now();
            let _ = req_tx.send(false);
        }
    };

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    res
}

fn move_table(state: &mut TableState, len: usize, delta: isize) {
    if len == 0 {
        state.select(None);
        return;
    }
    let cur = state.selected().unwrap_or(0) as isize;
    let next = (cur + delta).clamp(0, len as isize - 1) as usize;
    state.select(Some(next));
}

fn fmt_bytes(b: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    let v = b as f64;
    if v >= GB {
        format!("{:.2} GiB", v / GB)
    } else if v >= MB {
        format!("{:.1} MiB", v / MB)
    } else if v >= KB {
        format!("{:.0} KiB", v / KB)
    } else {
        format!("{b} B")
    }
}

fn draw_ui(f: &mut ratatui::Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(4),
            Constraint::Min(10),
            Constraint::Length(2),
        ])
        .split(f.area());

    let titles: Vec<Line> = Tab::TITLES.iter().map(|t| Line::from(*t)).collect();
    let core = app.active_core();
    let title_text = match core {
        CoreKind::Shoes => " sboxtui — shoes (smoltcp+redirect) & WireGuard Control (AGPL-3.0) ",
        CoreKind::SingBox | CoreKind::Auto => {
            " sboxtui — sing-box (gvisor stack) & WireGuard Control (AGPL-3.0) "
        }
    };
    let tabs = Tabs::new(titles)
        .block(Block::default().borders(Borders::ALL).title(title_text))
        .select(app.tab as usize)
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(tabs, chunks[0]);

    draw_stats_banner(f, app, chunks[1]);

    match app.tab {
        Tab::Nodes => draw_nodes_tab(f, app, chunks[2]),
        Tab::Rules => draw_rules_tab(f, app, chunks[2]),
        Tab::WireGuard => draw_wg_tab(f, app, chunks[2]),
        Tab::Connections => draw_connections_tab(f, app, chunks[2]),
    }

    let help = if app.searching_nodes && app.tab == Tab::Nodes {
        "Search: type words/proto (e.g. 'фин hy2') | [Up/Down] Move | [Enter] Lock Filter | [Esc] Clear"
    } else {
        match app.tab {
            Tab::Nodes => "[1-4/Tab] Tabs | [j/k] Move | [Enter] Select | [/ or f] Live Search | [Esc] Clear | [p] Delay | [s] Sync | [q] Quit",
            Tab::Rules => "[j/k] Move | [a] Add Rule (process/geoip/geosite/cidr) | [d] Delete | [K/J] Priority | [w] Validate & Save | [q] Quit",
            Tab::WireGuard => "[j/k] Move | [Enter/Space] Toggle NM WG/Wi-Fi | [u] Set Uplink | [R] Refresh | [q] Quit",
            Tab::Connections => "[j/k] Move | [a] Add process_name Rule from Selected | [R] Refresh | [q] Quit",
        }
    };
    let footer = Paragraph::new(vec![
        Line::from(Span::styled(
            format!("Status: {}", app.status_msg),
            Style::default().fg(Color::Yellow),
        )),
        Line::from(Span::styled(help, Style::default().fg(Color::DarkGray))),
    ]);
    f.render_widget(footer, chunks[3]);

    draw_modal(f, app);
}

fn format_core_label(engine_version: Option<&str>, core: CoreKind) -> String {
    match engine_version {
        Some(ver) if ver.to_ascii_lowercase().starts_with("shoes") => ver.to_string(),
        Some(ver) if ver.to_ascii_lowercase().starts_with("sing-box") => ver.to_string(),
        Some(ver) => match core {
            CoreKind::Shoes => format!("shoes {ver}"),
            CoreKind::SingBox | CoreKind::Auto => format!("sing-box {ver}"),
        },
        None => match core {
            CoreKind::Shoes => "shoes offline".to_string(),
            CoreKind::SingBox | CoreKind::Auto => "sing-box offline".to_string(),
        },
    }
}

fn draw_stats_banner(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let core = app.active_core();
    let core_label = format_core_label(app.engine_version.as_deref(), core);
    let stack = match core {
        CoreKind::Shoes => "smoltcp+redirect",
        CoreKind::SingBox | CoreKind::Auto => "gvisor",
    };
    let active_node = app.active_node.as_deref().unwrap_or("none");
    let ssid = app.wifi_ssid.as_deref().unwrap_or("disconnected");
    let up = fmt_bytes(app.upload_total);
    let down = fmt_bytes(app.download_total);

    let text = vec![
        Line::from(vec![
            Span::raw("Core: "),
            Span::styled(
                core_label,
                Style::default()
                    .fg(if app.engine_version.is_some() {
                        Color::Green
                    } else {
                        Color::Red
                    })
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                " | Stack: {stack} | Uplink: {} (Wi-Fi: {ssid})",
                app.default_interface
            )),
        ]),
        Line::from(format!(
            "Active Node: {active_node} | Connections: {} | TX/RX: {up} / {down}",
            app.connections.len()
        )),
    ];
    let p = Paragraph::new(text).block(Block::default().borders(Borders::ALL).title(" Telemetry "));
    f.render_widget(p, area);
}

fn draw_nodes_tab(f: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let table_area = if app.searching_nodes {
        let split = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(5)])
            .split(area);
        let search_box = Paragraph::new(format!("> {}_", app.node_filter))
            .style(Style::default().fg(Color::Cyan))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Live Search (e.g. 'фин hy2', 'de vless') — Enter=lock, Esc=clear "),
            );
        f.render_widget(search_box, split[0]);
        split[1]
    } else {
        area
    };

    let active = app.active_node.clone();
    let filtered: Vec<String> = app.filtered_nodes().into_iter().cloned().collect();
    if let Some(sel) = app.node_state.selected()
        && sel >= filtered.len()
    {
        app.node_state.select((!filtered.is_empty()).then_some(0));
    }
    let rows: Vec<Row> = filtered
        .iter()
        .map(|name| {
            let is_active = active.as_deref() == Some(name.as_str());
            let entry = app.proxies.get(name);
            let proto = entry.map(|e| e.proxy_type.as_str()).unwrap_or("-");
            let lat = entry
                .and_then(|e| e.history.last())
                .map(|h| {
                    if h.delay == 0 {
                        "timeout".to_string()
                    } else {
                        format!("{} ms", h.delay)
                    }
                })
                .unwrap_or_else(|| "-".to_string());
            let mark = if is_active { "★" } else { " " };
            let style = if is_active {
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(mark),
                Cell::from(name.clone()),
                Cell::from(proto.to_string()),
                Cell::from(lat),
            ])
            .style(style)
        })
        .collect();

    let title = if app.node_filter.is_empty() {
        format!(" Nodes ({}) ", filtered.len())
    } else {
        format!(
            " Nodes ({}/{}) [filter: {}] ",
            filtered.len(),
            app.group_nodes.len(),
            app.node_filter
        )
    };
    let table = Table::new(
        rows,
        [
            Constraint::Length(3),
            Constraint::Min(30),
            Constraint::Length(12),
            Constraint::Length(10),
        ],
    )
    .header(
        Row::new(["", "Name", "Proto", "Latency"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(Block::default().borders(Borders::ALL).title(title))
    .row_highlight_style(Style::default().bg(Color::DarkGray));
    f.render_stateful_widget(table, table_area, &mut app.node_state);
}

fn draw_rules_tab(f: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let summaries = app
        .config_doc
        .as_ref()
        .map(ConfigDoc::summarize_rules)
        .unwrap_or_default();
    let cfg_path = app.cfg.active_config_path(app.active_core());
    let rows: Vec<Row> = summaries
        .iter()
        .map(|r| {
            let style = if r.is_builtin {
                Style::default().fg(Color::DarkGray)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(format!("{}", r.index + 1)),
                Cell::from(r.matcher.clone()),
                Cell::from(r.target.clone()),
            ])
            .style(style)
        })
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Length(4),
            Constraint::Percentage(72),
            Constraint::Percentage(24),
        ],
    )
    .header(
        Row::new(["#", "Matcher", "Target"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Routing Rules ({}) ", cfg_path.display())),
    )
    .row_highlight_style(Style::default().bg(Color::DarkGray));
    f.render_stateful_widget(table, area, &mut app.rule_state);
}

fn draw_wg_tab(f: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let rows: Vec<Row> = app
        .nm_conns
        .iter()
        .map(|c| {
            let active = c.is_active();
            let style = if active {
                Style::default().fg(Color::Green)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(if active { "UP" } else { "DOWN" }),
                Cell::from(c.name.clone()),
                Cell::from(c.conn_type.clone()),
                Cell::from(c.device.clone()),
            ])
            .style(style)
        })
        .collect();
    let title = format!(
        " NetworkManager WireGuard & Wi-Fi | uplink = {} ",
        app.default_interface
    );
    let table = Table::new(
        rows,
        [
            Constraint::Length(6),
            Constraint::Min(24),
            Constraint::Length(18),
            Constraint::Length(14),
        ],
    )
    .header(
        Row::new(["State", "Connection", "Type", "Device"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(Block::default().borders(Borders::ALL).title(title))
    .row_highlight_style(Style::default().bg(Color::DarkGray));
    f.render_stateful_widget(table, area, &mut app.wg_state);
}

fn draw_connections_tab(f: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let rows: Vec<Row> = app
        .connections
        .iter()
        .map(|c| {
            let proc_name = Path::new(&c.metadata.process_path)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("-")
                .to_string();
            let host = if !c.metadata.host.is_empty() {
                format!("{}:{}", c.metadata.host, c.metadata.destination_port)
            } else {
                format!(
                    "{}:{}",
                    c.metadata.destination_ip, c.metadata.destination_port
                )
            };
            let chain = c.chains.join(" -> ");
            Row::new(vec![
                Cell::from(proc_name),
                Cell::from(host),
                Cell::from(c.rule.clone()),
                Cell::from(chain),
                Cell::from(fmt_bytes(c.upload)),
                Cell::from(fmt_bytes(c.download)),
            ])
        })
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Length(18),
            Constraint::Min(24),
            Constraint::Length(18),
            Constraint::Length(22),
            Constraint::Length(10),
            Constraint::Length(10),
        ],
    )
    .header(
        Row::new(["Process", "Destination", "Rule", "Chain", "TX", "RX"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Live Connections ({}) ", app.connections.len())),
    )
    .row_highlight_style(Style::default().bg(Color::DarkGray));
    f.render_stateful_widget(table, area, &mut app.conn_state);
}

fn draw_modal(f: &mut ratatui::Frame, app: &App) {
    let targets = app.available_targets();
    match &app.modal {
        Modal::None => {}
        Modal::SetWan { ifaces, cursor } => {
            let area = centered_rect(45, 45, f.area());
            f.render_widget(Clear, area);
            let items: Vec<ListItem> = ifaces.iter().map(|i| ListItem::new(i.as_str())).collect();
            let mut st = ListState::default();
            st.select(Some(*cursor));
            let list = List::new(items)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Select sing-box Uplink Interface "),
                )
                .highlight_style(Style::default().bg(Color::Blue));
            f.render_stateful_widget(list, area, &mut st);
        }
        Modal::AddRule {
            step,
            kind_idx,
            value,
            target_idx,
            procs,
            proc_cursor,
        } => {
            let area = centered_rect(65, 60, f.area());
            f.render_widget(Clear, area);
            let kind = RuleKind::ALL[*kind_idx];
            let mut lines = vec![
                Line::from(format!(
                    "Step: {:?} (Tab switches step, Enter confirms, Esc cancels)",
                    step
                )),
                Line::from(""),
                Line::from(Span::styled(
                    format!("1. Kind: {}", kind.label()),
                    if *step == AddRuleStep::Kind {
                        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    },
                )),
                Line::from(Span::styled(
                    format!("2. Value: {value}_"),
                    if *step == AddRuleStep::Value {
                        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    },
                )),
                Line::from(Span::styled(
                    format!("3. Target: {}", targets[*target_idx]),
                    if *step == AddRuleStep::Target {
                        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    },
                )),
                Line::from(""),
            ];
            if *step == AddRuleStep::Value && kind == RuleKind::ProcessName {
                lines.push(Line::from("Matching running processes (Up/Down to pick):"));
                let q = value.to_lowercase();
                for (i, p) in procs
                    .iter()
                    .filter(|p| q.is_empty() || p.to_lowercase().contains(&q))
                    .take(8)
                    .enumerate()
                {
                    let prefix = if i == *proc_cursor { "> " } else { "  " };
                    lines.push(Line::from(format!("{prefix}{p}")));
                }
            } else if *step == AddRuleStep::Kind {
                for (i, k) in RuleKind::ALL.iter().enumerate() {
                    let prefix = if i == *kind_idx { "> " } else { "  " };
                    lines.push(Line::from(format!("{prefix}{}", k.label())));
                }
            } else if *step == AddRuleStep::Target {
                for (i, t) in targets.iter().enumerate() {
                    let prefix = if i == *target_idx { "> " } else { "  " };
                    lines.push(Line::from(format!("{prefix}{t}")));
                }
            }
            let p = Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .block(Block::default().borders(Borders::ALL).title(" Add Routing Rule "));
            f.render_widget(p, area);
        }
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn matches_node_query(name: &str, proto: &str, tokens: &[String]) -> bool {
    if tokens.is_empty() {
        return true;
    }
    let name_l = name.to_lowercase();
    let proto_l = proto.to_lowercase();
    tokens.iter().all(|tok| {
        name_l.contains(tok)
            || proto_l.contains(tok)
            || (tok == "hy2" && proto_l == "hysteria2")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_multi_token_and_protocol_shorthand() {
        let tokens: Vec<String> = "фин hy2".split_whitespace().map(str::to_lowercase).collect();
        assert!(matches_node_query(
            "🇫🇮 🎮 ⚡️ ⭐️ Финляндия #2",
            "hysteria2",
            &tokens
        ));
        assert!(!matches_node_query(
            "🇫🇮 🎮 ⚡️ ⭐️ Финляндия #2",
            "vless",
            &tokens
        ));
        assert_eq!(
            format_core_label(Some("shoes 0.3.8"), CoreKind::Shoes),
            "shoes 0.3.8"
        );
        assert_eq!(
            format_core_label(Some("1.14.4"), CoreKind::SingBox),
            "sing-box 1.14.4"
        );
    }
}
