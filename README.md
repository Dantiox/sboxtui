# sboxtui

Energy-efficient Rust TUI network manager for **[sing-box](https://sing-box.sagernet.org/)** (`stack: system`, zero WebKitGTK), **Clash YAML subscriptions** (`VLESS` + Reality, `Hysteria2`), and **NetworkManager WireGuard** tunnels.

## Why?

GUI Clash wrappers (Electron / Tauri / WebKitGTK) plus userspace `gvisor` TCP/IP stacks burn significant laptop battery through constant UI WebView rendering, packet-copy overhead, and periodic health-check wakeups across hundreds of nodes.

`sboxtui` replaces that stack while staying 100% compatible with hardened Linux kernels (`lockdown=confidentiality`, `SELinux Enforcing`):
- **Headless `sing-box` with `stack: system`**: uses the host Linux TCP/IP stack instead of `gvisor`, with `0 MB` GUI WebView overhead.
- **Zero background probe storms**: uses a `selector` outbound by default; latency tests run only when you request them in the TUI.
- **Clash API control plane**: switches nodes, probes latency, inspects live connections, and tracks memory/traffic without root privileges.
- **Interactive Routing Rules**: add/delete/reorder rules by **process name (`process_name`)** (with live `/proc` process picker), **GeoIP / GeoSite (`.srs`)**, **domain suffix**, or **IP/CIDR**, targeting `proxy`, `direct`, `wg_mw` (or any WireGuard `bind_interface`), or `reject`.
- **NetworkManager WireGuard & Uplink control**: toggle `wg_mw` / `wg-lan` via `nmcli` and switch `sing-box`'s `default_interface` / `tun.mtu` for layered topologies (e.g., WireGuard-to-router over WPA3-Enterprise).

## Quick Start

```bash
cargo build --release
./target/release/sboxtui init-config
# Edit ~/.config/sboxtui/config.toml (see config.example.toml)
./target/release/sboxtui sync
./target/release/sboxtui
```

## Security & Secrets Hygiene

Never commit `~/.config/sboxtui/config.toml`, `/etc/sing-box/config.json`, or `/etc/sing-box/api.secret`. All runtime secrets are excluded via `.gitignore`.

## License

Licensed under **GNU AGPL v3.0** — see [LICENSE](file:///home/techpriest/Projects/sboxtui/LICENSE).
