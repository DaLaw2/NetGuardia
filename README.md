# NetGuardia

Inline network security platform built on eBPF/XDP. Runs four independent detectors (per-packet ML, temporal beaconing, graph correlation, Suricata) over the same data plane, fuses their verdicts, drives SOAR playbooks, and writes every decision into a WORM audit chain.

## Stack

- **Data plane** — eBPF / XDP / AF_XDP (aya, xsk-rs)
- **Detection** — Rust + tract-onnx for ML, custom temporal / graph engines, Suricata `eve.json` ingest
- **Control plane** — actix-web REST + WebSocket, SQLite + SQLCipher, argon2 / JWT / CSRF, per-playbook SOAR
- **Frontend** — Vue 3 + Pinia + Vue-i18n (en / zh-TW / zh-CN / ja)
- **Architecture** — hexagonal: `adapter/` · `core/` · `infrastructure/` · `interface/` · `model/`

## Screens

<table>
<tr>
<td><img src=".github/images/ui/statistics.png" alt="Traffic statistics"/><br><sub>Traffic statistics (per-IP bytes/packets)</sub></td>
<td><img src=".github/images/ui/map.png" alt="Geo map"/><br><sub>Live geographic flow map</sub></td>
<td><img src=".github/images/ui/drop-monitor.png" alt="Drop monitor"/><br><sub>Real-time drop monitor</sub></td>
</tr>
<tr>
<td><img src=".github/images/ui/detection.png" alt="Threat detection"/><br><sub>Fused threat detection + ML status</sub></td>
<td><img src=".github/images/ui/access-control.png" alt="Access control"/><br><sub>IPv4/IPv6 allow + block lists</sub></td>
<td><img src=".github/images/ui/geoip-block.png" alt="GeoIP block"/><br><sub>GeoIP country block</sub></td>
</tr>
<tr>
<td><img src=".github/images/ui/dns-filter.png" alt="DNS filter"/><br><sub>DNS blacklist</sub></td>
<td><img src=".github/images/ui/rate-limit.png" alt="Rate limit"/><br><sub>Per-class DDoS rate limits</sub></td>
<td><img src=".github/images/ui/protocol-filter.png" alt="Protocol filter"/><br><sub>HTTP / SSH service rules</sub></td>
</tr>
<tr>
<td><img src=".github/images/ui/auto-response.png" alt="SOAR"/><br><sub>SOAR playbooks + dry-run</sub></td>
<td><img src=".github/images/ui/security-report.png" alt="Security report"/><br><sub>Security report (PDF / email)</sub></td>
<td><img src=".github/images/ui/audit-log.png" alt="Audit log"/><br><sub>WORM-chained audit log</sub></td>
</tr>
<tr>
<td><img src=".github/images/ui/account-management.png" alt="Accounts"/><br><sub>Users + groups + RBAC</sub></td>
<td><img src=".github/images/ui/api-keys.png" alt="API keys"/><br><sub>API keys</sub></td>
<td><img src=".github/images/ui/flow-trace.png" alt="Flow trace"/><br><sub>Rotated flow recording</sub></td>
</tr>
<tr>
<td><img src=".github/images/ui/logs.png" alt="Logs"/><br><sub>Live + archived logs</sub></td>
<td><img src=".github/images/ui/system-status.png" alt="System status"/><br><sub>CPU / memory / NIC counters</sub></td>
<td><img src=".github/images/ui/system-settings.png" alt="System settings"/><br><sub>Mode / theme / HTTP / engine</sub></td>
</tr>
</table>

## Architecture

![NetGuardia architecture](.github/images/architecture.png)

## Requirements

Linux kernel with eBPF **and** a NIC driver that implements AF_XDP on that kernel. No single "minimum kernel" — it depends on the NIC.

| Driver | NIC family | Min kernel for AF_XDP |
|---|---|---|
| `mlx5` | Mellanox ConnectX-4/5/6/7 | 5.x |
| `ixgbe` | Intel 82599, X520, X540, X550 | 5.x |
| `i40e` | Intel X710, XL710, XXV710 | 5.x |
| `ice` | Intel E810 | 5.5+ |
| `igb` | Intel i350 T2 (reference HW) | **6.17** |
| `igc` | Intel I225/I226 | 6.x |
| `virtio_net` | QEMU/KVM | varies |

Check with `ethtool -i <iface>` before deploying. 8 GB RAM minimum, 16 GB+ for high-traffic.

## Build

```sh
cargo build --release --package net-guardia
sudo ./target/release/net-guardia
# open http://<host>:8080 — setup wizard issues the admin password on first boot
```

Systemd unit: [`deploy/netguardia.service`](deploy/netguardia.service).
