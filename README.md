# NetGuardia

Inline network security platform built on eBPF/XDP. Combines ONNX-based ML, temporal beaconing, correlation heuristics, and Suricata `eve.json` alerts in one fusion path, drives SOAR playbooks, and writes decisions into a WORM audit chain.

## Stack

- **Data plane** — eBPF / XDP / AF_XDP (aya, xsk-rs)
- **Detection** — Rust + tract-onnx for ML, custom temporal / graph engines, Suricata `eve.json` ingest
- **Control plane** — actix-web REST + WebSocket, SQLite + SQLCipher, argon2 / JWT / CSRF, per-playbook SOAR
- **Frontend** — Vue 3 + Pinia + Vue-i18n (en / zh-TW / zh-CN / ja)
- **Architecture** — hexagonal-ish Rust workspace: `domain/` · `interface/` · `core/` · `adapter/` · `infrastructure/`

## Capabilities

NetGuardia sits inline between network segments, observes traffic, detects threats, and applies policy or automated response from one control plane.

### Traffic Visibility

- Live security overview with threat counts, traffic rate, system health, recent alerts, and SOAR activity.
- Per-IP traffic statistics for bytes, packets, last-seen time, direction, address family, and source/destination views.
- Network and attack maps for geographic flow visualization and attack-source distribution.
- Flow trace recording for offline training, incident review, and audit workflows.

### Threat Detection

- ML-assisted traffic detection using ONNX runtime models and a pipeline adapter.
- Multi-source fusion across ML signals, temporal beaconing, correlation heuristics, and Suricata `eve.json` alerts.
- Alert details with confidence, anomaly score, classifier score, connection metadata, protocol, source, and destination.
- Drift detection and audit events for model behavior changes.
- BYO model upload, validation, promotion, and offline mode for custom pipeline bundles.

### Inline Enforcement

- IPv4 and IPv6 access-control lists with blacklist and whitelist support.
- GeoIP country blocking for region-based policy.
- DNS blacklist filtering for suspicious domains.
- HTTP and SSH protocol/service access rules.
- Packet, SYN, UDP, and DNS rate limits for DDoS-oriented controls.
- Real-time drop monitor for intercepted packet events.

### Automated Response

- SOAR playbooks with triggers, conditions, cooldowns, and response actions.
- Dry-run mode for testing playbook behavior before enabling automation.
- Execution history for automated actions such as IP blocks.
- SOAR whitelist and active auto-block tracking.

### Operations And Administration

- WORM-style audit log with chain verification for administrative and detection events.
- Live log stream with level filtering, search, follow/pause, and archived log download.
- Security report with threat breakdown, SOAR summary, system health, PDF download, and email delivery.
- User, group, RBAC permission, and API key management.
- System health dashboard for CPU, memory, temperature, OS, NIC counters, engine mode, and boot time.
- Runtime settings for general mode, network interfaces, notifications, detection, threat analysis, SOAR, and system integrations.

## Screens

<table>
<tr>
<td><img src=".github/images/ui/overview.png" alt="Security overview"/><br><sub>Security overview with live posture, trends, threats, and SOAR activity</sub></td>
<td><img src=".github/images/ui/statistics.png" alt="Traffic statistics"/><br><sub>Traffic statistics (per-IP bytes/packets)</sub></td>
<td><img src=".github/images/ui/map.png" alt="Network traffic map"/><br><sub>Live geographic flow map</sub></td>
</tr>
<tr>
<td><img src=".github/images/ui/global-attack-map.png" alt="Global attack map"/><br><sub>Global attack-source distribution</sub></td>
<td><img src=".github/images/ui/drop-monitor.png" alt="Drop monitor"/><br><sub>Real-time drop monitor</sub></td>
<td><img src=".github/images/ui/detection.png" alt="Threat detection"/><br><sub>Threat detection alert queue</sub></td>
</tr>
<tr>
<td><img src=".github/images/ui/detection-details.png" alt="Alert details"/><br><sub>Alert details with model scores and connection metadata</sub></td>
<td><img src=".github/images/ui/access-control.png" alt="Access control"/><br><sub>IPv4/IPv6 allow + block lists</sub></td>
<td><img src=".github/images/ui/geoip-block.png" alt="GeoIP block"/><br><sub>GeoIP country block</sub></td>
</tr>
<tr>
<td><img src=".github/images/ui/dns-filter.png" alt="DNS filter"/><br><sub>DNS blacklist</sub></td>
<td><img src=".github/images/ui/rate-limit.png" alt="Rate limit"/><br><sub>Per-class DDoS rate limits</sub></td>
<td><img src=".github/images/ui/protocol-filter.png" alt="Protocol filter"/><br><sub>HTTP / SSH service rules</sub></td>
</tr>
<tr>
<td><img src=".github/images/ui/auto-response.png" alt="SOAR playbooks"/><br><sub>SOAR playbook management and dry-run</sub></td>
<td><img src=".github/images/ui/auto-response-history.png" alt="SOAR execution history"/><br><sub>SOAR execution history</sub></td>
<td><img src=".github/images/ui/auto-response-block-rules.png" alt="SOAR block rules"/><br><sub>SOAR whitelist and active auto-blocks</sub></td>
</tr>
<tr>
<td><img src=".github/images/ui/security-report.png" alt="Security report"/><br><sub>Security report (PDF / email)</sub></td>
<td><img src=".github/images/ui/account-management.png" alt="Accounts"/><br><sub>Users + groups + RBAC</sub></td>
<td><img src=".github/images/ui/group-management.png" alt="Groups"/><br><sub>Built-in and custom permission groups</sub></td>
</tr>
<tr>
<td><img src=".github/images/ui/api-keys.png" alt="API keys"/><br><sub>API keys</sub></td>
<td><img src=".github/images/ui/audit-log.png" alt="Audit log"/><br><sub>WORM-chained audit log</sub></td>
<td><img src=".github/images/ui/logs.png" alt="Logs"/><br><sub>Live + archived logs</sub></td>
</tr>
<tr>
<td><img src=".github/images/ui/system-status.png" alt="System status"/><br><sub>CPU / memory / NIC counters</sub></td>
<td><img src=".github/images/ui/flow-trace.png" alt="Flow trace"/><br><sub>Rotated flow recording</sub></td>
<td><img src=".github/images/ui/system-settings.png" alt="System settings"/><br><sub>Mode / theme / HTTP / engine</sub></td>
</tr>
<tr>
<td><img src=".github/images/ui/system-settings-network.png" alt="Network settings"/><br><sub>Network interfaces, XDP, and pipeline settings</sub></td>
<td><img src=".github/images/ui/system-settings-notifications.png" alt="Notification settings"/><br><sub>SMTP and Telegram notification settings</sub></td>
<td><img src=".github/images/ui/system-settings-detection.png" alt="Detection settings"/><br><sub>ML model status, inference, and BYO upload controls</sub></td>
</tr>
<tr>
<td><img src=".github/images/ui/system-settings-threat-analysis.png" alt="Threat analysis settings"/><br><sub>Beaconing and correlation thresholds</sub></td>
<td><img src=".github/images/ui/system-settings-soar.png" alt="SOAR settings"/><br><sub>SOAR limits, TTL, and DNS action settings</sub></td>
<td><img src=".github/images/ui/system-settings-system.png" alt="System integration settings"/><br><sub>Suricata and GeoIP integration settings</sub></td>
</tr>
</table>
