<div align="center">

```
 ██████╗ ██████╗  ██████╗ ███╗   ██╗██╗████████╗ ██████╗ 
██╔════╝██╔═══██╗██╔════╝ ████╗  ██║██║╚══██╔══╝██╔═══██╗
██║     ██║   ██║██║  ███╗██╔██╗ ██║██║   ██║   ██║   ██║
██║     ██║   ██║██║   ██║██║╚██╗██║██║   ██║   ██║   ██║
╚██████╗╚██████╔╝╚██████╔╝██║ ╚████║██║   ██║   ╚██████╔╝
 ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═╝   ╚═╝    ╚═════╝ 
```

**Military-Grade Extended Detection & Response — v1.0**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)](https://www.python.org/)
[![PyQt5](https://img.shields.io/badge/GUI-PyQt5-41CD52?style=flat-square&logo=qt)](https://riverbankcomputing.com/software/pyqt/)
[![scikit-learn](https://img.shields.io/badge/ML-scikit--learn-F7931E?style=flat-square&logo=scikit-learn)](https://scikit-learn.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey?style=flat-square)]()
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)]()
[![Status](https://img.shields.io/badge/Status-Alpha%20Build-orange?style=flat-square)]()

*Real-time network threat detection powered by ML anomaly analysis, live packet sniffing, and cross-platform firewall enforcement.*

</div>

---

## Overview

**COGNITO** is an open-source Extended Detection and Response (XDR) platform built in Python. It monitors live network traffic, detects anomalies using a machine learning ensemble (Isolation Forest + Local Outlier Factor), cross-references IPs against real-world threat intelligence feeds, and automatically blocks malicious actors at the OS firewall level — all from a sleek dark-mode GUI dashboard.

Designed for security researchers, homelab enthusiasts, and network administrators who want actionable threat visibility without enterprise-level complexity.

---

## Screenshots

| Dashboard | Threat Events |
|-----------|---------------|
| ![Dashboard](assets/screenshots/dashboard) | ![Threats](assets/screenshots/threats) |

| Blocked IPs | Traffic Analytics |
|-------------|------------------|
| ![Blocked](assets/screenshots/blocked_ips) | ![Analytics](assets/screenshots/analytics) |

| System Monitor | Threat Logs |
|---------------|-------------|
| ![System](assets/screenshots/system_monitor) | ![Logs](assets/screenshots/logs) |

| Settings |
|----------|
| ![Settings](assets/screenshots/settings) |

---

## Features

### 🔍 Real-Time Detection Engine
- **Live packet sniffing** via Scapy with automatic fallback to demo simulation mode
- **DDoS detection** — per-IP packet rate and total volume thresholds
- **Port scan detection** — tracks unique destination ports per source IP
- **Brute-force detection** — monitors repeated hits on auth ports (SSH, RDP, FTP, etc.)
- **DNS tunneling detection** — flags suspiciously long or high-frequency DNS queries
- **Beaconing detection** — identifies C2 callback patterns using time-windowed regularity analysis
- **Data exfiltration detection** — alerts on excessive outbound byte volume per IP
- **Lateral movement detection** — watches for internal scanning of SMB, RDP, WinRM, and SSH ports

### 🤖 ML Anomaly Detection
- **Ensemble model**: Isolation Forest + Local Outlier Factor vote-based scoring
- **Feature vector**: packet size, protocol, destination port, port risk score, and time-of-day
- **Continuous retraining** on clean traffic for adaptive baselines
- Operates fully offline — no cloud dependency

### 🌐 Threat Intelligence
- Aggregates **3 live blocklists**: Feodo Tracker, ipsum, and Emerging Threats
- Loads **700,000+ known malicious IPs** on startup from disk cache
- Background refresh every hour with JSON cache persistence
- Instant IP reputation lookup on every captured packet

### 🔥 Cross-Platform Firewall
- **Linux**: `iptables -I INPUT -s <ip> -j DROP`
- **Windows**: `netsh advfirewall` rule injection
- **macOS**: `pfctl` integration
- One-click block/unblock from the GUI, with whitelist (trusted IP) support

### 📊 Dashboard & GUI
- **Network Overview**: live status bar — packets, bandwidth, threats, blocked IPs, active connections
- **Security Score**: 0–100 composite score degraded by threat severity weights
- **Protocol Breakdown**: real-time donut chart (TCP / UDP / ICMP / ARP)
- **Live Packet Rate**: dual-axis time-series chart (pkt/s + KB/s)
- **Threat Activity Timeline**: bar chart of threats over time
- **Traffic Analytics**: top source IPs, top destination ports, top countries, threat type distribution
- **System Monitor**: CPU, RAM, disk, network I/O with 60-second rolling history chart
- **ML Detector Status**: live model health, check count, anomaly count, retrain counter
- **Threat Log**: timestamped event stream with save/load to JSON

---

## Architecture

```
cognito_main.py          ← Entry point, splash screen, dependency checks
│
├── gui/
│   ├── cognito_dashboard.py   ← Main PyQt5 window, all UI views
│   ├── graph_widget.py        ← Custom pyqtgraph / matplotlib widgets
│   └── theme.py               ← Global dark-mode color constants
│
├── core/
│   ├── cognito_sniffer.py     ← Scapy packet capture + demo simulation
│   ├── threat_engine.py       ← Detection rules: DDoS, scan, brute, beacon, exfil, lateral
│   ├── ml_detector.py         ← IsolationForest + LOF ensemble anomaly scorer
│   ├── threat_intel.py        ← Multi-feed IP blocklist aggregator with caching
│   ├── firewall.py            ← Cross-platform block/unblock via OS firewall
│   └── system_monitor.py      ← psutil CPU / RAM / disk / network I/O polling
│
└── logs/
    ├── threat_log.json        ← Persistent threat event log
    └── threat_intel_cache.json ← Cached threat intelligence IP sets
```

---

## Requirements

| Dependency | Purpose |
|---|---|
| `PyQt5 >= 5.15` | GUI framework |
| `pyqtgraph >= 0.13` | Live graph widgets |
| `matplotlib >= 3.5` | Chart rendering |
| `scikit-learn >= 1.0` | ML anomaly detection |
| `numpy >= 1.21` | Numerical feature processing |
| `scapy >= 2.4.5` | Packet capture |
| `psutil >= 5.9` | System resource monitoring |
| `requests >= 2.26` | Threat intelligence feed fetching |
| `geoip2 >= 4.6` | IP geolocation |
| `maxminddb >= 2.2` | MaxMind DB reader |
| `colorama >= 0.4` | Terminal color output |

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/COGNITO.git
cd COGNITO
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run COGNITO

Live capture mode requires root/admin privileges for raw socket access:

```bash
# Linux / macOS
sudo python3 cognito_main.py

# Windows (run as Administrator)
python cognito_main.py
```

**No root? No problem.** COGNITO automatically detects missing privileges and launches in **Demo Mode** — full GUI with realistic simulated traffic, ML detection, and all features active.

---

## Usage

### Starting Protection

1. Launch COGNITO — the dashboard opens in **IDLE** state
2. Click **START PROTECTION** in the top-right of the dashboard
3. Status changes to **RUNNING** — live packet capture begins
4. Threats are detected, logged, and blocked automatically if auto-block is enabled

### Detection Thresholds (Settings)

| Parameter | Default | Description |
|---|---|---|
| DDoS Threshold | 500 packets/IP | Total packets before an IP is flagged as DDoS |
| Port Scan Threshold | 18 unique ports | Unique destination ports before flagging a scan |
| Brute Force Threshold | 30 attempts | Auth-port hits before flagging brute force |

Thresholds are adjustable live from **Settings → Detection Thresholds → Apply**.

### Runtime Options

- **Auto-block on CRITICAL threats** — automatically calls `block_ip()` for critical severity events
- **Enable ML anomaly detection** — toggle the IsolationForest + LOF ensemble
- **Enable threat intelligence feeds** — cross-reference every IP against blocklists
- **Enable system monitor** — activate CPU/RAM/disk telemetry panel

### Whitelist / Trusted IPs

Navigate to **Blocked IPs** and use the **Whitelist** panel on the right to add trusted IPs that should never be blocked (e.g. your router, local servers).

---

## Demo Mode

If Scapy is unavailable or COGNITO is run without root, it enters **Demo Mode** automatically:

- Realistic synthetic traffic is generated using common IP ranges and protocols
- ML detection, threat scoring, IP blocking, and all UI features remain fully functional
- Ideal for testing, development, or showcasing without network access

---

## Security Score

The security score (0–100) is computed in real time:

```
score = max(0, 100 − Σ(threat_count × severity_weight))

Severity weights:
  CRITICAL → 15 pts
  HIGH     →  8 pts
  MEDIUM   →  4 pts
  LOW      →  1 pt
```

A score of **100** means no active threats. As threats are detected, the score degrades. Blocking threats and clearing logs restores the score.

---

## Threat Intelligence Feeds

COGNITO aggregates the following open-source blocklists on startup:

| Feed | Source |
|---|---|
| Feodo Tracker | `feodotracker.abuse.ch` — banking trojan / botnet C2 IPs |
| ipsum | `github.com/stamparm/ipsum` — crowd-sourced malicious IPs |
| Emerging Threats | `rules.emergingthreats.net` — compromised host IPs |

Feeds are cached to `logs/threat_intel_cache.json` and refreshed every hour in the background.

---

## Contributors

Thanks to the following people who have contributed to this project:

| Name | Role |
|---|---|
| **Ansh** | Contributor |
| **Hridyanshu Khattar** | Contributor |
| **Prateek Singh** | Contributor |

---

## Contributing

Contributions are welcome. To get started:

```bash
git checkout -b feature/your-feature-name
# make your changes
git commit -m "feat: describe your change"
git push origin feature/your-feature-name
```

Then open a Pull Request. Please follow existing code style and add comments for any new detection logic.

---

## Roadmap

- [ ] GeoIP map visualization (country-level threat heatmap)
- [ ] PCAP export / import for offline analysis
- [ ] Custom detection rule editor (YAML-based)
- [ ] Email / webhook alerting for critical threats
- [ ] Suricata / Zeek log ingestion
- [ ] Docker container support
- [ ] Windows tray icon & background service mode

---

## Disclaimer

COGNITO is intended for **authorized use only** on networks and systems you own or have explicit permission to monitor. The firewall blocking feature modifies OS-level firewall rules. Use responsibly.

The authors are not responsible for any misuse, damage, or unintended consequences arising from the use of this software.

---

## License

This project is licensed under the [MIT License](LICENSE).

---

<div align="center">

Built with Python, PyQt5, scikit-learn, and Scapy.

**COGNITO XDR v1.0 — Alpha Build**

</div>
