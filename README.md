# COGNITO XDR v3.0
**Military-Grade Extended Detection & Response — Next Level Edition**

---

## 🚀 Quick Start

### Install dependencies
```bash
pip install -r requirements.txt
```

### Run (Windows — as Administrator for real capture, normal user for demo)
```bat
python cognito_main.py
```

### Run (Linux/macOS — sudo for real capture)
```bash
sudo python cognito_main.py
# Or without sudo (demo mode):
python cognito_main.py
```

> **Demo mode** runs automatically without admin/root privileges — full UI with realistic simulated traffic and attacks.

---

## ✨ What's New in v3.0

### 🛡 Detection Engine (7 threat types)
| Threat Type         | Method              | Severity |
|---------------------|---------------------|----------|
| Known Malicious IP  | Threat Intel Feeds  | CRITICAL |
| DDoS Flood          | Packet rate counter | CRITICAL |
| Port Scan           | Unique port counter | HIGH     |
| Brute Force         | Auth port hit count | HIGH     |
| ML Anomaly          | IsolationForest+LOF | HIGH     |
| C2 Beaconing        | Interval variance   | HIGH     |
| Lateral Movement    | Admin port tracking | MEDIUM   |
| Data Exfiltration   | Byte volume         | MEDIUM   |

### 🧠 ML Detector v2
- **Dual-model ensemble**: IsolationForest + Local Outlier Factor (majority vote)
- **5-feature extraction**: packet size, protocol, port, port risk, time-of-day
- **Auto-retraining** every 300 live packets with bounded sliding window
- **Separate StandardScaler** fitted jointly for both models

### 📡 Threat Intelligence
- 3 live feeds: Feodo Tracker, ipsum, Emerging Threats
- Background loading + disk cache for instant startup
- Auto-refresh every 60 minutes
- Feed status visible in sidebar

### 📊 7-Page Premium Dashboard
0. **Dashboard** — Live stats, score ring, dual-axis graph, protocol donut, activity timeline
1. **Threats** — Full table with search/filter/sort, export to JSON
2. **Blocked IPs** — Unblock individual/all, manual block dialog, whitelist manager
3. **Analytics** — Top IPs, ports, countries, threat type distribution
4. **System** — CPU/RAM/disk/network monitoring with live graphs
5. **Logs** — Rich HTML threat log, save to file, reload from disk
6. **Settings** — Adjustable thresholds, runtime toggles, danger zone

### 🎨 Premium Theme
- Deep navy cyberpunk palette with electric cyan accent
- Animated blinking status dot
- Security Score ring widget with arc rendering
- Stacked severity bar charts
- Dual-axis matplotlib live graph (pkt/s + KB/s)
- Protocol donut chart
- Threat timeline stacked bar chart
- Smooth progress bars with gradient fill
- Custom scrollbar styling throughout

### 🖥 Cross-Platform
| Feature           | Windows        | Linux           | macOS      |
|-------------------|----------------|-----------------|------------|
| Real packet capture | ✅ netsh       | ✅ iptables     | ✅ pfctl   |
| Firewall blocking | ✅ netsh       | ✅ iptables     | ✅ pfctl   |
| Demo simulation   | ✅             | ✅              | ✅         |
| System monitor    | ✅ psutil      | ✅ psutil       | ✅ psutil  |

---

## 📁 Project Structure
```
cognito_main.py           Entry point + splash screen + dependency check
requirements.txt          All Python dependencies
core/
  cognito_sniffer.py      Packet capture + rich demo simulation
  threat_engine.py        8-type threat detection engine
  ml_detector.py          IsolationForest + LOF ensemble
  threat_intel.py         3-feed intel with cache + auto-refresh
  firewall.py             Cross-platform IP blocking (Windows/Linux/macOS)
  system_monitor.py       CPU / RAM / disk / network via psutil
gui/
  cognito_dashboard.py    7-page premium dashboard
  graph_widget.py         5 matplotlib chart widgets
  theme.py                Global color palette + stylesheet helpers
logs/
  threat_log.json         Append-only threat events (JSON-lines)
  threat_intel_cache.json Cached malicious IP list
  cognito_session.log     Session log export
```

---

## ⚙ Configuration
All detection thresholds are adjustable live from the **Settings** page:
- DDoS threshold (default: 500 packets/IP)
- Port scan threshold (default: 18 unique ports)
- Brute force threshold (default: 30 attempts)

---

## 🔒 Permissions
| Mode           | Windows       | Linux/macOS  |
|----------------|---------------|--------------|
| Demo / UI only | Normal user   | Normal user  |
| Real capture   | Administrator | root / sudo  |
| Firewall block | Administrator | root / sudo  |

Without elevated permissions COGNITO automatically falls back to demo simulation mode — the full UI works including threat detection, ML, scoring, and all pages.

---

## 📦 Requirements
```
PyQt5>=5.15
matplotlib>=3.5
scikit-learn>=1.0
numpy>=1.21
requests>=2.26
scapy>=2.4.5
psutil>=5.9
```
