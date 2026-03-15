# core/threat_engine.py  –  COGNITO XDR v3.0
# Advanced threat detection: intel, ML, DDoS, port-scan, brute-force, DNS tunneling,
# beaconing, data exfiltration, lateral movement, whitelist/blacklist management

import platform
import subprocess
import time
import json
import os
import threading
import ipaddress
from collections import defaultdict, deque

from core.threat_intel import ThreatIntel
from core.ml_detector   import MLDetector


# ── Severity weights ─────────────────────────────────────────────────────────
SEV_WEIGHTS = {"CRITICAL": 15, "HIGH": 8, "MEDIUM": 4, "LOW": 1}

# ── Detection thresholds ──────────────────────────────────────────────────────
DDOS_PPS_THRESH       = 200    # pkts/s from one IP = DDoS
DDOS_TOTAL_THRESH     = 500    # total packets from one IP
PORTSCAN_THRESH       = 18     # unique dst ports = scan
BRUTE_THRESH          = 30     # repeated auth-port hits
BEACON_WINDOW         = 30     # seconds for beaconing check
BEACON_MIN_HITS       = 8      # minimum hits to suspect beaconing
EXFIL_BYTES_THRESH    = 500_000  # bytes from one IP = exfiltration risk
LATERAL_PORTS         = {135, 445, 3389, 5985, 22}   # lateral movement ports

# ── Auth ports for brute-force detection ────────────────────────────────────
AUTH_PORTS = {21, 22, 23, 25, 110, 143, 445, 3306, 3389, 5432, 5900, 27017}


class ThreatEngine:

    def __init__(self):
        self.intel   = ThreatIntel()
        self.ml      = MLDetector()
        self._lock   = threading.Lock()

        # Per-IP state
        self.packet_count   = defaultdict(int)
        self.bytes_count    = defaultdict(int)
        self.port_scan      = defaultdict(set)
        self.auth_hits      = defaultdict(int)
        self.beacon_times   = defaultdict(lambda: deque(maxlen=100))
        self.lateral_hits   = defaultdict(set)

        # Global state
        self.blocked        = set()          # IPs currently blocked
        self.whitelist      = set()          # Never-block IPs
        self.custom_block   = set()          # Manually added blocks
        self.callbacks      = []

        # Stats
        self.security_score   = 100
        self.total_threats    = 0
        self.total_blocked    = 0
        self.threat_history   = deque(maxlen=500)  # last 500 events
        self.sev_counts       = defaultdict(int)   # by severity
        self.type_counts      = defaultdict(int)   # by threat type

        # Per-second rate tracking for DDoS
        self._ip_pps          = defaultdict(lambda: deque(maxlen=5))
        self._last_tick       = time.time()

        os.makedirs("logs", exist_ok=True)

    # ── Callback management ───────────────────────────────────────────────────

    def add_callback(self, cb):
        self.callbacks.append(cb)

    # ── Main processing ───────────────────────────────────────────────────────

    def process(self, packet: dict):
        ip   = packet.get("src_ip", "0.0.0.0")
        port = packet.get("dst_port", 0)
        size = packet.get("size", 0)

        # Skip whitelisted / private IPs
        if ip in self.whitelist or self._is_private(ip):
            return

        with self._lock:
            already = ip in self.blocked
        if already:
            return

        threat   = None
        severity = "LOW"
        details  = {}

        # ── 1. Threat intelligence check ──────────────────────────────────
        if self.intel.check(ip):
            threat   = "Known Malicious IP"
            severity = "CRITICAL"
            details  = {"source": "Threat Intel Feed"}

        # ── 2. Manual custom block ─────────────────────────────────────────
        elif ip in self.custom_block:
            threat   = "Manually Blocked IP"
            severity = "HIGH"

        # ── 3. ML anomaly detection ────────────────────────────────────────
        elif self.ml.check(packet):
            threat   = "ML Anomaly Detected"
            severity = "HIGH"
            details  = {"score": "anomalous"}

        else:
            with self._lock:
                self.packet_count[ip] += 1
                self.bytes_count[ip]  += size
                self.port_scan[ip].add(port)
                self.beacon_times[ip].append(time.time())

                if port in AUTH_PORTS:
                    self.auth_hits[ip] += 1

                if port in LATERAL_PORTS:
                    self.lateral_hits[ip].add(port)

                cnt         = self.packet_count[ip]
                total_bytes = self.bytes_count[ip]
                unique_ports= len(self.port_scan[ip])
                auth_cnt    = self.auth_hits[ip]
                btimes      = list(self.beacon_times[ip])
                lateral_cnt = len(self.lateral_hits[ip])

            # ── DDoS flood ────────────────────────────────────────────────
            if cnt > DDOS_TOTAL_THRESH:
                threat   = "DDoS Flood"
                severity = "CRITICAL"
                details  = {"packets": cnt}

            # ── Port scan ─────────────────────────────────────────────────
            elif unique_ports > PORTSCAN_THRESH:
                threat   = "Port Scan"
                severity = "HIGH"
                details  = {"unique_ports": unique_ports}

            # ── Brute force ───────────────────────────────────────────────
            elif auth_cnt > BRUTE_THRESH:
                svc = {22: "SSH", 3389: "RDP", 21: "FTP", 23: "Telnet"}.get(port, "Service")
                threat   = f"Brute Force ({svc})"
                severity = "HIGH"
                details  = {"attempts": auth_cnt, "port": port}

            # ── Data exfiltration risk ────────────────────────────────────
            elif total_bytes > EXFIL_BYTES_THRESH:
                threat   = "Data Exfiltration Risk"
                severity = "MEDIUM"
                details  = {"bytes": total_bytes}

            # ── Beaconing / C2 communication ──────────────────────────────
            elif self._detect_beaconing(btimes):
                threat   = "C2 Beaconing"
                severity = "HIGH"
                details  = {"pattern": "regular intervals"}

            # ── Lateral movement ──────────────────────────────────────────
            elif lateral_cnt >= 3:
                threat   = "Lateral Movement"
                severity = "MEDIUM"
                details  = {"admin_ports": lateral_cnt}

        if threat:
            self._handle_threat(ip, threat, severity, packet, details)

    # ── Threat handling ───────────────────────────────────────────────────────

    def _handle_threat(self, ip, threat, severity, packet, details=None):
        with self._lock:
            if ip in self.blocked:
                return
            self.blocked.add(ip)
            self.total_threats  += 1
            self.total_blocked  += 1
            self.sev_counts[severity] += 1
            self.type_counts[threat]  += 1
            pts = SEV_WEIGHTS.get(severity, 1)
            self.security_score = max(0, self.security_score - pts)

        self._block_firewall(ip)

        event = {
            "id":           self.total_threats,
            "time":         time.strftime("%H:%M:%S"),
            "date":         time.strftime("%Y-%m-%d"),
            "ip":           ip,
            "threat":       threat,
            "severity":     severity,
            "protocol":     packet.get("protocol", "N/A"),
            "dst_port":     packet.get("dst_port", 0),
            "service":      packet.get("service", "UNKNOWN"),
            "country_code": packet.get("country_code", "??"),
            "country_name": packet.get("country_name", "Unknown"),
            "size":         packet.get("size", 0),
            "details":      details or {},
            "blocked":      True,
        }

        with self._lock:
            self.threat_history.appendleft(event)

        self._save_log(event)
        print(f"[COGNITO] [{severity}] {threat} ← {ip} ({event['country_name']})")

        for cb in self.callbacks:
            try:
                cb(event)
            except Exception as e:
                print(f"[COGNITO] Callback error: {e}")

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _detect_beaconing(self, times: list) -> bool:
        """Detect regular-interval communication (C2 beaconing)."""
        if len(times) < BEACON_MIN_HITS:
            return False
        now = time.time()
        recent = [t for t in times if now - t < BEACON_WINDOW]
        if len(recent) < BEACON_MIN_HITS:
            return False
        intervals = [recent[i+1] - recent[i] for i in range(len(recent)-1)]
        if not intervals:
            return False
        avg = sum(intervals) / len(intervals)
        if avg < 0.5:
            return False  # Too fast — probably not beaconing
        variance = sum((x - avg) ** 2 for x in intervals) / len(intervals)
        # Low variance = regular intervals = beaconing
        return variance < (avg * 0.3) ** 2

    def _is_private(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def _block_firewall(self, ip: str):
        try:
            sys = platform.system()
            if sys == "Windows":
                cmd = (
                    f'netsh advfirewall firewall add rule '
                    f'name="COGNITO_{ip}" dir=in action=block remoteip={ip}'
                )
                subprocess.run(cmd, shell=True, capture_output=True, timeout=5)
            elif sys in ("Linux", "Darwin"):
                subprocess.run(
                    ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                    capture_output=True, timeout=5
                )
        except Exception as e:
            print(f"[COGNITO] Firewall error for {ip}: {e}")

    def _unblock_firewall(self, ip: str):
        try:
            sys = platform.system()
            if sys == "Windows":
                cmd = f'netsh advfirewall firewall delete rule name="COGNITO_{ip}"'
                subprocess.run(cmd, shell=True, capture_output=True, timeout=5)
            elif sys in ("Linux", "Darwin"):
                subprocess.run(
                    ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                    capture_output=True, timeout=5
                )
        except Exception as e:
            print(f"[COGNITO] Firewall unblock error for {ip}: {e}")

    def _save_log(self, event: dict):
        try:
            with open("logs/threat_log.json", "a") as f:
                json.dump(event, f)
                f.write("\n")
        except Exception as e:
            print(f"[COGNITO] Log error: {e}")

    # ── Public API ────────────────────────────────────────────────────────────

    def manual_block(self, ip: str):
        with self._lock:
            self.custom_block.add(ip)

    def unblock(self, ip: str):
        with self._lock:
            self.blocked.discard(ip)
            self.custom_block.discard(ip)
        self._unblock_firewall(ip)

    def add_whitelist(self, ip: str):
        with self._lock:
            self.whitelist.add(ip)
            self.blocked.discard(ip)

    def remove_whitelist(self, ip: str):
        with self._lock:
            self.whitelist.discard(ip)

    def reset_score(self):
        with self._lock:
            self.security_score = 100

    def get_stats(self):
        with self._lock:
            return {
                "security_score":  self.security_score,
                "total_threats":   self.total_threats,
                "total_blocked":   self.total_blocked,
                "blocked_ips":     list(self.blocked),
                "whitelist":       list(self.whitelist),
                "sev_counts":      dict(self.sev_counts),
                "type_counts":     dict(self.type_counts),
                "threat_history":  list(self.threat_history)[:50],
                "intel_count":     self.intel.count(),
            }
