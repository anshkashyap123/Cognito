# core/cognito_sniffer.py  –  COGNITO XDR v3.0
# Advanced packet sniffer with real capture + rich demo simulation

import threading
import time
import random
import socket
from collections import defaultdict, deque

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[COGNITO] Scapy not available — demo simulation active")


# ── Well-known port service map ───────────────────────────────────────────────
SERVICE_MAP = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    143: "IMAP", 161: "SNMP", 194: "IRC", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-ALT", 8443: "HTTPS-ALT", 27017: "MongoDB",
}

# ── Simulated realistic IP sets ───────────────────────────────────────────────
NORMAL_IPS = [f"192.168.1.{i}" for i in range(2, 30)] + \
             [f"10.0.0.{i}" for i in range(1, 20)]

SUSPICIOUS_IPS = [
    "185.220.101.45", "45.142.212.100", "91.108.4.0",
    "194.165.16.76", "198.54.117.197", "89.234.157.254",
    "5.188.62.214",  "222.186.175.0",  "103.75.190.100",
    "1.34.23.100",   "77.83.36.215",   "193.32.162.50",
]

COUNTRIES = [
    ("US", "United States"), ("CN", "China"), ("RU", "Russia"),
    ("DE", "Germany"), ("FR", "France"), ("BR", "Brazil"),
    ("IN", "India"), ("KR", "South Korea"), ("UA", "Ukraine"),
    ("NL", "Netherlands"), ("GB", "United Kingdom"), ("IR", "Iran"),
]


def _rand_ip():
    return f"{random.randint(1,223)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"


class CognitoSniffer:

    def __init__(self):
        self.running          = False
        self.packet_count     = 0
        self.bytes_total      = 0
        self.packet_rate      = 0
        self.bytes_rate       = 0   # bytes/sec
        self.callbacks        = []
        self._lock            = threading.Lock()

        # Rolling 60-second history
        self.rate_history     = deque([0] * 60, maxlen=60)
        self.bytes_history    = deque([0] * 60, maxlen=60)

        # Protocol & port breakdown
        self.proto_counts     = defaultdict(int)   # {"TCP": N, "UDP": N, ...}
        self.port_counts      = defaultdict(int)   # {443: N, 80: N, ...}
        self.src_ip_counts    = defaultdict(int)   # {ip: count}
        self.country_counts   = defaultdict(int)   # {"CN": N, ...}

        # Bandwidth tracking
        self._last_count      = 0
        self._last_bytes      = 0
        self._last_time       = time.time()

        # Connection tracking
        self.active_conns     = 0
        self._conn_set        = set()

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def add_callback(self, cb):
        self.callbacks.append(cb)

    def start(self):
        if self.running:
            return
        self.running = True
        if SCAPY_AVAILABLE:
            threading.Thread(target=self._sniff_real, daemon=True).start()
        else:
            threading.Thread(target=self._simulate, daemon=True).start()
        threading.Thread(target=self._rate_monitor, daemon=True).start()
        print("[COGNITO] Sniffer v3.0 started")

    def stop(self):
        self.running = False
        print("[COGNITO] Sniffer stopped")

    # ── Real capture ──────────────────────────────────────────────────────────

    def _sniff_real(self):
        try:
            sniff(prn=self._process_scapy,
                  store=False,
                  stop_filter=lambda _: not self.running)
        except Exception as e:
            print(f"[COGNITO] Capture error (admin needed): {e}")
            self._simulate()

    def _process_scapy(self, pkt):
        if not pkt.haslayer(IP):
            return
        proto    = "OTHER"
        dst_port = 0
        src_port = 0
        flags    = ""
        if pkt.haslayer(TCP):
            proto    = "TCP"
            dst_port = pkt[TCP].dport
            src_port = pkt[TCP].sport
            flags    = str(pkt[TCP].flags)
        elif pkt.haslayer(UDP):
            proto    = "UDP"
            dst_port = pkt[UDP].dport
            src_port = pkt[UDP].sport
        elif pkt.haslayer(ICMP):
            proto    = "ICMP"
        elif pkt.haslayer(ARP):
            proto    = "ARP"

        country_code, country_name = self._fake_geo(pkt[IP].src)

        info = {
            "src_ip":       pkt[IP].src,
            "dst_ip":       pkt[IP].dst,
            "src_port":     src_port,
            "dst_port":     dst_port,
            "protocol":     proto,
            "flags":        flags,
            "size":         len(pkt),
            "service":      SERVICE_MAP.get(dst_port, "UNKNOWN"),
            "country_code": country_code,
            "country_name": country_name,
            "time":         time.time(),
            "timestamp":    time.strftime("%H:%M:%S"),
        }
        self._ingest(info)

    # ── Demo simulation ───────────────────────────────────────────────────────

    def _simulate(self):
        """Rich simulation: realistic traffic + periodic attack bursts."""
        tick = 0
        while self.running:
            tick += 1
            burst = (tick % 80 < 5)   # burst attack every ~80s for 5s

            # Pick source IP
            if burst:
                src_ip = random.choice(SUSPICIOUS_IPS)
            else:
                src_ip = random.choice(NORMAL_IPS + [_rand_ip()])

            # Protocol weights: TCP 60%, UDP 28%, ICMP 8%, OTHER 4%
            proto = random.choices(
                ["TCP", "UDP", "ICMP", "OTHER"],
                weights=[60, 28, 8, 4]
            )[0]

            dst_port = random.choices(
                list(SERVICE_MAP.keys()) + [random.randint(1025, 65535)],
                weights=[1] * len(SERVICE_MAP) + [len(SERVICE_MAP)]
            )[0]

            src_port = random.randint(1024, 65535)
            size     = random.randint(40, 1500)
            flags    = random.choice(["S", "SA", "A", "F", "R", "PA"]) if proto == "TCP" else ""

            # Simulate port scan behaviour occasionally
            if burst and random.random() < 0.4:
                dst_port = random.randint(1, 1024)

            country_code, country_name = self._fake_geo(src_ip)

            info = {
                "src_ip":       src_ip,
                "dst_ip":       "192.168.1.1",
                "src_port":     src_port,
                "dst_port":     dst_port,
                "protocol":     proto,
                "flags":        flags,
                "size":         size,
                "service":      SERVICE_MAP.get(dst_port, "UNKNOWN"),
                "country_code": country_code,
                "country_name": country_name,
                "time":         time.time(),
                "timestamp":    time.strftime("%H:%M:%S"),
            }
            self._ingest(info)

            sleep = random.uniform(0.005, 0.06) if burst else random.uniform(0.015, 0.08)
            time.sleep(sleep)

    def _fake_geo(self, ip: str):
        """Assign a deterministic but fake country based on IP hash."""
        idx = sum(int(x) for x in ip.split(".") if x.isdigit()) % len(COUNTRIES)
        return COUNTRIES[idx]

    # ── Ingestion & stats ─────────────────────────────────────────────────────

    def _ingest(self, info: dict):
        with self._lock:
            self.packet_count        += 1
            self.bytes_total         += info["size"]
            self.proto_counts[info["protocol"]] += 1
            self.port_counts[info["dst_port"]]  += 1
            self.src_ip_counts[info["src_ip"]]  += 1
            self.country_counts[info["country_code"]] += 1

            # Connection tracking (5-tuple hash)
            conn = (info["src_ip"], info["dst_ip"], info["src_port"], info["dst_port"], info["protocol"])
            self._conn_set.add(conn)
            self.active_conns = len(self._conn_set)

        for cb in self.callbacks:
            try:
                cb(info)
            except Exception as e:
                print(f"[COGNITO] Sniffer callback error: {e}")

    def _rate_monitor(self):
        while self.running:
            time.sleep(1)
            now = time.time()
            with self._lock:
                cnt   = self.packet_count
                byt   = self.bytes_total
                dt    = now - self._last_time

            self.packet_rate = int((cnt - self._last_count) / max(dt, 0.001))
            self.bytes_rate  = int((byt - self._last_bytes) / max(dt, 0.001))
            self.rate_history.append(self.packet_rate)
            self.bytes_history.append(self.bytes_rate)

            self._last_count = cnt
            self._last_bytes = byt
            self._last_time  = now

    # ── Public getters ────────────────────────────────────────────────────────

    def get_stats(self):
        with self._lock:
            return {
                "status":        "RUNNING" if self.running else "STOPPED",
                "packets":       self.packet_count,
                "bytes_total":   self.bytes_total,
                "rate":          self.packet_rate,
                "bytes_rate":    self.bytes_rate,
                "active_conns":  self.active_conns,
                "rate_history":  list(self.rate_history),
                "bytes_history": list(self.bytes_history),
                "proto_counts":  dict(self.proto_counts),
                "top_ports":     sorted(self.port_counts.items(), key=lambda x: x[1], reverse=True)[:10],
                "top_ips":       sorted(self.src_ip_counts.items(), key=lambda x: x[1], reverse=True)[:10],
                "country_counts":dict(self.country_counts),
            }

    @staticmethod
    def format_bytes(b: int) -> str:
        for unit in ("B", "KB", "MB", "GB"):
            if b < 1024:
                return f"{b:.1f} {unit}"
            b /= 1024
        return f"{b:.1f} TB"
