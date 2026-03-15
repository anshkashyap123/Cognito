# core/threat_intel.py  –  COGNITO XDR v3.0
# Multi-feed threat intelligence with background refresh and disk cache

import requests
import threading
import time
import json
import os

FEED_URLS = [
    ("Feodo Tracker",   "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"),
    ("ipsum",           "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"),
    ("Emerging Threats","https://rules.emergingthreats.net/blockrules/compromised-ips.txt"),
]

CACHE_FILE    = "logs/threat_intel_cache.json"
REFRESH_SEC   = 3600   # 1-hour auto-refresh


class ThreatIntel:

    def __init__(self):
        self._lock        = threading.Lock()
        self.bad_ips      = set()
        self.feed_status  = {}   # feed_name -> {"count": N, "ok": bool, "ts": ts}
        self.last_refresh = 0

        # Load from disk cache first (instant startup)
        self._load_cache()

        # Background network load
        threading.Thread(target=self._background_load, daemon=True).start()

    # ── Loading ───────────────────────────────────────────────────────────────

    def _background_load(self):
        self._fetch_all()
        # Periodic refresh
        while True:
            time.sleep(REFRESH_SEC)
            self._fetch_all()

    def _fetch_all(self):
        new_ips = set()
        for name, url in FEED_URLS:
            ok, ips = self._fetch_one(url)
            with self._lock:
                self.feed_status[name] = {
                    "ok":    ok,
                    "count": len(ips),
                    "ts":    time.strftime("%H:%M"),
                }
            if ok:
                new_ips |= ips
                print(f"[COGNITO] Threat feed '{name}': {len(ips)} IPs")

        if new_ips:
            with self._lock:
                self.bad_ips |= new_ips
                self.last_refresh = time.time()
            self._save_cache()
            print(f"[COGNITO] Threat Intel total: {len(self.bad_ips)} malicious IPs")

    def _fetch_one(self, url: str):
        try:
            r = requests.get(url, timeout=12)
            if r.status_code != 200:
                return False, set()
            ips = set()
            for line in r.text.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    ip = line.split()[0]
                    if self._valid_ip(ip):
                        ips.add(ip)
            return True, ips
        except Exception:
            return False, set()

    def _valid_ip(self, ip: str) -> bool:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    # ── Cache ─────────────────────────────────────────────────────────────────

    def _save_cache(self):
        try:
            os.makedirs("logs", exist_ok=True)
            with self._lock:
                data = list(self.bad_ips)
            with open(CACHE_FILE, "w") as f:
                json.dump({"ts": time.time(), "ips": data}, f)
        except Exception as e:
            print(f"[COGNITO] Cache save error: {e}")

    def _load_cache(self):
        try:
            if not os.path.exists(CACHE_FILE):
                return
            with open(CACHE_FILE) as f:
                data = json.load(f)
            with self._lock:
                self.bad_ips = set(data.get("ips", []))
            print(f"[COGNITO] Cache loaded: {len(self.bad_ips)} IPs")
        except Exception:
            pass

    # ── Public API ────────────────────────────────────────────────────────────

    def check(self, ip: str) -> bool:
        with self._lock:
            return ip in self.bad_ips

    def add(self, ip: str):
        with self._lock:
            self.bad_ips.add(ip)

    def remove(self, ip: str):
        with self._lock:
            self.bad_ips.discard(ip)

    def count(self) -> int:
        with self._lock:
            return len(self.bad_ips)

    def get_feed_status(self):
        with self._lock:
            return dict(self.feed_status)
