# core/system_monitor.py  –  COGNITO XDR v3.0
# Real-time system resource monitoring (CPU, RAM, disk, network interfaces)

import threading
import time
from collections import deque

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False
    print("[COGNITO] psutil not available — system monitor in stub mode")


class SystemMonitor:

    def __init__(self):
        self._lock      = threading.Lock()
        self.enabled    = PSUTIL_OK
        self.running    = False

        # Rolling 60-second histories
        self.cpu_history  = deque([0.0] * 60, maxlen=60)
        self.ram_history  = deque([0.0] * 60, maxlen=60)
        self.net_sent_hist= deque([0]   * 60, maxlen=60)
        self.net_recv_hist= deque([0]   * 60, maxlen=60)

        self._prev_net    = None

        # Current values
        self.cpu_pct      = 0.0
        self.ram_pct      = 0.0
        self.ram_used_gb  = 0.0
        self.ram_total_gb = 0.0
        self.disk_pct     = 0.0
        self.net_sent_bps = 0
        self.net_recv_bps = 0
        self.net_ifaces   = []

    def start(self):
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()

    def stop(self):
        self.running = False

    def _loop(self):
        while self.running:
            self._collect()
            time.sleep(1)

    def _collect(self):
        if not PSUTIL_OK:
            # Stub random data
            import random
            with self._lock:
                self.cpu_pct = random.uniform(5, 45)
                self.ram_pct = random.uniform(30, 70)
                self.cpu_history.append(self.cpu_pct)
                self.ram_history.append(self.ram_pct)
            return

        try:
            cpu  = psutil.cpu_percent(interval=None)
            mem  = psutil.virtual_memory()
            disk = psutil.disk_usage("/")
            net  = psutil.net_io_counters()

            sent_bps = 0
            recv_bps = 0
            if self._prev_net:
                sent_bps = max(0, net.bytes_sent - self._prev_net.bytes_sent)
                recv_bps = max(0, net.bytes_recv - self._prev_net.bytes_recv)
            self._prev_net = net

            # Interface list
            ifaces = []
            for name, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family.name == "AF_INET":
                        ifaces.append({"name": name, "ip": addr.address})

            with self._lock:
                self.cpu_pct      = cpu
                self.ram_pct      = mem.percent
                self.ram_used_gb  = mem.used / 1e9
                self.ram_total_gb = mem.total / 1e9
                self.disk_pct     = disk.percent
                self.net_sent_bps = sent_bps
                self.net_recv_bps = recv_bps
                self.net_ifaces   = ifaces
                self.cpu_history.append(cpu)
                self.ram_history.append(mem.percent)
                self.net_sent_hist.append(sent_bps)
                self.net_recv_hist.append(recv_bps)

        except Exception as e:
            print(f"[COGNITO] SysMonitor error: {e}")

    def get_stats(self):
        with self._lock:
            return {
                "cpu_pct":       self.cpu_pct,
                "ram_pct":       self.ram_pct,
                "ram_used_gb":   self.ram_used_gb,
                "ram_total_gb":  self.ram_total_gb,
                "disk_pct":      self.disk_pct,
                "net_sent_bps":  self.net_sent_bps,
                "net_recv_bps":  self.net_recv_bps,
                "net_ifaces":    self.net_ifaces,
                "cpu_history":   list(self.cpu_history),
                "ram_history":   list(self.ram_history),
                "net_sent_hist": list(self.net_sent_hist),
                "net_recv_hist": list(self.net_recv_hist),
            }
