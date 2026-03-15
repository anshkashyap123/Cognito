# core/firewall.py  –  COGNITO XDR v3.0
# Cross-platform firewall: Windows netsh / Linux iptables / macOS pf

import platform
import subprocess
import threading
import time
import os

_lock = threading.Lock()
_rule_log = []   # [(ts, ip, action, success)]


def _run(cmd, shell=False, timeout=6):
    try:
        r = subprocess.run(cmd, shell=shell, capture_output=True, timeout=timeout)
        return r.returncode == 0
    except Exception:
        return False


def block_ip(ip: str, label: str = "COGNITO") -> bool:
    sys = platform.system()
    ok  = False
    if sys == "Windows":
        ok = _run(
            f'netsh advfirewall firewall add rule name="{label}_{ip}" '
            f'dir=in action=block remoteip={ip}',
            shell=True
        )
    elif sys == "Linux":
        ok = _run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
    elif sys == "Darwin":
        # macOS: use pfctl if available
        ok = _run(f'echo "block in quick from {ip}" | pfctl -f -', shell=True)

    with _lock:
        _rule_log.append({
            "ts":     time.strftime("%H:%M:%S"),
            "ip":     ip,
            "action": "BLOCK",
            "ok":     ok,
            "os":     sys,
        })
    return ok


def unblock_ip(ip: str, label: str = "COGNITO") -> bool:
    sys = platform.system()
    ok  = False
    if sys == "Windows":
        ok = _run(
            f'netsh advfirewall firewall delete rule name="{label}_{ip}"',
            shell=True
        )
    elif sys == "Linux":
        ok = _run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
    elif sys == "Darwin":
        ok = True   # simplified — real impl would edit pf rules

    with _lock:
        _rule_log.append({
            "ts":     time.strftime("%H:%M:%S"),
            "ip":     ip,
            "action": "UNBLOCK",
            "ok":     ok,
            "os":     sys,
        })
    return ok


def get_rule_log():
    with _lock:
        return list(_rule_log[-100:])


def detect_platform():
    return {
        "os":    platform.system(),
        "arch":  platform.machine(),
        "node":  platform.node(),
        "ver":   platform.version(),
    }
