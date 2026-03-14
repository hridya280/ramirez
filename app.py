# -*- coding: utf-8 -*-
"""
RAMIREZ — Defense Operations Center
Unified Tkinter UI integrating all 4 defense modules.
Run as Administrator for full functionality (scapy + wmi).
"""
# ──────────────────────────────────────────────────────────────────────────────
# STANDARD IMPORTS
# ──────────────────────────────────────────────────────────────────────────────
import tkinter as tk
import threading
import time
import datetime
import os
import sys
import gc
import math
import random
import socket
import queue
import subprocess
from collections import defaultdict
from difflib import SequenceMatcher

# ──────────────────────────────────────────────────────────────────────────────
# OPTIONAL IMPORTS — fail gracefully; panels show error but keep running
# ──────────────────────────────────────────────────────────────────────────────
try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

try:
    import numpy as np
    NUMPY_OK = True
except ImportError:
    np = None
    NUMPY_OK = False

try:
    from scapy.all import sniff as scapy_sniff, TCP, IP, Ether
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

try:
    import wmi as _wmi_mod
    WMI_OK = True
except Exception:
    WMI_OK = False

try:
    import nmap as _nmap_mod
    NMAP_OK = True
except Exception:
    NMAP_OK = False

# ──────────────────────────────────────────────────────────────────────────────
# THEME
# ──────────────────────────────────────────────────────────────────────────────
C = {
    "bg":           "#0a0e1a",
    "card":         "#111827",
    "card2":        "#0d1520",
    "border":       "#1f2937",
    "green":        "#00ff88",
    "red":          "#ff4444",
    "red_bg":       "#2a0008",
    "red_bright":   "#ff6666",
    "white":        "#e2e8f0",
    "muted":        "#4b5563",
    "yellow":       "#fbbf24",
    "blue":         "#60a5fa",
    "cyan":         "#22d3ee",
    "header_bg":    "#060a14",
    "attack_bg":    "#0d0a14",
    "attack_card":  "#1a0d2e",
    "attack_border":"#2d1b4e",
    "attack_accent":"#a855f7",
}
FONT_LOG    = ("Courier New", 10)          # panel log text
FONT_LOG_B  = ("Courier New", 10, "bold")  # panel log bold / alerts
FONT_MONO_B = ("Courier New", 10, "bold")  # general bold mono
FONT_MONO_L = ("Courier New", 11, "bold")  # larger mono
FONT_TITLE  = ("Courier New", 20, "bold")  # main title
FONT_MED    = ("Courier New", 13, "bold")  # metric values
FONT_SM     = ("Courier New", 9)           # small labels
FONT_SM_B   = ("Courier New", 9, "bold")   # small bold labels
FONT_PANEL_TITLE = ("Courier New", 11, "bold") # panel header title
FONT_ATK_LOG = ("Courier New", 9)          # attack log text

# ──────────────────────────────────────────────────────────────────────────────
# GLOBAL STATE
# ──────────────────────────────────────────────────────────────────────────────
_threat_lock  = threading.Lock()
_threat_count = 0

_queues = {
    "anomaly":  queue.Queue(),
    "portscan": queue.Queue(),
    "kernel":   queue.Queue(),
    "packet":   queue.Queue(),
}


def _push(panel: str, text: str, is_alert: bool = False):
    """Thread-safe: enqueue a log line for display in the given panel."""
    _queues[panel].put((text, is_alert))
    if is_alert:
        global _threat_count
        with _threat_lock:
            _threat_count += 1


# ──────────────────────────────────────────────────────────────────────────────
# DEFENSE ADAPTER 1 — Anomaly Monitor
# ──────────────────────────────────────────────────────────────────────────────
def _run_anomaly_monitor():
    if not PSUTIL_OK:
        _push("anomaly", "[ERROR] psutil not installed. Run: pip install psutil", True)
        return
    if not NUMPY_OK:
        _push("anomaly", "[ERROR] numpy not installed. Run: pip install numpy", True)
        return

    WINDOW = 10
    cpu_hist, ram_hist, disk_hist, net_hist = [], [], [], []
    prev_cpu = prev_ram = prev_disk = prev_net = prev_time = None

    def slope(curr, prev_val, dt):
        if prev_val is None or dt == 0:
            return 0.0
        return (curr - prev_val) / dt

    def probability(value, mean, std):
        if std == 0:
            return 0.0
        z = abs(value - mean) / std
        return min(1.0, z / 3.0)

    def check_hist(hist, value):
        if len(hist) < WINDOW:
            hist.append(value)
            return None, 0.0
        mean = float(np.mean(hist))
        std  = float(np.std(hist))
        p    = probability(value, mean, std)
        hist.pop(0)
        hist.append(value)
        return (p > 0.50), p

    _push("anomaly", "[*] Anomaly Monitor started  (sampling every 1 s)")
    _push("anomaly", f"[*] Warm-up: collecting {WINDOW} baseline samples…")

    while True:
        try:
            curr_time = time.time()
            if prev_time is None:
                prev_time = curr_time
                time.sleep(1)
                continue

            dt   = curr_time - prev_time
            cpu  = psutil.cpu_percent()
            ram  = psutil.virtual_memory().percent
            disk = psutil.disk_usage("C:\\").percent
            net  = psutil.net_io_counters().bytes_sent

            cpu_s  = slope(cpu,  prev_cpu,  dt)
            ram_s  = slope(ram,  prev_ram,  dt)
            disk_s = slope(disk, prev_disk, dt)
            net_s  = slope(net,  prev_net,  dt)

            for hist, val, name in [
                (cpu_hist,  cpu_s,  "CPU"),
                (ram_hist,  ram_s,  "RAM"),
                (disk_hist, disk_s, "DISK"),
                (net_hist,  net_s,  "NET"),
            ]:
                is_anom, p = check_hist(hist, val)
                if is_anom is None:
                    continue
                ts  = datetime.datetime.now().strftime("%H:%M:%S")
                pct = round(p * 100, 1)
                if is_anom:
                    msg = (f"[{ts}] !! ANOMALY  {name:<4s}  "
                           f"slope={val:+.3f}  prob={pct}%")
                    _push("anomaly", msg, True)
                else:
                    msg = (f"[{ts}]    OK       {name:<4s}  "
                           f"slope={val:+.3f}  prob={pct}%")
                    _push("anomaly", msg, False)

            prev_cpu, prev_ram, prev_disk, prev_net = cpu, ram, disk, net
            prev_time = curr_time
            time.sleep(1)

        except Exception as e:
            _push("anomaly", f"[ERR] {e}", False)
            time.sleep(2)


# ──────────────────────────────────────────────────────────────────────────────
# DEFENSE ADAPTER 2 — Port Scan Detector
# ──────────────────────────────────────────────────────────────────────────────
def _run_port_scan_detector():
    if not SCAPY_OK:
        _push("portscan",
              "[ERROR] scapy not available.\n"
              "        Install: pip install scapy\n"
              "        Also install Npcap from https://npcap.com  (WinPcap mode)", True)
        return

    THRESHOLD   = 15
    TIME_WINDOW = 5
    COOLDOWN    = 30
    port_hits   = defaultdict(set)
    alert_times = defaultdict(float)
    pkt_count   = [0]

    def process_pkt(pkt):
        try:
            pkt_count[0] += 1
            if IP not in pkt or TCP not in pkt:
                return

            src_ip   = pkt[IP].src
            dst_port = pkt[TCP].dport
            now      = time.time()
            ts       = datetime.datetime.now().strftime("%H:%M:%S")

            port_hits[src_ip].add((dst_port, round(now)))
            # Keep only recent hits
            port_hits[src_ip] = {
                (p, t) for p, t in port_hits[src_ip]
                if now - t <= TIME_WINDOW
            }
            recent = port_hits[src_ip]

            if len(recent) >= THRESHOLD:
                if now - alert_times[src_ip] > COOLDOWN:
                    alert_times[src_ip] = now
                    ports = sorted({p for p, _ in recent})
                    msg = (
                        f"[{ts}] !! PORT SCAN DETECTED\n"
                        f"         Attacker IP : {src_ip}\n"
                        f"         Ports hit   : {ports[:12]}"
                        f"{'...' if len(ports) > 12 else ''}\n"
                        f"         Total ports : {len(ports)}"
                    )
                    _push("portscan", msg, True)
            else:
                msg = f"[{ts}]  PKT  {src_ip:<15s} -> :{dst_port}"
                _push("portscan", msg, False)
        except Exception:
            pass

    _push("portscan", "[*] Port Scan Detector started  (TCP filter)")
    _push("portscan", "[*] Waiting for TCP packets…")
    try:
        scapy_sniff(filter="tcp", prn=process_pkt, store=False)
    except PermissionError:
        _push("portscan",
              "[ERROR] Permission denied — run app as Administrator\n"
              "        Right-click app.py -> 'Run as administrator'", True)
    except Exception as e:
        _push("portscan", f"[ERROR] Sniff failed: {e}\n"
              "        Try running as Administrator.", True)


# ──────────────────────────────────────────────────────────────────────────────
# DEFENSE ADAPTER 3 — Kernel / Process Monitor
# ──────────────────────────────────────────────────────────────────────────────
def _run_kernel_monitor():
    base = os.path.dirname(os.path.abspath(__file__))

    def load_list(fname):
        path = os.path.join(base, "data", fname)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                return [line.strip().lower() for line in f if line.strip()]
        except Exception as e:
            _push("kernel", f"[WARN] Could not load {fname}: {e}", False)
            return []

    suspicious_list = load_list("suspicious_processes.txt")
    common_list     = load_list("common_processes.txt")
    # Also add malware.exe explicitly
    if "malware.exe" not in suspicious_list:
        suspicious_list.append("malware.exe")

    _push("kernel", f"[*] Kernel Monitor started")
    _push("kernel", f"[*] Loaded {len(suspicious_list)} suspicious signatures")
    _push("kernel", f"[*] Loaded {len(common_list)} common (safe) processes")
    _push("kernel", "[*] Scanning running processes every 2 s…")

    def similar(a, b):
        return SequenceMatcher(None, a, b).ratio()

    def classify(name):
        if name in common_list:
            return "common"
        for bad in suspicious_list:
            if name == bad or similar(name, bad) > 0.80:
                return "suspicious"
        return "unknown"

    # Strategy 1: WMI event watcher for new process spawns
    # Strategy 2: fallback to psutil polling (always works)
    wmi_ok = False
    if WMI_OK:
        try:
            _push("kernel", "[*] Initialising WMI process watcher…")
            c_test = _wmi_mod.WMI()
            # Try creating the event watcher — this is where access denied fires
            _test_watcher = c_test.Win32_ProcessStartTrace.watch_for()
            wmi_ok = True
            _push("kernel", "[+] WMI watcher ready — watching for new process spawns")
        except Exception as e:
            err_msg = str(e)
            if "Access denied" in err_msg or "access" in err_msg.lower():
                _push("kernel",
                      "[WARN] WMI requires admin rights.\n"
                      "         Switching to psutil poll mode (all processes scanned)", False)
            else:
                _push("kernel", f"[WARN] WMI unavailable: {e} — using psutil", False)
            wmi_ok = False # Explicitly set to False on error

    if wmi_ok:
        _run_kernel_wmi(suspicious_list, common_list, similar, classify)
    else:
        _run_kernel_psutil(suspicious_list, common_list, classify)


def _run_kernel_wmi(suspicious_list, common_list, similar_fn, classify_fn):
    """Use WMI Win32_ProcessStartTrace to watch new process spawns in real time."""
    try:
        c = _wmi_mod.WMI()
        watcher = c.Win32_ProcessStartTrace.watch_for()
    except Exception as e:
        _push("kernel", f"[ERROR] WMI watcher failed: {e}", True)
        _push("kernel", "[*] Falling back to psutil poll mode…")
        # fallback inline
        _run_kernel_psutil(suspicious_list, common_list, classify_fn)
        return

    while True:
        try:
            new_proc = watcher(timeout_ms=2000)
            if new_proc is None:
                continue
            name = new_proc.ProcessName.lower()
            pid  = new_proc.ProcessID
            ppid = new_proc.ParentProcessID
            ts   = datetime.datetime.now().strftime("%H:%M:%S")

            kind = classify_fn(name)
            if kind == "common":
                continue

            if kind == "suspicious":
                msg = (f"[{ts}] !! SUSPICIOUS PROCESS DETECTED\n"
                       f"         Name : {name}\n"
                       f"         PID  : {pid}   PPID: {ppid}")
                _push("kernel", msg, True)
            else:
                msg = (f"[{ts}]  ? Unknown process\n"
                       f"         Name : {name}\n"
                       f"         PID  : {pid}   PPID: {ppid}")
                _push("kernel", msg, True)

        except Exception as e:
            err = str(e)
            if "timeout" in err.lower() or "timed out" in err.lower():
                continue   # just a polling timeout, not a real error
            _push("kernel", f"[ERR] WMI: {e}", False)
            time.sleep(1)


def _run_kernel_psutil(suspicious_list, common_list, classify_fn):
    """Poll psutil every 2 s. Alert on suspicious/unknown processes."""
    _push("kernel", "[*] psutil poll mode: scanning every 2 s")
    seen_pids = set()

    while True:
        try:
            current_pids = set()
            for proc in psutil.process_iter(["pid", "name", "ppid"]):
                try:
                    pid  = proc.info["pid"]
                    name = (proc.info["name"] or "").lower()
                    ppid = proc.info.get("ppid", 0)
                    current_pids.add(pid)

                    if pid in seen_pids:
                        continue  # already reported

                    kind = classify_fn(name)
                    if kind == "common":
                        seen_pids.add(pid)
                        continue

                    ts = datetime.datetime.now().strftime("%H:%M:%S")
                    seen_pids.add(pid)

                    if kind == "suspicious":
                        msg = (f"[{ts}] !! SUSPICIOUS PROCESS\n"
                               f"         Name : {name}\n"
                               f"         PID  : {pid}   PPID: {ppid}")
                        _push("kernel", msg, True)
                    else:
                        # Only log truly new unknowns once — suppress common system noise
                        if not name.startswith(("system", "registry", "smss", "csrss")):
                            msg = (f"[{ts}]  ? New process: {name}  PID={pid}")
                            _push("kernel", msg, True)

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            # Clean up pids that disappeared
            gone = seen_pids - current_pids
            seen_pids -= gone

        except Exception as e:
            _push("kernel", f"[ERR] {e}", False)

        time.sleep(2)


# ──────────────────────────────────────────────────────────────────────────────
# DEFENSE ADAPTER 4 — Packet Capture
# ──────────────────────────────────────────────────────────────────────────────
def _run_packet_capture():
    if not SCAPY_OK:
        _push("packet",
              "[ERROR] scapy not available.\n"
              "        Install: pip install scapy\n"
              "        Also install Npcap from https://npcap.com", True)
        return

    _push("packet", "[*] Packet Capture started — all IP packets")
    _push("packet", "[*] Waiting for packets…")
    _push("packet", "[*] NOTE: Run as Administrator for live capture")

    pkt_times = []
    BURST_THRESH = 40  # packets/second to flag as suspicious

    # Flow stats (reset every 30s)
    flow_stats = {"fwd": 0, "bwd": 0, "bytes": 0, "start": time.time()}
    SRC_IP = [None]

    def process_pkt(pkt):
        try:
            if not pkt.haslayer("IP"):
                return

            now   = time.time()
            src   = pkt["IP"].src
            dst   = pkt["IP"].dst
            size  = len(pkt)
            proto = pkt["IP"].proto
            ts    = datetime.datetime.now().strftime("%H:%M:%S")

            # Track rate
            pkt_times.append(now)
            cutoff = now - 1.0
            while pkt_times and pkt_times[0] < cutoff:
                pkt_times.pop(0)
            pps = len(pkt_times)
            is_burst = pps >= BURST_THRESH

            # Track flow
            if SRC_IP[0] is None:
                SRC_IP[0] = src
            if src == SRC_IP[0]:
                flow_stats["fwd"] += 1
            else:
                flow_stats["bwd"] += 1
            flow_stats["bytes"] += size

            if proto == 6:   proto_name = "TCP"
            elif proto == 17: proto_name = "UDP"
            elif proto == 1:  proto_name = "ICMP"
            else:             proto_name = f"IP/{proto}"

            burst_tag = f" [BURST! {pps}pkt/s]" if is_burst else f" [{pps}pkt/s]"
            msg = (f"[{ts}]  {proto_name:<4s}  {src:<15s} -> {dst:<15s}"
                   f"  {size}B{burst_tag}")
            _push("packet", msg, is_burst)

        except Exception:
            pass

    try:
        scapy_sniff(prn=process_pkt, store=False)
    except PermissionError:
        _push("packet",
              "[ERROR] Permission denied.\n"
              "        Run the app as Administrator for packet capture.", True)
    except Exception as e:
        _push("packet", f"[ERROR] Sniff failed: {e}", True)


# ──────────────────────────────────────────────────────────────────────────────
# ATTACK FUNCTIONS
# ──────────────────────────────────────────────────────────────────────────────
def _spike_cpu(log_fn, duration=5):
    if not PSUTIL_OK:
        log_fn("[ERR] psutil not available")
        return
    n = max(1, psutil.cpu_count(logical=True))
    log_fn(f"[*] CPU spike: {n} burn-threads for {duration}s…")

    end = time.time() + duration
    def burn():
        while time.time() < end:
            _ = math.sqrt(random.random()) ** random.random()

    for _ in range(n):
        threading.Thread(target=burn, daemon=True).start()
    log_fn(f"[+] CPU spike running ({n} threads)")


def _spike_memory(log_fn, duration=5):
    size_mb = random.randint(300, 500)
    log_fn(f"[*] Memory spike: allocating {size_mb} MB for {duration}s…")
    def alloc():
        try:
            chunk = bytearray(size_mb * 1024 * 1024)
            for i in range(0, len(chunk), 4096):
                chunk[i] = i & 0xFF
            time.sleep(duration)
            del chunk
            gc.collect()
            log_fn("[+] Memory spike released")
        except MemoryError:
            log_fn("[ERR] Not enough free RAM")
    threading.Thread(target=alloc, daemon=True).start()


def _spike_network(log_fn, duration=5):
    log_fn("[*] Network spike: local TCP loopback flood…")
    def flood():
        PORT = random.randint(50000, 59999)
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", PORT))
            srv.listen(1)
            srv.settimeout(duration + 1)

            def serve():
                try:
                    conn, _ = srv.accept()
                    end = time.time() + duration
                    buf = os.urandom(65536)
                    while time.time() < end:
                        conn.sendall(buf)
                    conn.close()
                except Exception:
                    pass
                finally:
                    try: srv.close()
                    except Exception: pass

            threading.Thread(target=serve, daemon=True).start()
            cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            cli.connect(("127.0.0.1", PORT))
            end = time.time() + duration
            total = 0
            while time.time() < end:
                data = cli.recv(65536)
                if not data:
                    break
                total += len(data)
            cli.close()
            log_fn(f"[+] Network spike done — {total // 1024} KB transferred")
        except Exception as ex:
            log_fn(f"[WARN] Network spike error: {ex}")
    threading.Thread(target=flood, daemon=True).start()


def _run_port_scan_attack(target, log_fn):
    if not NMAP_OK:
        log_fn("[ERROR] python-nmap not installed:  pip install python-nmap")
        return
    log_fn(f"[*] Port scanning {target}  (ports 1-1024)…")
    try:
        scanner = _nmap_mod.PortScanner()
        scanner.scan(target, "1-1024", arguments="-T4 --open")
        for host in scanner.all_hosts():
            log_fn(f"[+] Host: {host}  ({scanner[host].state()})")
            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()
                open_ports = [p for p in ports
                              if scanner[host][proto][p]["state"] == "open"]
                for p in sorted(open_ports):
                    svc = scanner[host][proto][p].get("name", "?")
                    log_fn(f"    {p:5d}/{proto}  OPEN  {svc}")
        log_fn("[+] Port scan complete")
    except Exception as e:
        log_fn(f"[ERR] Scan failed: {e}")


# ──────────────────────────────────────────────────────────────────────────────
# UI HELPERS
# ──────────────────────────────────────────────────────────────────────────────
# Panel accent colors per panel (dot indicator color)
_PANEL_COLORS = {
    "Anomaly Monitor":    "#fbbf24",   # yellow
    "Port Scan Detector": "#f87171",   # red-orange
    "Kernel Monitor":     "#a78bfa",   # violet
    "Packet Capture":     "#34d399",   # teal
}

def make_panel(parent, title: str, row: int, col: int):
    """Create a defense panel, return its tk.Text widget."""
    accent = _PANEL_COLORS.get(title, C["green"])

    frame = tk.Frame(parent, bg=C["card"],
                     highlightbackground=C["border"], highlightthickness=1)
    frame.grid(row=row, column=col, sticky="nsew",
               padx=(0, 6), pady=(0, 6))

    # Coloured top accent bar
    tk.Frame(frame, bg=accent, height=3).pack(fill="x")

    # Title bar with more vertical breathing room
    tbar = tk.Frame(frame, bg=C["card2"])
    tbar.pack(fill="x")

    # Dot + title
    dot_lbl = tk.Label(tbar, text="●", bg=C["card2"], fg=accent,
                       font=FONT_SM_B)
    dot_lbl.pack(side="left", padx=(12, 6), pady=10)
    tk.Label(tbar, text=title.upper(), bg=C["card2"], fg=C["white"],
             font=FONT_PANEL_TITLE).pack(side="left", pady=10)

    # Thin separator line
    tk.Frame(frame, bg=C["border"], height=1).pack(fill="x")

    # Scrollable text area — generous padding
    inner = tk.Frame(frame, bg=C["card"])
    inner.pack(fill="both", expand=True, padx=6, pady=6)

    sb = tk.Scrollbar(inner, bg=C["border"], troughcolor=C["bg"], width=8)
    sb.pack(side="right", fill="y")

    txt = tk.Text(inner, bg=C["card"], fg=C["green"], font=FONT_LOG,
                  state="disabled", wrap="word", relief="flat",
                  borderwidth=0, padx=10, pady=6,
                  insertbackground=C["green"],
                  spacing1=2, spacing3=2,  # extra line spacing
                  yscrollcommand=sb.set)
    txt.pack(fill="both", expand=True)
    sb.config(command=txt.yview)

    txt.tag_config("normal", foreground=C["green"])
    txt.tag_config("alert",  foreground=C["red_bright"],
                   background=C["red_bg"], font=FONT_LOG_B)
    txt.tag_config("info",   foreground=C["white"])

    return txt


def panel_write(txt: tk.Text, message: str, is_alert: bool):
    """Append text to a panel — MUST be called from the main thread."""
    txt.config(state="normal")
    tag = "alert" if is_alert else "normal"
    for line in message.split("\n"):
        txt.insert("end", line + "\n", tag)
    txt.see("end")
    txt.config(state="disabled")


# ──────────────────────────────────────────────────────────────────────────────
# MAIN APPLICATION CLASS
# ──────────────────────────────────────────────────────────────────────────────
class RamirezApp:
    def __init__(self, root: tk.Tk):
        self.root   = root
        self._aids  = []   # after() handles for clean cancel on close
        root.title("RAMIREZ — Defense Operations Center")
        root.configure(bg=C["bg"])
        root.minsize(1200, 740)

        self._build_header()
        self._build_main()
        self._start_defense_threads()
        self._schedule_refresh()

    # ──────────────────────────────────────────────────────────────────────────
    # HEADER
    # ──────────────────────────────────────────────────────────────────────────
    def _build_header(self):
        hdr = tk.Frame(self.root, bg=C["header_bg"],
                       highlightbackground=C["border"], highlightthickness=1)
        hdr.pack(fill="x", padx=8, pady=(8, 6))

        # ── Left: branding
        left = tk.Frame(hdr, bg=C["header_bg"])
        left.pack(side="left", padx=18, pady=12)

        tk.Label(left, text="▣  RAMIREZ", bg=C["header_bg"],
                 fg=C["green"], font=FONT_TITLE).pack(anchor="w")
        tk.Label(left, text="Multi-Agent Cybersecurity Defense System",
                 bg=C["header_bg"], fg=C["muted"], font=FONT_SM).pack(anchor="w", pady=(2, 0))

        # ── Vertical divider
        tk.Frame(hdr, bg=C["border"], width=1).pack(
            side="left", fill="y", padx=(6, 0), pady=10)

        # ── Centre: metric cards
        mc = tk.Frame(hdr, bg=C["header_bg"])
        mc.pack(side="left", padx=20, pady=10)
        self._mlabels = {}
        for name, color in [("CPU",  C["yellow"]),
                            ("RAM",  C["blue"]),
                            ("DISK", C["cyan"]),
                            ("NET",  C["green"])]:
            card = tk.Frame(mc, bg=C["card"],
                            highlightbackground=color, highlightthickness=1)
            card.pack(side="left", padx=5)
            # Coloured top strip
            tk.Frame(card, bg=color, height=3).pack(fill="x")
            tk.Label(card, text=name, bg=C["card"], fg=color,
                     font=FONT_SM_B).pack(padx=18, pady=(6, 2))
            v = tk.Label(card, text="--", bg=C["card"],
                         fg=C["white"], font=FONT_MED)
            v.pack(padx=18, pady=(0, 8))
            self._mlabels[name] = v

        # ── Vertical divider
        tk.Frame(hdr, bg=C["border"], width=1).pack(
            side="right", fill="y", padx=(0, 6), pady=10)

        # ── Right: status + threat counter
        right = tk.Frame(hdr, bg=C["header_bg"])
        right.pack(side="right", padx=20, pady=12)

        # Status row
        sr = tk.Frame(right, bg=C["header_bg"])
        sr.pack(anchor="e")
        tk.Label(sr, text="STATUS", bg=C["header_bg"],
                 fg=C["muted"], font=FONT_SM_B).pack(side="left")
        self._sdot = tk.Label(sr, text="  ●", bg=C["header_bg"],
                              fg=C["green"], font=("Courier New", 12, "bold"))
        self._sdot.pack(side="left")
        self._slbl = tk.Label(sr, text="MONITORING",
                              bg=C["header_bg"], fg=C["green"],
                              font=("Courier New", 11, "bold"))
        self._slbl.pack(side="left", padx=(4, 0))

        # Separator line between status and threat counter
        tk.Frame(right, bg=C["border"], height=1).pack(fill="x", pady=5)

        # Threat row
        tr = tk.Frame(right, bg=C["header_bg"])
        tr.pack(anchor="e")
        tk.Label(tr, text="THREATS DETECTED", bg=C["header_bg"],
                 fg=C["muted"], font=FONT_SM_B).pack(side="left")
        self._tlbl = tk.Label(tr, text="0", bg=C["header_bg"],
                              fg=C["red"], font=("Courier New", 22, "bold"))
        self._tlbl.pack(side="left", padx=(10, 0))

    # ──────────────────────────────────────────────────────────────────────────
    # MAIN AREA: 2×2 defense grid + attack console
    # ──────────────────────────────────────────────────────────────────────────
    def _build_main(self):
        main = tk.Frame(self.root, bg=C["bg"])
        main.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        # Defense 2×2 grid — expanded min sizes for breathing room
        da = tk.Frame(main, bg=C["bg"])
        da.pack(side="left", fill="both", expand=True)
        for r in range(2):
            da.rowconfigure(r, weight=1, minsize=240)
        for c in range(2):
            da.columnconfigure(c, weight=1, minsize=320)

        self._panels = {
            "anomaly":  make_panel(da, "Anomaly Monitor",    0, 0),
            "portscan": make_panel(da, "Port Scan Detector", 0, 1),
            "kernel":   make_panel(da, "Kernel Monitor",     1, 0),
            "packet":   make_panel(da, "Packet Capture",     1, 1),
        }

        # Attack console
        self._build_attack_console(main)

    def _build_attack_console(self, parent):
        atk = tk.Frame(parent, bg=C["attack_bg"],
                       highlightbackground=C["attack_border"], highlightthickness=1)
        atk.pack(side="right", fill="y", padx=(6, 0))
        atk.config(width=300)
        atk.pack_propagate(False)

        # Accent bar at top
        tk.Frame(atk, bg=C["attack_accent"], height=3).pack(fill="x")

        # Title
        tbar = tk.Frame(atk, bg=C["attack_card"])
        tbar.pack(fill="x")
        tk.Label(tbar, text="ATTACK CONSOLE", bg=C["attack_card"],
                 fg=C["attack_accent"], font=("Courier New", 12, "bold"),
                 pady=10).pack()
        tk.Frame(atk, bg=C["attack_border"], height=1).pack(fill="x")

        body = tk.Frame(atk, bg=C["attack_bg"])
        body.pack(fill="both", expand=True, padx=12, pady=12)

        # ── Target IP
        tk.Label(body, text="TARGET IP", bg=C["attack_bg"],
                 fg=C["muted"], font=FONT_SM_B).pack(anchor="w")
        ipf = tk.Frame(body, bg=C["attack_card"],
                       highlightbackground=C["attack_border"], highlightthickness=1)
        ipf.pack(fill="x", pady=(4, 14))
        self._ipv = tk.StringVar(value="127.0.0.1")
        tk.Entry(ipf, textvariable=self._ipv,
                 bg=C["attack_card"], fg=C["attack_accent"],
                 insertbackground=C["attack_accent"],
                 font=FONT_MONO_L, relief="flat", borderwidth=6).pack(fill="x")

        # ── Attack buttons with icons baked in
        btn_cfg = dict(font=("Courier New", 10, "bold"), relief="flat",
                       cursor="hand2", borderwidth=0, pady=10)
        btns = [
            ("  PORT SCAN",    "#7c3aed", "#ddd6fe", self._btn_portscan),
            ("  SPIKE CPU",    "#b91c1c", "#fca5a5", self._btn_cpu),
            ("  SPIKE MEMORY", "#1d4ed8", "#93c5fd", self._btn_memory),
            ("  SPIKE NET",    "#0f766e", "#99f6e4", self._btn_network),
        ]
        for lbl, bg, fg, cmd in btns:
            tk.Button(body, text=lbl, bg=bg, fg=fg,
                      activebackground=fg, activeforeground=bg,
                      command=cmd, anchor="w", padx=14, **btn_cfg).pack(fill="x", pady=4)

        tk.Frame(body, bg=C["attack_border"], height=1).pack(fill="x", pady=10)

        # ── Attack log
        tk.Label(body, text="ATTACK LOG", bg=C["attack_bg"],
                 fg=C["muted"], font=FONT_SM_B).pack(anchor="w")
        lf = tk.Frame(body, bg=C["attack_card"],
                      highlightbackground=C["attack_border"], highlightthickness=1)
        lf.pack(fill="both", expand=True, pady=(4, 0))
        sb = tk.Scrollbar(lf, bg=C["attack_border"],
                          troughcolor=C["attack_bg"], width=6)
        sb.pack(side="right", fill="y")
        self._atk = tk.Text(lf, bg=C["attack_card"], fg=C["attack_accent"],
                            font=FONT_ATK_LOG, state="disabled", wrap="word",
                            relief="flat", borderwidth=0, padx=8, pady=6,
                            spacing1=2, spacing3=2,
                            yscrollcommand=sb.set)
        self._atk.pack(fill="both", expand=True)
        sb.config(command=self._atk.yview)
        self._atk.tag_config("ok",   foreground="#a3e635")
        self._atk.tag_config("err",  foreground=C["red"])
        self._atk.tag_config("info", foreground=C["white"])

    # ──────────────────────────────────────────────────────────────────────────
    # ATTACK CONSOLE HELPERS
    # ──────────────────────────────────────────────────────────────────────────
    def _alog(self, msg: str, tag: str = "info"):
        """Write to the attack log — safe to call from any thread."""
        def _do():
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            self._atk.config(state="normal")
            self._atk.insert("end", f"[{ts}] {msg}\n", tag)
            self._atk.see("end")
            self._atk.config(state="disabled")
        self.root.after(0, _do)

    def _btn_portscan(self):
        tgt = self._ipv.get().strip() or "127.0.0.1"
        threading.Thread(
            target=_run_port_scan_attack,
            args=(tgt, lambda m: self._alog(m, "ok")),
            daemon=True
        ).start()
        self._alog(f"Port scan launched -> {tgt}", "info")

    def _btn_cpu(self):
        threading.Thread(
            target=_spike_cpu,
            args=(lambda m: self._alog(m, "ok"),),
            daemon=True
        ).start()
        self._alog("CPU spike launched", "info")

    def _btn_memory(self):
        threading.Thread(
            target=_spike_memory,
            args=(lambda m: self._alog(m, "ok"),),
            daemon=True
        ).start()
        self._alog("Memory spike launched", "info")

    def _btn_network(self):
        threading.Thread(
            target=_spike_network,
            args=(lambda m: self._alog(m, "ok"),),
            daemon=True
        ).start()
        self._alog("Network spike launched", "info")

    # ──────────────────────────────────────────────────────────────────────────
    # DEFENSE THREAD STARTUP
    # ──────────────────────────────────────────────────────────────────────────
    def _start_defense_threads(self):
        for fn, name in [
            (_run_anomaly_monitor,    "anomaly"),
            (_run_port_scan_detector, "portscan"),
            (_run_kernel_monitor,     "kernel"),
            (_run_packet_capture,     "packet"),
        ]:
            t = threading.Thread(target=fn, name=f"defense-{name}", daemon=True)
            t.start()

    # ──────────────────────────────────────────────────────────────────────────
    # REFRESH LOOP (main thread, every 2 s)
    # ──────────────────────────────────────────────────────────────────────────
    def _schedule_refresh(self):
        self._refresh()

    def _refresh(self):
        # Drain queues → write to panel Text widgets
        for key, txt in self._panels.items():
            q = _queues[key]
            count = 0
            while not q.empty() and count < 60:
                try:
                    msg, alert = q.get_nowait()
                    panel_write(txt, msg, alert)
                    count += 1
                except queue.Empty:
                    break

        # Live metrics
        self._update_metrics()

        # Threat counter
        with _threat_lock:
            tc = _threat_count
        self._tlbl.config(text=str(tc),
                          fg=C["red"] if tc > 0 else C["muted"])

        self._aids.append(self.root.after(2000, self._refresh))

    def _update_metrics(self):
        if not PSUTIL_OK:
            return
        try:
            cpu  = psutil.cpu_percent()
            ram  = psutil.virtual_memory().percent
            disk = psutil.disk_usage("C:\\").percent

            net = psutil.net_io_counters()
            now_b = net.bytes_sent + net.bytes_recv
            if not hasattr(self, "_prev_net"):
                self._prev_net = (now_b, time.time())
                net_str = "-- KB/s"
            else:
                pb, pt = self._prev_net
                dt = max(time.time() - pt, 0.001)
                kbps = (now_b - pb) / 1024 / dt
                net_str = f"{kbps:.0f} KB/s"
                self._prev_net = (now_b, time.time())

            self._mlabels["CPU"].config(text=f"{cpu:.0f}%")
            self._mlabels["RAM"].config(text=f"{ram:.0f}%")
            self._mlabels["DISK"].config(text=f"{disk:.0f}%")
            self._mlabels["NET"].config(text=net_str)
        except Exception:
            pass

    def on_close(self):
        for a in self._aids:
            try: self.root.after_cancel(a)
            except Exception: pass
        self.root.destroy()


# ──────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if PSUTIL_OK:
        psutil.cpu_percent(interval=None)   # prime baseline

    root = tk.Tk()
    app  = RamirezApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)

    try:
        sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
        w, h = min(1400, sw - 30), min(860, sh - 60)
        root.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")
    except Exception:
        root.geometry("1280x800")

    root.mainloop()
