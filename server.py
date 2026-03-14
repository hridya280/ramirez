# -*- coding: utf-8 -*-
"""
RAMIREZ — Defense Operations Center (Web App Version)
FastAPI Server backend for the Oryn-themed UI.
Run as Administrator for full functionality (scapy + wmi).
"""
import asyncio
import json
import tkinter as tk # Not used for UI, but keeping if needed for imports? No, remove tkinter.
import threading
import time
import datetime
import os
import sys
import gc
import random
import socket
import tempfile
from collections import defaultdict
from difflib import SequenceMatcher

from fastapi import FastAPI, BackgroundTasks
from fastapi.responses import StreamingResponse, FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
import uvicorn

# ──────────────────────────────────────────────────────────────────────────────
# OPTIONAL IMPORTS — fail gracefully
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
# GLOBAL STATE
# ──────────────────────────────────────────────────────────────────────────────
app = FastAPI()

_threat_lock  = threading.Lock()
_threat_count = 0

_fake_spikes = {
    'cpu': 0.0,
    'ram': 0.0,
    'disk': 0.0,
    'net': 0.0
}

# Store history for all panels so late clients can sync, and for the report export.
# Also allows polling from the SSE endpoint easily.
history = {
    "anomaly": [],
    "portscan": [],
    "kernel": [],
    "packet": [],
    "attack": []
}

def _push(panel: str, text: str, is_alert: bool = False):
    """Thread-safe: append a log line to history."""
    history[panel].append({
        "text": text,
        "alert": is_alert,
        "timestamp": datetime.datetime.now().strftime("%H:%M:%S")
    })
    if is_alert and panel != "attack":
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
        if prev_val is None or dt == 0: return 0.0
        return (curr - prev_val) / dt

    def probability(value, mean, std):
        if std == 0: return 0.0
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
                pct = round(p * 100, 1)
                if is_anom:
                    msg = f"!! ANOMALY  {name:<4s}  slope={val:+.3f}  prob={pct}%"
                    _push("anomaly", msg, True)
                else:
                    msg = f"   OK       {name:<4s}  slope={val:+.3f}  prob={pct}%"
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
        _push("portscan", "[ERROR] scapy not available. Install: pip install scapy\nAlso install Npcap.", True)
        return

    THRESHOLD   = 15
    TIME_WINDOW = 5
    COOLDOWN    = 30
    port_hits   = defaultdict(set)
    alert_times = defaultdict(float)

    def process_pkt(pkt):
        try:
            if IP not in pkt or TCP not in pkt:
                return

            src_ip   = pkt[IP].src
            dst_port = pkt[TCP].dport
            now      = time.time()

            port_hits[src_ip].add((dst_port, round(now)))
            port_hits[src_ip] = { (p, t) for p, t in port_hits[src_ip] if now - t <= TIME_WINDOW }
            recent = port_hits[src_ip]

            if len(recent) >= THRESHOLD:
                if now - alert_times[src_ip] > COOLDOWN:
                    alert_times[src_ip] = now
                    ports = sorted({p for p, _ in recent})
                    msg = (f"!! PORT SCAN DETECTED\n"
                           f"         Attacker IP : {src_ip}\n"
                           f"         Ports hit   : {ports[:12]}{'...' if len(ports) > 12 else ''}")
                    _push("portscan", msg, True)
            else:
                _push("portscan", f" PKT  {src_ip:<15s} -> :{dst_port}", False)
        except Exception:
            pass

    _push("portscan", "[*] Port Scan Detector started  (TCP filter)")
    try:
        scapy_sniff(filter="tcp", prn=process_pkt, store=False)
    except PermissionError:
        _push("portscan", "[ERROR] Permission denied — run as Administrator", True)
    except Exception as e:
        _push("portscan", f"[ERROR] Sniff failed: {e}", True)

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
        except Exception:
            return []

    suspicious_list = load_list("suspicious_processes.txt")
    common_list     = load_list("common_processes.txt")
    if "malware.exe" not in suspicious_list:
        suspicious_list.append("malware.exe")

    _push("kernel", f"[*] Kernel Monitor started")
    _push("kernel", f"[*] Loaded signatures: {len(suspicious_list)} suspicious, {len(common_list)} common")

    def similar(a, b): return SequenceMatcher(None, a, b).ratio()

    def classify(name):
        if name in common_list: return "common"
        for bad in suspicious_list:
            if name == bad or similar(name, bad) > 0.80: return "suspicious"
        return "unknown"

    wmi_ok = False
    if WMI_OK:
        try:
            c_test = _wmi_mod.WMI()
            _test_watcher = c_test.Win32_ProcessStartTrace.watch_for()
            wmi_ok = True
            _push("kernel", "[+] WMI watcher ready — real-time spawn tracking")
        except Exception as e:
            if "Access denied" in str(e) or "access" in str(e).lower():
                _push("kernel", "[WARN] WMI requires admin. Switching to psutil poll mode.", False)
            else:
                _push("kernel", f"[WARN] WMI unavailable: {e} — using psutil", False)

    if wmi_ok:
        _run_kernel_wmi(suspicious_list, common_list, similar, classify)
    else:
        _run_kernel_psutil(suspicious_list, common_list, classify)

def _run_kernel_wmi(suspicious_list, common_list, similar_fn, classify_fn):
    try:
        c = _wmi_mod.WMI()
        watcher = c.Win32_ProcessStartTrace.watch_for()
    except Exception as e:
        _push("kernel", f"[ERROR] WMI watcher failed: {e}", True)
        _run_kernel_psutil(suspicious_list, common_list, classify_fn)
        return

    while True:
        try:
            try: new_proc = watcher(timeout_ms=2000)
            except TypeError: new_proc = watcher()

            if new_proc is None: continue
            name = new_proc.ProcessName.lower()
            pid  = new_proc.ProcessID
            
            kind = classify_fn(name)
            if kind == "common": continue

            if kind == "suspicious":
                _push("kernel", f"!! SUSPICIOUS PROCESS: {name} PID:{pid}", True)
            else:
                _push("kernel", f" ? Unknown process: {name} PID:{pid}", True)
        except Exception as e:
            if "timeout" not in str(e).lower():
                _push("kernel", f"[ERR] WMI: {e}", False)
                time.sleep(1)

def _run_kernel_psutil(suspicious_list, common_list, classify_fn):
    seen_pids = set()
    while True:
        try:
            current_pids = set()
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    pid  = proc.info["pid"]
                    name = (proc.info["name"] or "").lower()
                    current_pids.add(pid)

                    if pid in seen_pids: continue
                    
                    kind = classify_fn(name)
                    if kind == "common":
                        seen_pids.add(pid)
                        continue

                    seen_pids.add(pid)
                    if kind == "suspicious":
                        _push("kernel", f"!! SUSPICIOUS PROCESS: {name} PID:{pid}", True)
                    elif not name.startswith(("system", "registry", "smss", "csrss")):
                        _push("kernel", f" ? New process: {name} PID:{pid}", True)
                except:
                    pass
            seen_pids.intersection_update(current_pids)
        except Exception as e:
            _push("kernel", f"[ERR] {e}", False)
        time.sleep(2)

# ──────────────────────────────────────────────────────────────────────────────
# DEFENSE ADAPTER 4 — Packet Capture
# ──────────────────────────────────────────────────────────────────────────────
def _run_packet_capture():
    if not SCAPY_OK:
        _push("packet", "[ERROR] scapy not available.", True)
        return

    _push("packet", "[*] Packet Capture started")
    pkt_times = []
    BURST_THRESH = 40

    def process_pkt(pkt):
        try:
            if not pkt.haslayer("IP"): return
            now   = time.time()
            src   = pkt["IP"].src
            dst   = pkt["IP"].dst
            size  = len(pkt)
            proto = pkt["IP"].proto

            pkt_times.append(now)
            cutoff = now - 1.0
            while pkt_times and pkt_times[0] < cutoff:
                pkt_times.pop(0)
            pps = len(pkt_times)
            is_burst = pps >= BURST_THRESH

            pname = "TCP" if proto==6 else "UDP" if proto==17 else "ICMP" if proto==1 else f"IP/{proto}"
            btag = f" [BURST! {pps}pkt/s]" if is_burst else f" [{pps}pkt/s]"
            _push("packet", f" {pname:<4s}  {src:<15s} -> {dst:<15s}  {size}B{btag}", is_burst)
        except Exception:
            pass

    try:
        scapy_sniff(prn=process_pkt, store=False)
    except PermissionError:
        _push("packet", "[ERROR] Permission denied. Run app as Administrator.", True)
    except Exception as e:
        _push("packet", f"[ERROR] Sniff failed: {e}", True)

# ──────────────────────────────────────────────────────────────────────────────
# ATTACK FUNCTIONS
# ──────────────────────────────────────────────────────────────────────────────
def _spike_cpu():
    if not PSUTIL_OK: return
    n = max(1, psutil.cpu_count(logical=True))
    _push("attack", f"[*] CPU spike: {n} burn-threads for 5s…")
    _fake_spikes['cpu'] = time.time() + 5
    end = time.time() + 5
    def burn():
        while time.time() < end:
            _ = math.sqrt(random.random()) ** random.random()
    for _ in range(n):
        threading.Thread(target=burn, daemon=True).start()

def _spike_memory():
    size_mb = random.randint(1500, 2500) # Increased to 1.5-2.5 GB to guarantee visual graph spike
    _push("attack", f"[*] Memory spike: allocating {size_mb} MB for 5s…")
    _fake_spikes['ram'] = time.time() + 5
    def alloc():
        try:
            chunk = bytearray(size_mb * 1024 * 1024)
            for i in range(0, len(chunk), 4096): chunk[i] = i & 0xFF
            time.sleep(5)
            del chunk
            _push("attack", "[+] Memory spike released")
        except MemoryError:
            _push("attack", "[ERR] Not enough free RAM", True)
    threading.Thread(target=alloc, daemon=True).start()

def _spike_disk():
    _push("attack", "[*] Disk spike: heavy sequential IO for 5s (C: Drive)…")
    _fake_spikes['disk'] = time.time() + 5
    def write_disk():
        try:
            path = os.path.join(tempfile.gettempdir(), "_ramirez_spike.tmp")
            end = time.time() + 5
            with open(path, "wb") as f:
                while time.time() < end:
                    f.write(os.urandom(1024 * 1024 * 10)) # Write chunks rapidly to stress I/O
            os.remove(path)
            _push("attack", "[+] Disk spike released")
        except Exception as e:
            _push("attack", f"[ERR] Disk spike failed: {e}", True)
    threading.Thread(target=write_disk, daemon=True).start()

def _spike_network():
    _push("attack", "[*] Network spike: local TCP loopback flood…")
    _fake_spikes['net'] = time.time() + 5
    def flood():
        PORT = random.randint(50000, 59999)
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", PORT))
            srv.listen(1)
            srv.settimeout(6)
            def serve():
                try:
                    conn, _ = srv.accept()
                    end = time.time() + 5
                    buf = os.urandom(65536)
                    while time.time() < end: conn.sendall(buf)
                    conn.close()
                except Exception: pass
                finally:
                    try: srv.close()
                    except: pass
            threading.Thread(target=serve, daemon=True).start()
            cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            cli.connect(("127.0.0.1", PORT))
            end = time.time() + 5
            total = 0
            while time.time() < end:
                data = cli.recv(65536)
                if not data: break
                total += len(data)
            cli.close()
            _push("attack", f"[+] Network spike done — {total // 1024} KB transferred")
        except Exception as ex:
            _push("attack", f"[WARN] Network spike error: {ex}", True)
    threading.Thread(target=flood, daemon=True).start()

def _run_port_scan_attack(target):
    if not NMAP_OK:
        _push("attack", "[ERROR] python-nmap not installed.", True)
        return
    _push("attack", f"[*] Port scanning {target} (1-1024)…")
    def scan():
        try:
            scanner = _nmap_mod.PortScanner()
            scanner.scan(target, "1-1024", arguments="-T4 --open")
            for host in scanner.all_hosts():
                _push("attack", f"[+] Host: {host}  ({scanner[host].state()})")
                for proto in scanner[host].all_protocols():
                    ports = [p for p in scanner[host][proto].keys() if scanner[host][proto][p]["state"] == "open"]
                    for p in sorted(ports):
                        svc = scanner[host][proto][p].get("name", "?")
                        _push("attack", f"    {p:5d}/{proto}  OPEN  {svc}")
            _push("attack", "[+] Port scan complete")
        except Exception as e:
            _push("attack", f"[ERR] Scan failed: {e}", True)
    threading.Thread(target=scan, daemon=True).start()

# ──────────────────────────────────────────────────────────────────────────────
# FASTAPI ENDPOINTS
# ──────────────────────────────────────────────────────────────────────────────

# Start background threads
@app.on_event("startup")
def startup_event():
    for fn in [_run_anomaly_monitor, _run_port_scan_detector, _run_kernel_monitor, _run_packet_capture]:
        threading.Thread(target=fn, daemon=True).start()

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def index():
    return FileResponse("static/index.html")

_prev_net = (0, time.time())

@app.get("/stream")
async def stream():
    """SSE endpoint distributing live logs and metrics to the JS frontend."""
    async def event_generator():
        global _prev_net
        # Track cursors for each panel
        cursors = {k: len(v) for k, v in history.items()}
        
        while True:
            await asyncio.sleep(1.0)
            
            # 1. Send system metrics
            metrics = {"cpu": 0, "ram": 0, "disk": 0, "net": 0}
            if PSUTIL_OK:
                metrics["cpu"] = psutil.cpu_percent()
                metrics["ram"] = psutil.virtual_memory().percent
                metrics["disk"] = psutil.disk_usage("C:\\").percent
                
                net = psutil.net_io_counters()
                now_b = net.bytes_sent + net.bytes_recv
                pb, pt = _prev_net
                dt = max(time.time() - pt, 0.001)
                metrics["net"] = (now_b - pb) / 1024 / dt
                _prev_net = (now_b, time.time())
                
            # --- OVERLAY DEMO SPIKES FOR VISUAL IMPACT ---
            now = time.time()
            if _fake_spikes['cpu'] > now:
                metrics["cpu"] = min(100.0, metrics["cpu"] + random.uniform(50.0, 75.0))
            if _fake_spikes['ram'] > now:
                metrics["ram"] = min(100.0, metrics["ram"] + random.uniform(30.0, 50.0))
            if _fake_spikes['disk'] > now:
                metrics["disk"] = min(100.0, metrics["disk"] + random.uniform(15.0, 35.0))
            if _fake_spikes['net'] > now:
                metrics["net"] += random.uniform(50000.0, 150000.0) # Massive KB/s spike
            # ---------------------------------------------
            
            yield f"data: {json.dumps({'type': 'metrics', 'data': metrics, 'threats': _threat_count})}\n\n"
            
            # 2. Send new logs
            new_logs = []
            for panel, cursor in cursors.items():
                curr_len = len(history[panel])
                if curr_len > cursor:
                    for item in history[panel][cursor:curr_len]:
                        icopy = dict(item)
                        icopy["panel"] = panel
                        new_logs.append(icopy)
                    cursors[panel] = curr_len
            
            if new_logs:
                yield f"data: {json.dumps({'type': 'logs', 'logs': new_logs})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.post("/attack/{action}")
def trigger_attack(action: str, target: str = "127.0.0.1"):
    if action == "cpu": _spike_cpu()
    elif action == "memory": _spike_memory()
    elif action == "disk": _spike_disk()
    elif action == "network": _spike_network()
    elif action == "portscan": _run_port_scan_attack(target)
    return {"status": "ok"}

@app.get("/export")
def export_report():
    """Generate a downloadable text report."""
    lines = [
        "===========================================================",
        "        RAMIREZ DEFENSE OPERATIONS CENTER — EXPORT         ",
        "===========================================================",
        f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Total Threats Detected: {_threat_count}",
        "===========================================================\n"
    ]
    
    for panel in ["anomaly", "kernel", "portscan", "packet"]:
        lines.append(f"--- {panel.upper()} MONITOR ---")
        alerts_only = [item for item in history[panel] if item['alert']]
        if not alerts_only:
            lines.append("No alerts recorded.")
        else:
            for item in alerts_only:
                lines.append(f"[{item['timestamp']}] {item['text']}")
        lines.append("\n")
        
    return PlainTextResponse(
        "\n".join(lines), 
        headers={"Content-Disposition": "attachment; filename=ramirez-report.txt"}
    )

if __name__ == "__main__":
    if PSUTIL_OK:
        psutil.cpu_percent(interval=None) # Prime baseline
    uvicorn.run(app, host="0.0.0.0", port=8000)
