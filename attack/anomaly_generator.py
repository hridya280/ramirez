"""
Anomaly Generator — A trackable test app that counts 1 → 1,000,000,000
and deliberately fires CPU, Memory, Disk, and Network (WiFi) spikes
so that monitoring tools can detect and log them.

Requirements:
    pip install psutil requests

Run:
    python anomaly_generator.py
"""

import tkinter as tk
from tkinter import ttk, font as tkfont
import threading
import time
import random
import math
import os
import gc
import socket
import psutil
import tempfile
import struct
import itertools

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
COUNT_TARGET   = 1_000_000_000
SPIKE_INTERVAL = (8, 20)          # random seconds between auto-spikes
SPIKE_TYPES    = ["CPU", "MEMORY", "DISK", "NETWORK"]

COLORS = {
    "bg":         "#0d0d0d",
    "panel":      "#141414",
    "border":     "#1e1e1e",
    "accent":     "#00ff88",
    "accent2":    "#00ccff",
    "warn":       "#ffaa00",
    "danger":     "#ff3366",
    "text":       "#e8e8e8",
    "muted":      "#555555",
    "cpu":        "#ff6b35",
    "memory":     "#a855f7",
    "disk":       "#22d3ee",
    "network":    "#4ade80",
}

# ─────────────────────────────────────────────────────────────────────────────
# SPIKE WORKERS
# ─────────────────────────────────────────────────────────────────────────────

def spike_cpu(duration=3):
    """Burn CPU on all available threads for `duration` seconds."""
    end = time.time() + duration
    workers = []
    def burn():
        while time.time() < end:
            _ = math.sqrt(random.random()) ** random.random()
    n = max(1, psutil.cpu_count(logical=True))
    for _ in range(n):
        t = threading.Thread(target=burn, daemon=True)
        t.start()
        workers.append(t)


def spike_memory(duration=4):
    """Allocate ~400–600 MB of RAM then release it."""
    def alloc():
        size_mb = random.randint(400, 600)
        chunk = bytearray(size_mb * 1024 * 1024)
        # Touch every page so the OS actually commits the memory
        for i in range(0, len(chunk), 4096):
            chunk[i] = i & 0xFF
        time.sleep(duration)
        del chunk
        gc.collect()
    threading.Thread(target=alloc, daemon=True).start()


def spike_disk(duration=3):
    """Write and read a temp file rapidly to create a disk I/O spike."""
    def io_storm():
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".anomaly")
        path = tmp.name
        try:
            end = time.time() + duration
            data = os.urandom(4 * 1024 * 1024)   # 4 MB block
            while time.time() < end:
                tmp.seek(0)
                tmp.write(data)
                tmp.flush()
                os.fsync(tmp.fileno())
                tmp.seek(0)
                _ = tmp.read()
        finally:
            tmp.close()
            try:
                os.unlink(path)
            except OSError:
                pass
    threading.Thread(target=io_storm, daemon=True).start()


def spike_network(duration=4):
    """
    Create a local TCP loopback flood to generate network traffic.
    Falls back to a raw byte-shuffle if socket binding fails.
    """
    def loopback_flood():
        PORT = random.randint(50000, 59999)
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("127.0.0.1", PORT))
            server.listen(1)
            server.settimeout(duration + 1)

            def serve():
                try:
                    conn, _ = server.accept()
                    end = time.time() + duration
                    buf = os.urandom(65536)
                    while time.time() < end:
                        conn.sendall(buf)
                    conn.close()
                except Exception:
                    pass
                finally:
                    server.close()

            threading.Thread(target=serve, daemon=True).start()

            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect(("127.0.0.1", PORT))
            end = time.time() + duration
            while time.time() < end:
                data = client.recv(65536)
                if not data:
                    break
            client.close()
        except Exception:
            # Fallback: CPU-based fake "network" work
            end = time.time() + duration
            buf = bytearray(os.urandom(1024 * 1024))
            while time.time() < end:
                buf = bytearray(itertools.islice(itertools.cycle(buf), len(buf)))

    threading.Thread(target=loopback_flood, daemon=True).start()


SPIKE_FUNCS = {
    "CPU":     spike_cpu,
    "MEMORY":  spike_memory,
    "DISK":    spike_disk,
    "NETWORK": spike_network,
}

SPIKE_COLORS = {
    "CPU":     COLORS["cpu"],
    "MEMORY":  COLORS["memory"],
    "DISK":    COLORS["disk"],
    "NETWORK": COLORS["network"],
}

# ─────────────────────────────────────────────────────────────────────────────
# MAIN APP
# ─────────────────────────────────────────────────────────────────────────────

class AnomalyApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Anomaly Generator")
        self.configure(bg=COLORS["bg"])
        self.resizable(False, False)

        # State
        self._counter        = 0
        self._running        = False
        self._count_thread   = None
        self._auto_thread    = None
        self._active_spikes  = {}    # spike_type → label widget
        self._log_entries    = []    # list of (timestamp, spike_type)
        self._metrics_after  = None

        self._build_ui()
        self._refresh_metrics()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ── UI CONSTRUCTION ──────────────────────────────────────────────────────

    def _build_ui(self):
        W = 780

        # ── Title bar ──
        title_frame = tk.Frame(self, bg=COLORS["bg"], pady=12)
        title_frame.pack(fill="x", padx=24)

        tk.Label(
            title_frame, text="ANOMALY GENERATOR",
            bg=COLORS["bg"], fg=COLORS["accent"],
            font=("Courier New", 18, "bold"), anchor="w"
        ).pack(side="left")

        self._status_dot = tk.Label(
            title_frame, text="●", bg=COLORS["bg"], fg=COLORS["muted"],
            font=("Courier New", 14)
        )
        self._status_dot.pack(side="right", padx=(0, 4))
        self._status_lbl = tk.Label(
            title_frame, text="IDLE", bg=COLORS["bg"], fg=COLORS["muted"],
            font=("Courier New", 10)
        )
        self._status_lbl.pack(side="right")

        # ── Counter display ──
        counter_frame = tk.Frame(self, bg=COLORS["panel"],
                                 highlightbackground=COLORS["border"],
                                 highlightthickness=1)
        counter_frame.pack(fill="x", padx=24, pady=(0, 12))

        inner = tk.Frame(counter_frame, bg=COLORS["panel"], pady=18)
        inner.pack()

        tk.Label(
            inner, text="COUNT", bg=COLORS["panel"], fg=COLORS["muted"],
            font=("Courier New", 9, "bold"), pady=0
        ).pack()

        self._counter_var = tk.StringVar(value="000,000,000,000")
        tk.Label(
            inner, textvariable=self._counter_var,
            bg=COLORS["panel"], fg=COLORS["accent"],
            font=("Courier New", 36, "bold")
        ).pack()

        self._progress = ttk.Progressbar(
            inner, length=W - 80, mode="determinate",
            style="Anomaly.Horizontal.TProgressbar"
        )
        self._progress.pack(pady=(8, 4))

        self._pct_var = tk.StringVar(value="0.000000%  of  1,000,000,000")
        tk.Label(
            inner, textvariable=self._pct_var,
            bg=COLORS["panel"], fg=COLORS["muted"],
            font=("Courier New", 9)
        ).pack()

        # Style progress bar
        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            "Anomaly.Horizontal.TProgressbar",
            troughcolor=COLORS["border"],
            background=COLORS["accent"],
            bordercolor=COLORS["panel"],
            lightcolor=COLORS["accent"],
            darkcolor=COLORS["accent"],
        )

        # ── Metrics row ──
        metrics_frame = tk.Frame(self, bg=COLORS["bg"])
        metrics_frame.pack(fill="x", padx=24, pady=(0, 12))

        self._metric_widgets = {}
        metric_defs = [
            ("CPU",  "CPU",     COLORS["cpu"]),
            ("MEM",  "MEMORY",  COLORS["memory"]),
            ("DISK", "DISK",    COLORS["disk"]),
            ("NET↑", "NETWORK", COLORS["network"]),
        ]
        for label, key, color in metric_defs:
            box = tk.Frame(
                metrics_frame, bg=COLORS["panel"],
                highlightbackground=COLORS["border"], highlightthickness=1
            )
            box.pack(side="left", expand=True, fill="x", padx=(0, 8))

            tk.Label(box, text=label, bg=COLORS["panel"],
                     fg=color, font=("Courier New", 9, "bold"), pady=6
                     ).pack()
            val_lbl = tk.Label(box, text="0%", bg=COLORS["panel"],
                               fg=COLORS["text"], font=("Courier New", 16, "bold"))
            val_lbl.pack(pady=(0, 6))
            self._metric_widgets[key] = val_lbl

        # ── Spike controls ──
        ctrl_frame = tk.Frame(self, bg=COLORS["bg"])
        ctrl_frame.pack(fill="x", padx=24, pady=(0, 12))

        btn_cfg = dict(font=("Courier New", 10, "bold"), relief="flat",
                       cursor="hand2", padx=12, pady=8, bd=0)

        self._start_btn = tk.Button(
            ctrl_frame, text="▶  START COUNTER",
            bg=COLORS["accent"], fg="#000000",
            command=self._toggle_counter, **btn_cfg
        )
        self._start_btn.pack(side="left", padx=(0, 8))

        tk.Label(ctrl_frame, text="MANUAL SPIKES:",
                 bg=COLORS["bg"], fg=COLORS["muted"],
                 font=("Courier New", 9)).pack(side="left", padx=(8, 6))

        spike_colors_map = {
            "CPU":     (COLORS["cpu"],     "#000"),
            "MEMORY":  (COLORS["memory"],  "#fff"),
            "DISK":    (COLORS["disk"],    "#000"),
            "NETWORK": (COLORS["network"], "#000"),
        }
        for stype, (bg, fg) in spike_colors_map.items():
            tk.Button(
                ctrl_frame, text=stype,
                bg=bg, fg=fg,
                command=lambda s=stype: self._fire_spike(s),
                **btn_cfg
            ).pack(side="left", padx=(0, 6))

        # Auto-spike toggle
        self._auto_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            ctrl_frame, text="AUTO SPIKE",
            variable=self._auto_var,
            bg=COLORS["bg"], fg=COLORS["accent2"],
            selectcolor=COLORS["panel"],
            activebackground=COLORS["bg"],
            activeforeground=COLORS["accent2"],
            font=("Courier New", 9, "bold"),
            command=self._toggle_auto,
            cursor="hand2"
        ).pack(side="right")

        # ── Active spikes indicator ──
        self._spike_banner_frame = tk.Frame(self, bg=COLORS["bg"])
        self._spike_banner_frame.pack(fill="x", padx=24, pady=(0, 6))

        self._spike_banner_inner = tk.Frame(self._spike_banner_frame, bg=COLORS["bg"])
        self._spike_banner_inner.pack(side="left")

        tk.Label(self._spike_banner_frame, text="ACTIVE:",
                 bg=COLORS["bg"], fg=COLORS["muted"],
                 font=("Courier New", 9)).pack(side="left", padx=(0, 6))

        # ── Event log ──
        log_frame = tk.Frame(self, bg=COLORS["panel"],
                             highlightbackground=COLORS["border"],
                             highlightthickness=1)
        log_frame.pack(fill="both", padx=24, pady=(0, 16), expand=True)

        tk.Label(log_frame, text="EVENT LOG",
                 bg=COLORS["panel"], fg=COLORS["muted"],
                 font=("Courier New", 8, "bold"), anchor="w", padx=12, pady=6
                 ).pack(fill="x")

        self._log_text = tk.Text(
            log_frame, bg=COLORS["panel"], fg=COLORS["text"],
            font=("Courier New", 9), height=8, state="disabled",
            relief="flat", borderwidth=0, padx=10, pady=4,
            insertbackground=COLORS["accent"],
        )
        self._log_text.pack(fill="both", padx=2, pady=(0, 6), expand=True)

        # Tag colors for log
        for stype, color in SPIKE_COLORS.items():
            self._log_text.tag_config(stype, foreground=color)
        self._log_text.tag_config("INFO", foreground=COLORS["muted"])
        self._log_text.tag_config("START", foreground=COLORS["accent"])

        self._log("System initialised — ready.", "INFO")

    # ── LOGGING ──────────────────────────────────────────────────────────────

    def _log(self, msg, tag="INFO"):
        ts = time.strftime("%H:%M:%S")
        line = f"[{ts}]  {msg}\n"
        self._log_text.config(state="normal")
        self._log_text.insert("end", line, tag)
        self._log_text.see("end")
        self._log_text.config(state="disabled")

    # ── COUNTER ──────────────────────────────────────────────────────────────

    def _toggle_counter(self):
        if not self._running:
            self._running = True
            self._start_btn.config(text="■  STOP COUNTER",
                                   bg=COLORS["danger"], fg="#ffffff")
            self._status_dot.config(fg=COLORS["accent"])
            self._status_lbl.config(fg=COLORS["accent"], text="RUNNING")
            self._count_thread = threading.Thread(
                target=self._count_loop, daemon=True)
            self._count_thread.start()
            self._log("Counter started → target 1,000,000,000", "START")
        else:
            self._running = False
            self._start_btn.config(text="▶  START COUNTER",
                                   bg=COLORS["accent"], fg="#000000")
            self._status_dot.config(fg=COLORS["muted"])
            self._status_lbl.config(fg=COLORS["muted"], text="IDLE")
            self._log("Counter paused.", "INFO")

    def _count_loop(self):
        """Count in large batches on a background thread; update UI every ~100 ms."""
        BATCH = 500_000        # increments per tight loop
        UPDATE_EVERY = 50      # batches between UI refreshes (~100 ms at batch speed)
        batch_count = 0
        while self._running and self._counter < COUNT_TARGET:
            end = min(self._counter + BATCH, COUNT_TARGET)
            # tight numeric loop — causes mild consistent CPU usage (intentional)
            c = self._counter
            while c < end:
                c += 1
            self._counter = c
            batch_count += 1
            if batch_count >= UPDATE_EVERY:
                batch_count = 0
                self.after(0, self._update_counter_ui)
                time.sleep(0.001)    # yield briefly

        self.after(0, self._update_counter_ui)
        if self._counter >= COUNT_TARGET:
            self.after(0, self._on_complete)

    def _update_counter_ui(self):
        n = self._counter
        self._counter_var.set(f"{n:,}")
        pct = n / COUNT_TARGET * 100
        self._progress["value"] = pct
        self._pct_var.set(f"{pct:.6f}%  of  1,000,000,000")

    def _on_complete(self):
        self._running = False
        self._start_btn.config(text="▶  RESTART",
                               bg=COLORS["accent"], fg="#000000")
        self._counter = 0
        self._status_dot.config(fg=COLORS["muted"])
        self._status_lbl.config(fg=COLORS["muted"], text="DONE")
        self._log("🎉 Reached 1,000,000,000! Counter reset.", "START")

    # ── SPIKES ───────────────────────────────────────────────────────────────

    def _fire_spike(self, stype):
        self._log(f"SPIKE ▶ {stype} triggered", stype)
        SPIKE_FUNCS[stype]()
        self._show_active_badge(stype)
        duration = {"CPU": 3, "MEMORY": 4, "DISK": 3, "NETWORK": 4}.get(stype, 3)
        self.after(int(duration * 1000) + 500,
                   lambda: self._hide_active_badge(stype))

    def _show_active_badge(self, stype):
        if stype in self._active_spikes:
            return
        color = SPIKE_COLORS[stype]
        badge = tk.Label(
            self._spike_banner_inner,
            text=f" {stype} ",
            bg=color, fg="#000000",
            font=("Courier New", 8, "bold"),
            padx=4, pady=2
        )
        badge.pack(side="left", padx=(0, 4))
        self._active_spikes[stype] = badge

    def _hide_active_badge(self, stype):
        badge = self._active_spikes.pop(stype, None)
        if badge:
            badge.destroy()

    # ── AUTO SPIKE ───────────────────────────────────────────────────────────

    def _toggle_auto(self):
        if self._auto_var.get():
            self._log("Auto-spike mode ENABLED", "INFO")
            self._auto_thread = threading.Thread(
                target=self._auto_spike_loop, daemon=True)
            self._auto_thread.start()
        else:
            self._log("Auto-spike mode DISABLED", "INFO")

    def _auto_spike_loop(self):
        while self._auto_var.get():
            wait = random.uniform(*SPIKE_INTERVAL)
            time.sleep(wait)
            if not self._auto_var.get():
                break
            stype = random.choice(SPIKE_TYPES)
            self.after(0, lambda s=stype: self._fire_spike(s))

    # ── LIVE METRICS ─────────────────────────────────────────────────────────

    def _refresh_metrics(self):
        try:
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory().percent
            disk = psutil.disk_io_counters()
            net  = psutil.net_io_counters()

            self._metric_widgets["CPU"].config(text=f"{cpu:.1f}%")
            self._metric_widgets["MEMORY"].config(text=f"{mem:.1f}%")

            # Disk: show read+write MB/s by sampling delta
            if not hasattr(self, "_last_disk"):
                self._last_disk = (disk.read_bytes + disk.write_bytes, time.time())
                disk_rate = 0.0
            else:
                prev_bytes, prev_t = self._last_disk
                now_bytes = disk.read_bytes + disk.write_bytes
                dt = time.time() - prev_t
                disk_rate = (now_bytes - prev_bytes) / (1024 * 1024 * max(dt, 0.001))
                self._last_disk = (now_bytes, time.time())
            self._metric_widgets["DISK"].config(text=f"{disk_rate:.1f} MB/s")

            # Network: bytes sent/s
            if not hasattr(self, "_last_net"):
                self._last_net = (net.bytes_sent + net.bytes_recv, time.time())
                net_rate = 0.0
            else:
                prev_bytes, prev_t = self._last_net
                now_bytes = net.bytes_sent + net.bytes_recv
                dt = time.time() - prev_t
                net_rate = (now_bytes - prev_bytes) / (1024 * max(dt, 0.001))
                self._last_net = (now_bytes, time.time())
            self._metric_widgets["NETWORK"].config(
                text=f"{net_rate:.1f} KB/s")
        except Exception:
            pass

        self._metrics_after = self.after(1000, self._refresh_metrics)

    # ── CLOSE ─────────────────────────────────────────────────────────────────

    def _on_close(self):
        self._running = False
        if self._metrics_after:
            self.after_cancel(self._metrics_after)
        self.destroy()


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Initialise psutil CPU percent baseline (first call always returns 0)
    psutil.cpu_percent(interval=None)

    app = AnomalyApp()
    app.mainloop()
