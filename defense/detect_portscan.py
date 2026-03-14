from scapy.all import sniff, TCP, IP
from collections import defaultdict
from datetime import datetime
import time

# track how many ports each IP has touched
port_hits = defaultdict(set)
alert_times = defaultdict(float)

THRESHOLD = 15      # ports hit
TIME_WINDOW = 5     # seconds
COOLDOWN = 30       # seconds before re-alerting same IP

def alert(ip, ports):
    print(f"\n{'!'*50}")
    print(f"  SCAN DETECTED at {datetime.now().strftime('%H:%M:%S')}")
    print(f"  Attacker IP : {ip}")
    print(f"  Ports hit   : {sorted(ports)}")
    print(f"  Total ports : {len(ports)}")
    print(f"{'!'*50}\n")

def process_packet(packet):
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        now = time.time()

        port_hits[src_ip].add((dst_port, round(now)))

        # only count hits within last TIME_WINDOW seconds
        recent = {p for p, t in port_hits[src_ip] if now - t <= TIME_WINDOW}
        port_hits[src_ip] = {(p, t) for p, t in port_hits[src_ip] if now - t <= TIME_WINDOW}

        if len(recent) >= THRESHOLD:
            if now - alert_times[src_ip] > COOLDOWN:
                alert_times[src_ip] = now
                alert(src_ip, recent)

print("[*] Watching for port scans... (Ctrl+C to stop)\n")
sniff(filter="tcp", prn=process_packet, store=False)