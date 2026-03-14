from scapy.all import sniff
import time

flow = {
    "start_time": None,
    "end_time": None,
    "fwd_packets": 0,
    "bwd_packets": 0,
    "fwd_bytes": 0,
    "bwd_bytes": 0,
    "packet_sizes": []
}


SRC_IP = None   # will set after first packet


def process_packet(pkt):
    global flow, SRC_IP

    if not pkt.haslayer("IP"):
        return

    size = len(pkt)

    if flow["start_time"] is None:
        flow["start_time"] = time.time()
        SRC_IP = pkt["IP"].src

    flow["end_time"] = time.time()

    src = pkt["IP"].src

    if src == SRC_IP:
        flow["fwd_packets"] += 1
        flow["fwd_bytes"] += size
    else:
        flow["bwd_packets"] += 1
        flow["bwd_bytes"] += size

    flow["packet_sizes"].append(size)


def compute_features():

    duration = flow["end_time"] - flow["start_time"]

    total_packets = flow["fwd_packets"] + flow["bwd_packets"]
    total_bytes = flow["fwd_bytes"] + flow["bwd_bytes"]

    fwd_mean = 0
    bwd_mean = 0

    if flow["fwd_packets"] > 0:
        fwd_mean = flow["fwd_bytes"] / flow["fwd_packets"]

    if flow["bwd_packets"] > 0:
        bwd_mean = flow["bwd_bytes"] / flow["bwd_packets"]

    avg_packet = 0
    if total_packets > 0:
        avg_packet = total_bytes / total_packets

    bytes_per_sec = 0
    packets_per_sec = 0

    if duration > 0:
        bytes_per_sec = total_bytes / duration
        packets_per_sec = total_packets / duration

    features = [
        duration,
        flow["fwd_packets"],
        flow["bwd_packets"],
        flow["fwd_bytes"],
        flow["bwd_bytes"],
        fwd_mean,
        bwd_mean,
        bytes_per_sec,
        packets_per_sec,
        avg_packet
    ]

    names = [
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Total Length of Fwd Packets",
        "Total Length of Bwd Packets",
        "Fwd Packet Length Mean",
        "Bwd Packet Length Mean",
        "Flow Bytes/s",
        "Flow Packets/s",
        "Average Packet Size"
    ]

    print("\nFeatures:\n")
    for n, v in zip(names, features):
        print(n, ":", v)

    return features


print("Sniffing 20 packets...")

sniff(prn=process_packet, count=20)

compute_features()