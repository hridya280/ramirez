import psutil
import time
from scapy.all import get_if_addr, conf

def get_system_usage():
    # 1. CPU Usage
    cpu_percent = psutil.cpu_percent(interval=1)

    # 2. Memory (RAM) Usage
    memory = psutil.virtual_memory()
    mem_used = memory.percent

    # 3. Disk Usage
    disk = psutil.disk_usage('/')
    disk_used = disk.percent

    # 4. WiFi/Network Usage
    # This tracks bytes sent/received since the last check
    net_before = psutil.net_io_counters(pernic=True)
    time.sleep(1) # Gap to calculate rate
    net_after = psutil.net_io_counters(pernic=True)

    # Automatically detect your WiFi interface (common names: 'Wi-Fi', 'wlan0', 'en0')
    wifi_iface = None
    for iface in psutil.net_if_addrs():
        if "wifi" in iface.lower() or "wlan" in iface.lower():
            wifi_iface = iface
            break
    
    # Fallback to default if WiFi name isn't standard
    if not wifi_iface:
        wifi_iface = list(net_after.keys())[0]

    stats_before = net_before[wifi_iface]
    stats_after = net_after[wifi_iface]

    # Calculate Speed (KB/s)
    upload_speed = (stats_after.bytes_sent - stats_before.bytes_sent) / 1024
    download_speed = (stats_after.bytes_recv - stats_before.bytes_recv) / 1024

    # Print Results
    print("-" * 30)
    print(f"💻 CPU Usage:    {cpu_percent}%")
    print(f"🧠 RAM Usage:    {mem_used}%")
    print(f"💽 Disk Usage:   {disk_used}%")
    print(f"📡 Interface:    {wifi_iface}")
    print(f"   ⬆️ Upload:    {upload_speed:.2f} KB/s")
    print(f"   ⬇️ Download:  {download_speed:.2f} KB/s")
    print("-" * 30)

if __name__ == "__main__":
    try:
        print("Monitoring System... (Press Ctrl+C to stop)")
        while True:
            get_system_usage()
    except KeyboardInterrupt:
        print("\nStopped.")