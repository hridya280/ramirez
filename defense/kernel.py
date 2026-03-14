import wmi
import datetime
from difflib import SequenceMatcher

print("[+] Starting Process Monitor...\n")

# Load suspicious list
with open("data/suspicious_processes.txt", "r") as f:
    suspicious_list = [line.strip().lower() for line in f if line.strip()]

# Load whitelist
with open("data/common_processes.txt", "r") as f:
    common_list = [line.strip().lower() for line in f if line.strip()]

print(f"[+] Loaded {len(suspicious_list)} suspicious signatures")
print(f"[+] Loaded {len(common_list)} common processes\n")

c = wmi.WMI()
process_watcher = c.Win32_ProcessStartTrace.watch_for()

def similar(a, b):
    return SequenceMatcher(None, a, b).ratio()

while True:
    try:
        new_process = process_watcher()

        process_name = new_process.ProcessName.lower()
        pid = new_process.ProcessID
        parent_pid = new_process.ParentProcessID

        # Ignore common processes
        if process_name in common_list:
            continue

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        print("===================================")
        print(f"[{timestamp}] Process Detected")
        print(f"Process Name : {process_name}")
        print(f"PID          : {pid}")
        print(f"Parent PID   : {parent_pid}")

        suspicious = False

        for bad in suspicious_list:

            if process_name == bad:
                suspicious = True
                break

            if similar(process_name, bad) > 0.8:
                suspicious = True
                break

        if suspicious:
            print("🚨 ALERT: Suspicious process detected!")
        else:
            print("⚠ Unknown process detected")

        print("===================================\n")

    except KeyboardInterrupt:
        print("\n[+] Monitor stopped.")
        break

    except Exception as e:
        print("[ERROR]", e)