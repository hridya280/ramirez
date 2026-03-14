import win32evtlog
import time

server = "localhost"
logtype = "Security"

hand = win32evtlog.OpenEventLog(server, logtype)

flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

last = 0

print("Monitoring commands...\n")

while True:

    events = win32evtlog.ReadEventLog(hand, flags, 0)

    if events:

        for ev in events:

            if ev.EventID != 4688:
                continue

            if ev.RecordNumber <= last:
                continue

            last = ev.RecordNumber

            data = ev.StringInserts

            if not data:
                continue

            try:
                process = data[5]
                cmd = data[8]
            except:
                process = str(data)
                cmd = ""

            print("PROCESS:", process)
            print("CMD:", cmd)
            print("-" * 50)

    time.sleep(1)