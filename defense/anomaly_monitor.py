import psutil
import time
import numpy as np

WINDOW = 10

cpu_hist = []
ram_hist = []
disk_hist = []
net_hist = []

prev_cpu = None
prev_ram = None
prev_disk = None
prev_net = None

prev_time = None


def slope(curr, prev, dt):

    if prev is None or dt == 0:
        return 0

    return (curr - prev) / dt


def probability(value, mean, std):

    if std == 0:
        return 0

    z = abs(value - mean) / std

    p = min(1, z / 3)

    return p


def check(metric_hist, value, name):

    if len(metric_hist) < WINDOW:
        metric_hist.append(value)
        return

    mean = np.mean(metric_hist)
    std = np.std(metric_hist)

    p = probability(value, mean, std)

    anomaly = 1 if p > 0.7 else 0

    print(name, "=", value,
          " anomaly =", anomaly,
          " prob =", round(p * 100, 2), "%")

    metric_hist.pop(0)
    metric_hist.append(value)


def run():

    global prev_cpu, prev_ram, prev_disk, prev_net, prev_time

    print("Time based anomaly monitor running")

    while True:

        curr_time = time.time()

        if prev_time is None:
            prev_time = curr_time
            time.sleep(1)
            continue

        dt = curr_time - prev_time

        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent
        disk = psutil.disk_usage("/").percent
        net = psutil.net_io_counters().bytes_sent

        cpu_s = slope(cpu, prev_cpu, dt)
        ram_s = slope(ram, prev_ram, dt)
        disk_s = slope(disk, prev_disk, dt)
        net_s = slope(net, prev_net, dt)

        check(cpu_hist, cpu_s, "CPU")
        check(ram_hist, ram_s, "RAM")
        check(disk_hist, disk_s, "DISK")
        check(net_hist, net_s, "NET")

        prev_cpu = cpu
        prev_ram = ram
        prev_disk = disk
        prev_net = net

        prev_time = curr_time

        time.sleep(1)


if __name__ == "__main__":
    run()