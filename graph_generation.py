from scapy.all import rdpcap
import matplotlib.pyplot as plt
from collections import defaultdict
import datetime

# Load capture file
packets = rdpcap("exp7capture.pcap")

def plot_graph(filter_func, title):
    time_dict = defaultdict(int)

    for pkt in packets:
        if filter_func(pkt):
            time_sec = int(pkt.time)
            time_dict[time_sec] += 1

    times = sorted(time_dict.keys())
    counts = [time_dict[t] for t in times]

    plt.figure()
    plt.plot(times, counts)
    plt.title(title)
    plt.xlabel("Time (seconds)")
    plt.ylabel("Packets")
    plt.show()

# 1 Total traffic
plot_graph(lambda p: True, "Total Traffic")

# 2 TCP
plot_graph(lambda p: p.haslayer("TCP"), "TCP Traffic")

# 3 UDP
plot_graph(lambda p: p.haslayer("UDP"), "UDP Traffic")

# 4 DNS
plot_graph(lambda p: p.haslayer("DNS"), "DNS Traffic")

# 5 HTTP/TLS
plot_graph(lambda p: p.haslayer("TCP"), "HTTP/HTTPS (Approx via TCP)")

