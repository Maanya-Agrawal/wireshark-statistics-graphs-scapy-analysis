from scapy.all import *
from collections import defaultdict
import numpy as np

packets = rdpcap("exp7capture.pcap")

# Dictionary format:
# (src, dst, protocol) -> bytes, packets, times
conversations = defaultdict(lambda: {
    "bytes": 0,
    "packets": 0,
    "times": []
})

# Collect conversation statistics
for pkt in packets:
    if pkt.haslayer(IP):

        src = pkt[IP].src
        dst = pkt[IP].dst

        # Detect protocol
        if pkt.haslayer(TCP):
            proto = "TCP"
        elif pkt.haslayer(UDP):
            proto = "UDP"
        elif pkt.haslayer(ICMP):
            proto = "ICMP"
        else:
            proto = "Other"

        key = (src, dst, proto)

        conversations[key]["bytes"] += len(pkt)
        conversations[key]["packets"] += 1

        conversations[key]["times"].append(float(pkt.time))
print("Conversation Analysis")

#Unique address pair with maximum bytes
max_pair = max(conversations.items(), key=lambda x: x[1]["bytes"])

print("\nAddress pair with maximum bytes:")
print("Source:", max_pair[0][0])
print("Destination:", max_pair[0][1])
print("Protocol:", max_pair[0][2])
print("Maximum bytes transferred:", max_pair[1]["bytes"])

#Average inter-packet time difference
print("\nAverage Inter-Packet Time Difference:")

for key, data in conversations.items():
    times = sorted(data["times"])

    if len(times) > 1:
        diffs = np.diff(times)
        avg_time = float(np.mean(diffs))

        print(f"{key[0]} -> {key[1]} ({key[2]}) : {avg_time:.6f} seconds")
#Total packets between every pair and protocol
print("\nTotal Packets Between Each Pair and Protocol:")

for key, data in conversations.items():
    print(f"{key[0]} -> {key[1]} ({key[2]}) : {data['packets']} packets")

