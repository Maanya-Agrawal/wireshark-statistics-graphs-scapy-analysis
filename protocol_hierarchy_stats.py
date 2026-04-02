from scapy.all import *

# Load the caoture file
packets = rdpcap("exp7capture.pcap")   

total_packets = len(packets)
total_bytes = 0
header_bytes = 0

for pkt in packets:
    total_bytes += len(pkt)

    # Calculate IP header size
    if pkt.haslayer(IP):
        header_bytes += pkt[IP].ihl * 4

    # Calculate TCP header size
    if pkt.haslayer(TCP):
        header_bytes += pkt[TCP].dataofs * 4

    # Calculate UDP header size (fixed 8 bytes)
    if pkt.haslayer(UDP):
        header_bytes += 8

# Data size = Total size - Header size
data_bytes = total_bytes - header_bytes

print("\n--- Protocol Hierarchy Statistics (Using Scapy) ---")
print("Total number of packets:", total_packets)
print("Total size of data (bytes):", data_bytes)
print("Total size of headers (bytes):", header_bytes)

