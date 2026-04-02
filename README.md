# Wireshark Statistics and Graphs Analysis

## Description

This project demonstrates network traffic analysis using Wireshark and Scapy. Packet capture data is processed to generate traffic graphs, protocol statistics, and conversation analysis. The results help in understanding traffic patterns, protocol behavior, and communication between devices.

## Objectives

* To analyze network traffic using Wireshark statistics tools
* To generate graphs for different protocols (TCP, UDP, DNS, HTTP/HTTPS)
* To extract protocol hierarchy statistics
* To analyze communication between devices using Scapy

## Technologies Used

* Wireshark
* Python (Scapy, Matplotlib, NumPy)

## Files Included

* `graph_generation.py`
  Generates traffic graphs (Total, TCP, UDP, DNS, HTTP/HTTPS)

* `protocol_hierarchy_stats.py`
  Calculates total packets, data size, and header size

* `conversations_stats.py`
  Analyzes communication between IP pairs, including packet counts and time differences

* `capture.pcap`
  Network packet capture file used for analysis

* `protocol_hierarchy.csv`
  Exported protocol hierarchy data from Wireshark

* `conversations.csv`
  Exported conversation data from Wireshark

## How to Run

1. Place all files in the same directory
2. Run each script:

```
python3 graph_generation.py
python3 protocol_hierarchy_stats.py
python3 conversations_stats.py
```

3. View:

* Graphs generated using Matplotlib
* Output printed in terminal

## Conclusion

The experiment demonstrates how Wireshark and Scapy can be used together to analyze network traffic. Graph visualization and statistical analysis provide insights into protocol behavior and communication patterns between devices.

## Author

Maanya Agrawal

