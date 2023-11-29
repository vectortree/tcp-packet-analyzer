# TCP Packet Analyzer

This is a Python program that analyzes TCP packets. It was created as an assignment for my computer networking course (Fall 2021).

## Instructions

When you first start the program, it should prompt you to input a PCAP file.

```
Please input a PCAP file for analysis: tcp-packet.pcap
```

The first two lines of the output should display the number of TCP segments and flows.

Here is the general format of the output for a single TCP flow:

```
Source port, Source IP address, Destination port, Destination IP address
TRANSACTION 1
(SENDER TO RECEIVER) Sequence number, Acknowledgement number, Receive window size
(RECEIVER TO SENDER) Sequence number, Acknowledgement number, Receive window size
TRANSACTION 2
(SENDER TO RECEIVER) Sequence number, Acknowledgement number, Receive window size
(RECEIVER TO SENDER) Sequence number, Acknowledgement number, Receive window size
Sender bytes
Sender time span
Sender throughput
Congestion window sizes (in packets/RTT)
Number of retransmissions due to triple duplicate ACK
Number of retransmissions due to timeout
```
