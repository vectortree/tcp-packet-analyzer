# CSE310-Programming-Assignment-2
# Starr Xu

Instructions:
When you first start the program, it should prompt you to input a PCAP file.

*EXAMPLE*
Please input a PCAP file for analysis: assignment2.pcap
*END OF EXAMPLE*

The first two lines of the output should display the number of TCP segments and flows.

Here is the general format of the output for a single TCP flow:

*FORMAT*
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
*END OF FORMAT*

Summary:

~Part A~
The number of TCP flows (initiated from the sender) was obtained by counting the number of SYNs
sent by the sender.
Assumption: Every flow starts with a SYN and ends with a FIN.
(a) No explanation needed.
(b) Only complete transactions (i.e., sender -> receiver and receiver -> sender) are included!
    Assumptions: A transaction is a pair of packets (i.e., sender -> receiver and receiver -> sender)
    such that the second packet is an ACK of the first. The first transaction is considered as the
    first packet pair (after the TCP connection establishment) that contains a payload (from sender to
    receiver). FINs are not included in transactions. An ACK is said to be piggy-backed if it contains a payload.
(c) The following formula was used to calculate the sender throughput (approximately):
    Sender Throughput = Sender bytes / Sender time span.
    With respect to each TCP flow:
    Sender bytes is the total number of bytes (TCP header + payload) sent by the sender to the receiver.
    Sender time span = Timestamp of last TCP packet sent by sender - Timestamp of first TCP packet sent
    by sender.

~Part B~
(1) The first three congestion window sizes were estimated by counting the number of packets in the first
    three RTT windows. The three initial congestion window sizes (roughly) double for each window
    (i.e., it grows exponentially).
    RTT was estimated at the sender using the initial RTT = Timestamp of first ACK - Timestamp of first
    SYN (w.r.t. each TCP flow).
(2) The number of retransmissions due to triple duplicate ACK (i.e., fast retransmissions) was
    obtained by getting the triple duplicate ACKs sent by the receiver and identifying the ones
    with a corresponding retransmission that is not due to timeout.
    Number of retransmissions due to timeout = Total number of retransmissions - Number of fast
    retransmissions.
    
    
    

