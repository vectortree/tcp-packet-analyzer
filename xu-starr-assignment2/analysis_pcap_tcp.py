import dpkt
import socket


def get_retransmissions(p):
    retransmissions = {}
    sequence = 0
    if len(p) > 0:
        sequence = p[0][1].seq
    for y in p:
        if sequence > y[1].seq:
            retransmissions[y[1]] = 1
        else:
            sequence = y[1].seq
    return retransmissions


def first_n_cwnds(filtered, rtt, n):
    cwnds = []
    flag = True
    initial_ts = 0
    cwnd = 0
    for y in filtered:
        if n == 0:
            break
        if len(y[1].data) > 0:
            if flag:
                initial_ts = y[2]
                flag = False
            if rtt >= y[2] - initial_ts:
                cwnd += 1
            else:
                cwnds.append(cwnd)
                initial_ts = y[2]
                cwnd = 1
                n -= 1
    return cwnds


def get_triple_dupacks_retransmissions(p, t):
    # According to Wireshark:
    # A segment is a duplicate ack if window/seq/ack is the same as the previous
    # segment and if the segment length is 0
    dupack_freq_dict = {}
    dupack_dict = {}
    triple_dupack_retransmissions = {}
    for y in p:
        if len(y[1].data) == 0:
            pair = (y[1].seq, y[1].ack)
            if pair not in dupack_freq_dict:
                dupack_freq_dict[pair] = 0
            else:
                dupack_freq_dict[pair] += 1
                dupack_dict[y[1]] = 1

    for k in range(len(t) - 1):
        seg1 = t[k][1]
        seg2 = t[k + 1][1]
        first_pair = (seg1.seq, seg1.ack)
        second_pair = (seg2.ack, seg2.seq)
        if first_pair == second_pair and \
                seg1 in dupack_dict and \
                first_pair in dupack_freq_dict and \
                dupack_freq_dict[first_pair] >= 3:
            triple_dupack_retransmissions[seg2] = 1
    return triple_dupack_retransmissions


def tcp_equality_tester(tcp_flow, sport, src, dport, dst):
    return tcp_flow[0] == sport and tcp_flow[1] == src and tcp_flow[2] == dport and tcp_flow[3] == dst


def collect_first_n_segments(tcp_flow, s, n, b):
    r = {}
    c = 0
    window_size_scaling_factor = 0
    for y in s:
        if c == n:
            break
        if b:
            if y[0] == tcp_flow:
                if y[1].flags & dpkt.tcp.TH_SYN:
                    tuples = dpkt.tcp.parse_opts(y[1].opts)
                    for option, data in tuples:
                        if option == dpkt.tcp.TCP_OPT_WSCALE:
                            window_size_scaling_factor = 2 ** int.from_bytes(data, "big")
                if (y[1].flags & dpkt.tcp.TH_ACK) and len(y[1].data) > 0 and not \
                        (y[1].flags & dpkt.tcp.TH_FIN):
                    r[(y[1].seq, y[1].ack, window_size_scaling_factor * y[1].win)] = 1
                    c += 1
        else:
            if y[0] == tcp_flow:
                if y[1].flags & dpkt.tcp.TH_SYN:
                    tuples = dpkt.tcp.parse_opts(y[1].opts)
                    for option, data in tuples:
                        if option == dpkt.tcp.TCP_OPT_WSCALE:
                            window_size_scaling_factor = 2 ** int.from_bytes(data, "big")
                if (y[1].flags & dpkt.tcp.TH_ACK) and not (y[1].flags & dpkt.tcp.TH_SYN) and not \
                        (y[1].flags & dpkt.tcp.TH_FIN):
                    r[(y[1].seq, y[1].ack, window_size_scaling_factor * y[1].win)] = 1
                    c += 1
    return r


senderAddress = '130.245.145.12'
receiverAddress = '128.208.2.198'
NUMBER_OF_TRANSACTIONS_TO_PRINT = 2
fileName = input('Please input a PCAP file for analysis: ')
while 1:
    try:
        file = open(fileName, 'rb')
        break
    except FileNotFoundError as error:
        print(error)
        fileName = input('Please input a PCAP file for analysis: ')
pcap = dpkt.pcap.Reader(file)
numberOfTcpSegments = 0
tcpFlows = []
tcpSrcToDstSegments = []
tcpDstToSrcSegments = []
tcpSegments = []
for timestamp, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)
    # Filtering for IP datagrams
    if not isinstance(eth.data, dpkt.ip.IP):
        continue
    ip = eth.data
    # Filtering for TCP segments
    if ip.p != dpkt.ip.IP_PROTO_TCP:
        continue
    tcp = ip.data
    numberOfTcpSegments += 1
    if (tcp.flags & dpkt.tcp.TH_SYN) and not (tcp.flags & dpkt.tcp.TH_ACK):
        tcpFlow = [tcp.sport, ip.src, tcp.dport, ip.dst]
        tcpFlows.append(tcpFlow)
    for tcpFlow in tcpFlows:
        if tcp_equality_tester(tcpFlow, tcp.sport, ip.src, tcp.dport, ip.dst) or \
                tcp_equality_tester(tcpFlow, tcp.dport, ip.dst, tcp.sport, ip.src):
            tcpSegments.append([tcpFlow, tcp, timestamp])
        if tcp_equality_tester(tcpFlow, tcp.sport, ip.src, tcp.dport, ip.dst):
            tcpSrcToDstSegments.append([tcpFlow, tcp, timestamp])
        elif tcp_equality_tester(tcpFlow, tcp.dport, ip.dst, tcp.sport, ip.src):
            tcpDstToSrcSegments.append([tcpFlow, tcp, timestamp])
print('\nNumber of TCP segments: ' + str(numberOfTcpSegments))
print('Number of TCP flows: ' + str(len(tcpFlows)) + '\n')
for tcpFlow in tcpFlows:
    print('Source port: ' + str(tcpFlow[0]) +
          ', Source IP address: ' + socket.inet_ntoa(tcpFlow[1]) +
          ', Destination port: ' + str(tcpFlow[2]) +
          ', Destination IP address: ' + socket.inet_ntoa(tcpFlow[3]))
    # Print first two TCP transactions for each TCP flow
    tcpSrcToDstTransactions = collect_first_n_segments(tcpFlow,
                                                       tcpSrcToDstSegments,
                                                       NUMBER_OF_TRANSACTIONS_TO_PRINT,
                                                       True)
    tcpDstToSrcTransactions = collect_first_n_segments(tcpFlow,
                                                       tcpDstToSrcSegments,
                                                       NUMBER_OF_TRANSACTIONS_TO_PRINT,
                                                       False)
    # Only include complete transactions (i.e., sender -> receiver and receiver -> sender)
    i = 0
    for seq1, ack1, rwnd1 in tcpSrcToDstTransactions:
        if i == NUMBER_OF_TRANSACTIONS_TO_PRINT:
            break
        for seq2, ack2, rwnd2 in tcpDstToSrcTransactions:
            if ack1 == seq2:
                print('TRANSACTION ' + str(i + 1))
                print('(SENDER TO RECEIVER) Sequence number: ' + str(seq1) +
                      ', Acknowledgement number: ' + str(ack1) +
                      ', Receive window size: ' + str(rwnd1))
                print('(RECEIVER TO SENDER) Sequence number: ' + str(seq2) +
                      ', Acknowledgement number: ' + str(ack2) +
                      ', Receive window size: ' + str(rwnd2))
                tcpDstToSrcTransactions.pop((seq2, ack2, rwnd2), None)
                i += 1
                break

    # Print sender throughput (bytes per second) for each TCP flow
    number_of_bytes = 0
    filteredSrcToDst = []
    for x in tcpSrcToDstSegments:
        if x[0] == tcpFlow:
            filteredSrcToDst.append(x)
            number_of_bytes += len(x[1])
    if len(filteredSrcToDst) > 1:
        start_ts = filteredSrcToDst[0][2]
        end_ts = filteredSrcToDst[-1][2]
        time_span = end_ts - start_ts
        print('Sender bytes: ' + str(number_of_bytes) + ' bytes')
        print('Sender time span: ' + str(time_span) + ' seconds')
        if time_span > 0:
            print('Sender throughput: ' + str(number_of_bytes / time_span) + ' bytes/second')
    else:
        print('Sender bytes: ' + str(number_of_bytes) + ' bytes')
        print('Error: Could not calculate throughput')

    filteredDstToSrc = []
    for x in tcpDstToSrcSegments:
        if x[0] == tcpFlow:
            filteredDstToSrc.append(x)

    filteredSegments = []
    for x in tcpSegments:
        if x[0] == tcpFlow:
            filteredSegments.append(x)

    # Print the first 3 congestion window sizes (estimated at the sender)
    # One RTT is approximated by the initial RTT
    if len(filteredSrcToDst) > 1:
        initial_rtt = filteredSrcToDst[1][2] - filteredSrcToDst[0][2]
        congestion_window_sizes = first_n_cwnds(filteredSrcToDst, initial_rtt, 3)
        print("Congestion window sizes (in packets/RTT): " + str(congestion_window_sizes)[1:-1])

    else:
        print('Error: Congestion window sizes could not be estimated')

    # Print the number of times a retransmission occurred due to triple duplicate ACK
    tripleDupacks = get_triple_dupacks_retransmissions(filteredDstToSrc, filteredSegments)
    print('Number of retransmissions due to triple duplicate ACK: ' + str(len(tripleDupacks)))

    # Print the number of times a retransmission occurred due to timeout
    # Number of timeout retransmissions = Number of retransmissions - Number of triple dupack retransmissions
    tcp_retransmissions = get_retransmissions(filteredSrcToDst)
    print('Number of retransmissions due to timeout: ' +
          str(len(tcp_retransmissions) - len(tripleDupacks)) + '\n')
