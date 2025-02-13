from scapy import *
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.sendrecv import send
from scapy.sendrecv import sniff

SERVER_PORT = 8200
CLIENT_PORT = 55555


def filter_packet(packet):
    return packet.haslayer(TCP) and packet[TCP].dport == CLIENT_PORT


syn_segment = TCP(dport=SERVER_PORT, sport=CLIENT_PORT, flags="S", seq=123)
syn_packet = IP(dst="127.0.0.1") / syn_segment

send(syn_packet)

syn_ack_packet = sniff(count=1, lfilter=filter_packet)

# if the packet is not reveived
if not syn_ack_packet:
    print("Packet not received")
    exit(1)

# prepare the ack packet

ack_segment = TCP(
    dport=SERVER_PORT,
    sport=CLIENT_PORT,
    flags="A",
    seq=syn_ack_packet[0][TCP].ack,
    ack=syn_ack_packet[0][TCP].seq + 1,
)

ack_packet = IP(dst="127.0.0.1") / ack_segment

send(ack_packet)

# prepare the data packet
# the data is a simple http get

# sleep for 1 second before sending the data


data_segment = TCP(dport=SERVER_PORT, sport=CLIENT_PORT, flags="PA", seq=123, ack=1) / Raw("GET / HTTP/1.1\r\n\r\n")

data_packet = IP(dst="127.0.0.01") / data_segment

send(data_packet)
