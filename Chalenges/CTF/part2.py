from scapy import *
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.sendrecv import send
from scapy.sendrecv import sniff

SERVER_PORT = 8200
CLIENT_PORT = 55555


data_segment = TCP(
    dport=SERVER_PORT, sport=CLIENT_PORT, flags="PA", seq=123, ack=1
) / Raw("GET / HTTP/1.1\r\n\r\n")

data_packet = IP(dst="127.0.0.1") / data_segment

send(data_packet)
