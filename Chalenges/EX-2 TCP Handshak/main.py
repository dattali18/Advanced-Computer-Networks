from scapy import *
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1, send

URL = "www.jct.ac.il"

SPORT = 55555

# Send SYN
ip = IP(dst=URL)  # IP layer

SYN = TCP(dport=80, sport=SPORT, flags="S", seq=1000)  # TCP layer

SYNACK = sr1(
    ip / SYN
)  # Send the packet and wait for a response

# Send ACK

ACK = TCP(
    dport=80, sport=SPORT, seq=SYNACK.ack, ack=SYNACK.seq + 1, flags="A"
)  # TCP layer

send(ip / ACK)  # Send the packet
