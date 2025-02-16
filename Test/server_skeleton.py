"""
Daniel Attali 328780879
"""

from scapy.all import *
import time

PORT = 4444
# cookie is a 64 bit number
# this was chosen randomly
# to make the connection more secure for each client we can use a different cookie generated randomly
# but for the purpose of this exercise we will use a static cookie
COOKIE = b"87654321"

dport = PORT

show_interfaces()
# -4 is my localhost interface
conf.iface = dev_from_index(-4)

""" Use prints after every step to show that it is completed"""


# step 1 - use proper filter to capture the client SYN
def syn_filter(p):
    """
    Filter for a client SYN packet
    """
    return TCP in p and p[TCP].dport == dport and p[TCP].flags == "S"


def capture_syn_client():
    print("Waiting for client SYN")

    syn_packet = sniff(count=1, lfilter=syn_filter)[0]

    print("Client SYN captured")

    return syn_packet


syn = capture_syn_client()


# step 2 - send SYN ACK along with a cookie (64 bit of your choice)
def send_syncak_with_cookie_client(synpacket):
    print("Sending SYN ACK wiith cookie")

    ip_layer = IP(dst=synpacket[IP].src)
    tcp_layer = TCP(
        sport=dport,
        dport=synpacket[TCP].sport,
        flags="SA",  # syn-ack flags
        seq=100,  # random number since it's a new connection
        ack=synpacket[TCP].seq + 1,  # the client's seq + 1
    )

    packet = ip_layer / tcp_layer / Raw(load=COOKIE)

    send(packet)

    print("SYN ACK with cookie sent")


send_syncak_with_cookie_client(syn)


# step 3 - use proper filter to capture the client ACK
def ack_filter(p):
    """
    Filter for a client ACK packet
    """
    return TCP in p and p[TCP].flags == "A" and p[TCP].dport == dport


def capture_ack_client():
    print("Waiting for client ACK")

    ack_packet = sniff(count=1, lfilter=ack_filter)[0]

    print("Client ACK captured")

    return ack_packet


ack = capture_ack_client()

# connection disconnected
time.sleep(1)


# step 4 -
# A. Use proper filter to capture the client SYN
# B. Check the cookie (if there is one)
def tfo_syn_filter(p):
    """
    Filter for a tfo SYN packet
    meaning its a SYN packet with a cookie
    """
    return TCP in p and p[TCP].flags == "S" and p[TCP].dport == PORT and Raw in p


def capture_tfo_syn():
    print("Waiting for TFO SYN")

    tfo_syn_packet = sniff(count=1, lfilter=tfo_syn_filter)[0]

    print("TFO SYN captured")

    return tfo_syn_packet


tfo_syn = capture_tfo_syn()

# step 5 -
# A. If the cookie is known, send ACK and the HTTP data requested
# B. If the cookie is not known, or no cookie - finish running


def send_tfo_response(syn_packet, request_type):
    """
    Send a TFO response to the client
    """

    # check if the cookie is in the packet and if it's the same as the one we sent
    if Raw in syn_packet and syn_packet[Raw].load.startswith(COOKIE):
        # if request_type == "Name":
        #     response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plaintext\r\n\r\nName: Daniel Attali"
        # elif request_type == "ID":
        #     response = (
        #         b"HTTP/1.1 200 OK\r\nContent-Type: text/plaintext\r\n\r\nID: 328780879"
        #     )

        content = ""
        if request_type == "Name":
            content = "Daniel Attali"
        elif request_type == "ID":
            content = "328780879"

        response = f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length : {len(content)}\r\n\r\n{content}".encode()

        ip_layer = IP(dst=syn_packet[IP].src)
        tcp_layer = TCP(
            sport=PORT,
            dport=syn_packet[TCP].sport,
            flags="SA",
            seq=2000,  # random number since it's a new connection
            ack=syn_packet[TCP].seq + 1,
        )

        packet = ip_layer / tcp_layer / Raw(load=response)
        send(packet)

        print("TFO response sent")

    else:
        print("No cookie found, finishing running")


# get the request from the packet
request = tfo_syn[Raw].load.decode("utf-8")

# send the response based on the request according to the exercise
if "/Name" in request:
    send_tfo_response(tfo_syn, "Name")
elif "/ID" in request:
    send_tfo_response(tfo_syn, "ID")

print("Finished running")
