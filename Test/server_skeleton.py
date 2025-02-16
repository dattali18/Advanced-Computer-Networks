from scapy.all import *
import time

PORT = 4444
COOKIE = b"87654321"

show_interfaces()
conf.iface = dev_from_index(-4)

""" Use prints after every step to show that it is completed"""


# step 1 - use proper filter to capture the client SYN
def syn_filter(p):
    return TCP in p and p[TCP].dport == PORT and p[TCP].flags == "S"


def capture_syn_client():
    print("Waiting for client SYN")

    syn_packet = sniff(count=1, lfilter=syn_filter)[0]

    print("Client SYN captured")

    return syn_packet


syn = capture_syn_client()


# step 2 - send SYN ACK along with a cookie (64 bit of your choice)
def send_syncak_with_cookie_client(synpacket):
    print("Sending SYN ACK with cookie")

    ip_layer = IP(dst=synpacket[IP].src)
    tcp_layer = TCP(
        sport=PORT,
        dport=synpacket[TCP].sport,
        flags="SA",
        seq=100,
        ack=synpacket[TCP].seq + 1,
    )

    packet = ip_layer / tcp_layer / Raw(load=COOKIE)

    send(packet)

    print("SYN ACK with cookie sent")


send_syncak_with_cookie_client(syn)


# step 3 - use proper filter to capture the client ACK
def ack_filter(p):
    return TCP in p and p[TCP].flags == "A"


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
    meaning it's a SYN packet with a cookie with lenght of 8 bytes
    """
    return TCP in p and p[TCP].flags == "S"


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
    if Raw in syn_packet and syn_packet[Raw].load.startswith(COOKIE):
        if request_type == "Name":
            response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nName: Daniel Attali"
        elif request_type == "ID":
            response = (
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nID: 328780879"
            )

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


request = tfo_syn[Raw].load.decode("utf-8")

if "/Name" in request:
    send_tfo_response(tfo_syn, "Name")
elif "/ID" in request:
    send_tfo_response(tfo_syn, "ID")

print("Finished running")
