"""
Daniel Attali 328780879
"""

from scapy.all import *
import time

PORT = 5555

show_interfaces()
conf.iface = dev_from_index(-4)

""" Use prints after every step to show that it is completed"""

dport = 4444
sport = PORT


# step 1 - send SYN
def send_syn_client():
    print("Sending SYN")

    ip_layer = IP(dst="127.0.0.1")
    tcp_layer = TCP(sport=sport, dport=dport, flags="S", seq=100)

    packet = ip_layer / tcp_layer
    send(packet)
    print("SYN sent")

    return packet.sport


sport = send_syn_client()


# step 2 - use proper filter to capture server's SYN ACK, keep the cookie
def syn_ack_filter(p):
    """
    Filter for a server SYN ACK packet
    """
    return TCP in p and p[TCP].dport == sport and p[TCP].flags == "SA"


def capture_synack_server():
    print("Waiting for server SYN ACK")

    syn_ack_packet = sniff(count=1, lfilter=syn_ack_filter)[0]

    print("Server SYN ACK captured")

    return syn_ack_packet, syn_ack_packet[TCP].seq


syn_ack, initial_seq = capture_synack_server()
cookie = syn_ack[Raw].load

print(f"Reviced Cookie = {cookie}")


# step 3 - send ACK
def send_ack_server(synack_p, sport, initial_seq):
    print("Sending ACK")

    ip_layer = IP(dst=synack_p[IP].src)
    tcp_layer = TCP(
        sport=sport,
        dport=synack_p[TCP].sport,
        flags="A",
        seq=initial_seq + 1,
        ack=synack_p[TCP].seq + 1,
    )

    packet = ip_layer / tcp_layer

    send(packet)

    print("ACK sent")


send_ack_server(syn_ack, sport, initial_seq)

# step 4 -
time.sleep(1)

# A. ask the user if to ask for Name or ID (input)
# B. send SYN with the cookie, plus an HTTP request
request_type = input("Please Enter request type (options Name, ID): ").strip()

while request_type not in ["Name", "ID"]:
    request_type = input("Please Enter request type (options Name, ID): ").strip()

# preparing the request with tfo


def send_tfo_request_server(cookie, request_type, sport):
    print(f"Starting sending TFO reqeust for {request_type}")

    http_request = f"GET/{request_type} HTTP1.1\r\nHost : localhost\r\n\r\n"

    ip_layer = IP(dst="127.0.0.1")
    tcp_layer = TCP(sport=sport, dport=dport, flags="S", seq=200)
    # starting with a new seq number

    packet = ip_layer / tcp_layer / Raw(load=cookie + http_request.encode())
    # adding teh cookie and the http request 
    # cookie has the first 4 bytes of the packet (meaning we know the server knows how to read it)

    send(packet)
    print("Sending TFO request")

# choose another port to so there isn't conflict (in Wireshark)
sport = sport + 1

send_tfo_request_server(cookie, request_type, sport)


# step 5 -
# A. Use proper filter to capture server's response
# B. Extract the data from the HTTP header and print it.
def filter_server_response(p):
    """
    Filter for a server response packet with the data
    """
    return TCP in p and p[TCP].dport == sport and p[TCP].flags == "SA" and Raw in p


def capture_server_response():
    print("Waiting for server response")

    response_packet = sniff(count=1, lfilter=filter_server_response)[0]

    print("Server response captured")

    return response_packet


response = capture_server_response()

# print(f"Server response: {response[Raw].load.decode('utf-8')}")

# response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nName: Daniel Attali"

raw = response[Raw].load.decode('utf-8')

data = raw.split("\r\n\r\n")[1]

print(f"Server response: {data}")
