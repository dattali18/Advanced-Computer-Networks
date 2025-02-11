#####################################################################
# This a challenge as part of the Advanced Computer Networks course
# the challenge is to use the ICMP protocol to ping google and get
# back a custom message from the ICMP response.
# Using scapy
#####################################################################

MESSAGE = "You are the best!"

from scapy.all import sr1
from scapy.layers.inet import IP, ICMP

# Create an ICMP packet with a custom payload
packet = IP(dst="google.com") / ICMP() / MESSAGE

# Send the ICMP request and get the response
reply = sr1(packet)

# Print the response
if reply:
    print("Reply from {}:".format(reply.src))
    print(reply.show())
else:
    print("No reply received")
