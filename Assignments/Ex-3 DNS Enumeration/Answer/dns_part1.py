from scapy import *
from scapy.layers.dns import DNS, DNSQR, IP, UDP
from scapy.sendrecv import sr1

from typing import List

import sys

# write a script that takes as argument a domain name and find the dns server of the domain
# example: script.py www.google.com

def find_dns_server(domain):
    # send a dns query to the domain
    response = sr1(IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain)), verbose=0, timeout=2)

    ans = []

    # extract the dns server from the response
    if response and response.haslayer(DNS) and response[DNS].an:
        for i in range(response[DNS].ancount):
            answer = response[DNS].an[i]
            if hasattr(answer, "rdata"):
                ans.append(answer.rdata)

    return ans

def main(args: List[str]) -> None:
    domain = args[1]
    dns_server = find_dns_server(domain)
    print(f"The DNS server for {domain} is: {dns_server}")

if __name__ == "__main__":
    main(sys.argv)
