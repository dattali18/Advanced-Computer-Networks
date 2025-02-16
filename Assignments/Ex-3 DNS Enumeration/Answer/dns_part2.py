from scapy import *
from scapy.layers.dns import DNS, DNSQR, IP, UDP
from scapy.sendrecv import sr1

from typing import List

import sys

import re

# write a script that takes as an argument a subdomain and find the dns server of the domain
# and then loop over every subdomain in the file and find the dns server of the domain
# the file is 'subdomains.txt'
# example: script.py google.com

def find_dns_server(domain):
    # send a dns query to the domain
    response = sr1(
        IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain)),
        verbose=0,
        timeout=2,
    )

    ans = []

    # extract the dns server from the response
    if response and response.haslayer(DNS) and response[DNS].an:
        for i in range(response[DNS].ancount):
            answer = response[DNS].an[i]
            if hasattr(answer, "rdata"):
                ans.append(answer.rdata)

    return ans

def get_subdomains():
    with open("subdomains.txt") as f:
        return f.read().splitlines()

def validate_domain(domain):
    pattern = re.compile(r"^(www\.)?([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}$")
    return pattern.match(domain) is not None


def query_subdomain(domain, subdomain, dns_ip):
    fqdn = f"{subdomain}.{domain}"

    response = sr1(
        IP(dst=dns_ip) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=fqdn)),
        verbose=0,
        timeout=2,
    )

    if response and response.haslayer(DNS) and response[DNS].an:
        ips = []
        for i in range(response[DNS].ancount):
            answer = response[DNS].an[i]
            if hasattr(answer, "rdata"):
                ips.append(answer.rdata)
        return fqdn, ips
    
    return fqdn, None

def main(args: List[str]) -> None:
    print("DNS Mapping for domain:", args[1])

    domain = args[1]

    if not validate_domain(domain):
        print("Invalid domain")
        sys.exit(1)

    dns_ip = find_dns_server(domain)

    subdomains = get_subdomains()

    results = []

    for subdomain in subdomains:
        fqdn, ips = query_subdomain(domain, subdomain, dns_ip)
        # print(fqdn, "=>", ips)
        if ips:
            results.append((fqdn, ips))

    print("\nMapping Results:\n")
    for fqdn, ips in results:
        print(f"Subdomain: {fqdn}")
        print(f"  IPs/References:")
        for ip in ips:
            # Decode byte strings if necessary
            ip = ip.decode() if isinstance(ip, bytes) else ip
            print(f"    - {ip}")


if __name__ == "__main__":
    main(sys.argv)
