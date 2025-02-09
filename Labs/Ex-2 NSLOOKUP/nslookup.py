# this is the NSLOOKUP lab

from scapy.all import *
import os

# get the domain name from the user
# get it from the argument line

def get_ipv4_addresses(domain_name):
    # get the ipv4 addresses of the domain
    ipv4_addresses = []
    try:
        ipv4_addresses = socket.gethostbyname_ex(domain_name)
    except socket.gaierror as e:
        print("Error: ", e)
    return ipv4_addresses


# same function using scapy
def nslookup_a(domain):
    # Create a DNS request packet
    dns_request = (
        IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain, qtype="A"))
    )

    # Send the DNS request and get the response
    dns_response = sr1(dns_request, verbose=0)

    # Extract and print the IP addresses from the response
    if dns_response and dns_response.haslayer(DNS):
        for i in range(dns_response[DNS].ancount):
            dns_rr = dns_response[DNS].an[i]
            if dns_rr.type == 1:  # Type A
                print(f"{domain} has address {dns_rr.rdata}")


def main():
    domain_name = os.sys.argv[1]

    ipv4_addresses = get_ipv4_addresses(domain_name)

    print("The IPv4 addresses of the domain: ", domain_name)

    for ip in ipv4_addresses[2]:
        print(f"\t{ip}")

    nslookup_a(domain_name)

if __name__ == "__main__":
    main()
