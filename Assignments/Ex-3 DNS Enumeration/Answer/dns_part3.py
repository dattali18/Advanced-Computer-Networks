"""
This script is used to emulate the following command:
nslookup -type=SOA jct.ac.il

Meaning, it sends a DNS query to the DNS server and asks for the SOA record of the domain.
The output of the program should be a list of pairs of the domain
dns.jct.ac.il   internet address = 147.161.1.4
dns.jct.ac.il   internet address = 147.161.1.15
dns1.jct.ac.il  internet address = 147.161.1.4
dns2.jct.ac.il  internet address = 147.161.1.15

The script is using the scapy library to send the DNS query to the DNS server.

The script will be called like this:
python dns_part3.py jct.ac.il
"""

from scapy import *
from scapy.layers.dns import DNS, DNSQR, DNSRR, IP, UDP
from scapy.sendrecv import sr1, sr

from typing import List

import sys


def dns_query(domain, qtype="SOA"):
    # send a dns query to the domain
    response = sr1(
        IP(dst="8.8.8.8")
        / UDP(dport=53)
        / DNS(rd=1, qd=DNSQR(qname=domain, qtype=qtype)),
        verbose=0,
        timeout=2,
    )

    ans = []

    if response and response.haslayer(DNS):
        print(response[DNS].show())
        if response[DNS].an:
            for i in range(response[DNS].ancount):
                record = response[DNS].an[i]
                if record.type == 6:  # SOA record
                    ans.append(
                        (
                            "SOA",
                            record.mname.decode(),
                            record.rname.decode(),
                            record.serial,
                            record.refresh,
                            record.retry,
                            record.expire,
                            record.minimum,
                        )
                    )
                elif record.type == 1:  # A record
                    ans.append(("A", record.rrname.decode(), record.rdata))

        if response[DNS].ns:
            for i in range(response[DNS].nscount):
                ns_record = response[DNS].ns[i]
                if hasattr(ns_record, "rdata"):
                    ans.append(
                        ("NS", ns_record.rrname.decode(), ns_record.rdata.decode())
                    )

    return ans


def main(args: List[str]) -> None:
    domain = args[1]
    response = dns_query(domain, qtype="SOA")

    # Print SOA record
    for record in response:
        if record[0] == "SOA":
            print(f"{domain}")
            print(f"        origin = {record[1]}")
            print(f"        mail addr = {record[2]}")
            print(f"        serial = {record[3]}")
            print(f"        refresh = {record[4]}")
            print(f"        retry = {record[5]}")
            print(f"        expire = {record[6]}")
            print(f"        minimum = {record[7]}")

    # Query for A records of nameservers
    for record in response:
        if record[0] == "NS":
            ns_domain = record[2]
            ns_response = dns_query(ns_domain, qtype="A")
            ns_records = extract_records(ns_response)
            for ns_record in ns_records:
                if ns_record[0] == "A":
                    print(f"{ns_record[1]} internet address = {ns_record[2]}")


if __name__ == "__main__":
    main(sys.argv)
