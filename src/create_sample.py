
from scapy.all import (
    Ether,
    IP,
    TCP,
    UDP,
    ICMP,
    DNS,
    DNSQR,
    wrpcap,
)

packets = [
    # TCP traffic
    Ether() / IP(src="192.168.1.10", dst="192.168.1.1")
    / TCP(sport=50000, dport=443),

    # DNS query for example.com
    Ether() / IP(src="192.168.1.10", dst="192.168.1.1")
    / UDP(sport=50001, dport=53)
    / DNS(
        id=1,
        rd=1,
        qd=DNSQR(qname="example.com"),
    ),

    # Synthetic DNS response
    Ether() / IP(src="192.168.1.1", dst="192.168.1.10")
    / UDP(sport=53, dport=50001)
    / DNS(
        id=1,
        qr=1,
        aa=1,
        qd=DNSQR(qname="example.com"),
        an=None,
    ),

    # ICMP traffic
    Ether() / IP(src="192.168.1.20", dst="192.168.1.10")
    / ICMP(),

    # HTTP-port TCP traffic
    Ether() / IP(src="192.168.1.10", dst="192.168.1.20")
    / TCP(sport=50002, dport=80),
]

wrpcap("data/sample_traffic.pcap", packets)

print("Sample capture created successfully!")
print("File: data/sample_traffic.pcap")
print(f"Packets created: {len(packets)}")
