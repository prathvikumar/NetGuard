
from pathlib import Path

from scapy.all import Ether, IP, TCP, wrpcap


output_path = Path("data/port_scan_test.pcap")
output_path.parent.mkdir(parents=True, exist_ok=True)

packets = []

# Simulate one source contacting 12 different destination ports.
# These packets are written to a file only; they are not transmitted.
for port in range(20, 32):
    packet = (
        Ether()
        / IP(src="192.168.1.50", dst="192.168.1.100")
        / TCP(sport=45000, dport=port, flags="S")
    )
    packets.append(packet)

wrpcap(str(output_path), packets)

print("Synthetic threat-test capture created successfully!")
print(f"File: {output_path}")
print(f"Packets created: {len(packets)}")
print("No packets were transmitted over the network.")
