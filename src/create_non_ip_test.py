
from pathlib import Path
from scapy.all import Ether, ARP, wrpcap

output_path = Path("data/non_ip_test.pcap")
output_path.parent.mkdir(parents=True, exist_ok=True)

packets = [
    Ether() / ARP(
        op=1,
        hwsrc="02:00:00:00:00:01",
        psrc="192.168.1.10",
        hwdst="ff:ff:ff:ff:ff:ff",
        pdst="192.168.1.1",
    ),
    Ether() / ARP(
        op=2,
        hwsrc="02:00:00:00:00:02",
        psrc="192.168.1.1",
        hwdst="02:00:00:00:00:01",
        pdst="192.168.1.10",
    ),
]

wrpcap(str(output_path), packets)

print("Non-IPv4 test capture created successfully!")
print(f"File: {output_path}")
print(f"Packets created: {len(packets)}")
print("Packets are saved to a file; nothing was transmitted.")
