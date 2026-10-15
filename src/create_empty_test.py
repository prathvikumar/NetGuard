
from scapy.all import wrpcap

output_path = "data/empty_test.pcap"

wrpcap(output_path, [])

print("Empty test capture created successfully!")
print(f"File: {output_path}")
print("Packets created: 0")
