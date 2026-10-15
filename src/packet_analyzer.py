
from collections import Counter
from pathlib import Path

from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS, ARP


def analyze_pcap(file_path):
    """Analyze packets from a saved PCAP file."""

    capture_path = Path(file_path)

    if not capture_path.is_file():
        raise FileNotFoundError(
            f"Capture file not found: {capture_path}"
        )

    packets = rdpcap(str(capture_path))

    transport_counts = Counter()
    protocol_counts = Counter()
    source_ips = Counter()
    destination_ips = Counter()
    dns_queries = Counter()

    for packet in packets:

        # Identify ARP packets separately.
        if ARP in packet:
            protocol_counts["ARP"] += 1

        # Continue analyzing IPv4 traffic.
        if IP not in packet:
            if ARP not in packet:
                protocol_counts["Other Non-IPv4"] += 1
            continue

        source_ips[packet[IP].src] += 1
        destination_ips[packet[IP].dst] += 1

        if TCP in packet:
            transport_counts["TCP"] += 1
        elif UDP in packet:
            transport_counts["UDP"] += 1
        elif ICMP in packet:
            transport_counts["ICMP"] += 1
        else:
            transport_counts["Other IP"] += 1

        # Count DNS independently from its transport protocol.
        if DNS in packet:
            protocol_counts["DNS"] += 1

            dns = packet[DNS]

            if dns.qd is not None:
                query_name = getattr(dns.qd, "qname", None)

                if query_name:
                    if isinstance(query_name, bytes):
                        query_name = query_name.decode(
                            "utf-8", errors="replace"
                        )

                    dns_queries[query_name.rstrip(".")] += 1

    print("\n===== NETGUARD PACKET ANALYSIS =====")
    print(f"Total packets: {len(packets)}")

    print("\nTransport protocol counts:")
    if transport_counts:
        for protocol, count in transport_counts.most_common():
            print(f"  {protocol}: {count}")
    else:
        print("  No IPv4 transport packets found.")

    print("\nOther protocol counts:")
    other_protocols = {
        name: count
        for name, count in protocol_counts.items()
    }

    if other_protocols:
        for protocol, count in sorted(other_protocols.items()):
            print(f"  {protocol}: {count}")
    else:
        print("  None detected.")

    print("\nDNS names found:")
    if dns_queries:
        for name, count in dns_queries.most_common():
            print(f"  {name}: {count} packet(s)")
    else:
        print("  No DNS query names found.")

    print("\nTop source IP addresses:")
    for ip, count in source_ips.most_common(5):
        print(f"  {ip}: {count} packets")

    print("\nTop destination IP addresses:")
    for ip, count in destination_ips.most_common(5):
        print(f"  {ip}: {count} packets")

    return {
        "total_packets": len(packets),
        "transport_counts": transport_counts,
        "protocol_counts": protocol_counts,
        "source_ips": source_ips,
        "destination_ips": destination_ips,
        "dns_queries": dns_queries,
    }


if __name__ == "__main__":
    analyze_pcap("data/sample_traffic.pcap")
