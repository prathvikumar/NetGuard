
from collections import defaultdict
from pathlib import Path

from scapy.all import rdpcap, IP, TCP, UDP


def detect_threats(file_path, port_threshold=10):
    """
    Identify possible port scans in a saved packet capture.

    A source IP is flagged when it contacts at least
    port_threshold distinct destination ports on the same
    destination IP using TCP or UDP.
    """

    capture_path = Path(file_path)

    if not capture_path.is_file():
        raise FileNotFoundError(
            f"Capture file not found: {capture_path}"
        )

    if port_threshold < 2:
        raise ValueError("port_threshold must be at least 2")

    packets = rdpcap(str(capture_path))

    # Store destination ports and observed transport protocols
    # for each source/destination IP pair.
    contacted_ports = defaultdict(set)
    observed_protocols = defaultdict(set)

    for packet in packets:
        if IP not in packet:
            continue

        if TCP in packet:
            protocol = "TCP"
            destination_port = int(packet[TCP].dport)
        elif UDP in packet:
            protocol = "UDP"
            destination_port = int(packet[UDP].dport)
        else:
            continue

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        connection = (source_ip, destination_ip)

        contacted_ports[connection].add(destination_port)
        observed_protocols[connection].add(protocol)

    alerts = []

    for (source_ip, destination_ip), ports in contacted_ports.items():
        if len(ports) >= port_threshold:
            protocols = sorted(
                observed_protocols[(source_ip, destination_ip)]
            )

            alert = {
                "type": "Possible port scan",
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "distinct_ports": len(ports),
                "ports": sorted(ports),
                "severity": "Medium",
                "threshold": port_threshold,
                "protocols": protocols,
                "reason": (
                    f"{len(ports)} distinct destination ports were "
                    f"contacted, meeting the configured threshold "
                    f"of {port_threshold}."
                ),
            }

            alerts.append(alert)

    print("\n===== NETGUARD THREAT DETECTION =====")
    print(f"Packets examined: {len(packets)}")
    print(f"Port-scan detection threshold: {port_threshold}")

    if alerts:
        print(f"Potential threat alerts: {len(alerts)}")

        for alert in alerts:
            print("\n[ALERT] Possible port scan")
            print(f"  Source IP: {alert['source_ip']}")
            print(f"  Destination IP: {alert['destination_ip']}")
            print(
                f"  Distinct destination ports: "
                f"{alert['distinct_ports']}"
            )
            print(f"  Ports: {alert['ports']}")
            print(f"  Protocols: {', '.join(alert['protocols'])}")
            print(f"  Threshold: {alert['threshold']}")
            print(f"  Reason: {alert['reason']}")
            print(f"  Severity: {alert['severity']}")
    else:
        print("No port-scan patterns detected.")
        print("This does not guarantee that the traffic is safe.")

    return alerts


if __name__ == "__main__":
    detect_threats("data/sample_traffic.pcap")
