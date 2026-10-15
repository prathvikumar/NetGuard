
import csv
from pathlib import Path
from datetime import datetime


def generate_report(analysis_results, output_dir="reports"):
    """Save packet analysis results to CSV files."""

    report_dir = Path(output_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = report_dir / f"netguard_report_{timestamp}.csv"

    with report_path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        writer.writerow(["NetGuard - Network Traffic Analysis Report"])
        writer.writerow(["Generated at", datetime.now().isoformat(timespec="seconds")])
        writer.writerow([])

        writer.writerow(["Metric", "Value"])
        writer.writerow([
            "Total packets",
            analysis_results.get("total_packets", 0),
        ])

        writer.writerow([])
        writer.writerow(["Transport Protocol", "Packet Count"])

        for protocol, count in analysis_results.get(
            "transport_counts", {}
        ).items():
            writer.writerow([protocol, count])

        writer.writerow([])
        writer.writerow(["Source IP Address", "Packet Count"])

        for ip, count in analysis_results.get("source_ips", {}).items():
            writer.writerow([ip, count])

        writer.writerow([])
        writer.writerow(["Destination IP Address", "Packet Count"])

        for ip, count in analysis_results.get(
            "destination_ips", {}
        ).items():
            writer.writerow([ip, count])

        writer.writerow([])
        writer.writerow(["DNS Query Name", "Packet Count"])

        for name, count in analysis_results.get("dns_queries", {}).items():
            writer.writerow([name, count])

    print(f"\nCSV report saved successfully: {report_path}")
    return report_path


if __name__ == "__main__":
    from packet_analyzer import analyze_pcap

    results = analyze_pcap("data/sample_traffic.pcap")
    generate_report(results)
