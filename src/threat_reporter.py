
import csv
from pathlib import Path
from datetime import datetime


def save_threat_report(alerts, output_dir="reports"):
    """Save detected threat alerts to a CSV file."""

    report_dir = Path(output_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    report_path = report_dir / "threat_alerts.csv"

    fieldnames = [
        "timestamp",
        "alert_type",
        "source_ip",
        "destination_ip",
        "distinct_ports",
        "ports",
        "severity",
    ]

    file_exists = report_path.exists()
    write_header = (
        not file_exists or report_path.stat().st_size == 0
    )

    with report_path.open(
        "a", newline="", encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)

        if write_header:
            writer.writeheader()

        timestamp = datetime.now().isoformat(timespec="seconds")

        for alert in alerts:
            writer.writerow({
                "timestamp": timestamp,
                "alert_type": alert.get("type", "Unknown"),
                "source_ip": alert.get("source_ip", ""),
                "destination_ip": alert.get("destination_ip", ""),
                "distinct_ports": alert.get("distinct_ports", 0),
                "ports": ", ".join(
                    str(port) for port in alert.get("ports", [])
                ),
                "severity": alert.get("severity", "Unknown"),
            })

    print(f"Threat report saved: {report_path}")
    print(f"Alerts written: {len(alerts)}")

    return report_path


if __name__ == "__main__":
    from threat_detector import detect_threats

    capture_file = "data/port_scan_test.pcap"
    alerts = detect_threats(capture_file)
    save_threat_report(alerts)
