
import argparse
from pathlib import Path

from packet_analyzer import analyze_pcap
from report_generator import generate_report
from visualizer import create_protocol_chart
from threat_detector import detect_threats
from threat_reporter import save_threat_report


def main():
    parser = argparse.ArgumentParser(
        description="NetGuard - Network Traffic Analysis Tool"
    )

    parser.add_argument(
        "capture",
        nargs="?",
        default="data/sample_traffic.pcap",
        help="Path to the PCAP capture file to analyze",
    )

    parser.add_argument(
        "--port-threshold",
        type=int,
        default=10,
        help=(
            "Minimum number of distinct destination ports "
            "to flag a possible port scan (default: 10)"
        ),
    )

    args = parser.parse_args()

    if args.port_threshold < 2:
        parser.error("--port-threshold must be at least 2")

    print("=" * 50)
    print("                  NETGUARD")
    print("       Network Traffic Analysis Tool")
    print("=" * 50)

    capture_path = Path(args.capture)

    if not capture_path.is_file():
        print(f"\nError: Capture file not found: {capture_path}")
        return 1

    print(f"\nAnalyzing capture: {capture_path}")
    print(f"Port-scan detection threshold: {args.port_threshold}")

    try:
        # 1. Analyze network packets.
        results = analyze_pcap(str(capture_path))

        # 2. Generate the traffic CSV report.
        generate_report(results)

        # 3. Generate the protocol graph.
        create_protocol_chart(results)

        # 4. Detect possible port scans using the selected threshold.
        alerts = detect_threats(
            str(capture_path),
            port_threshold=args.port_threshold,
        )

        # 5. Save threat alerts when detections exist.
        if alerts:
            save_threat_report(alerts)
        else:
            print("\nNo threat alerts to save for this capture.")

    except (OSError, ValueError) as error:
        print(f"\nAnalysis failed: {error}")
        return 1

    print("\n" + "=" * 50)
    print("NETGUARD ANALYSIS COMPLETED")
    print("=" * 50)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
