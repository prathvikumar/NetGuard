
from pathlib import Path

import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt

from packet_analyzer import analyze_pcap


def create_protocol_chart(analysis_results, output_dir="reports"):
    """Create a chart of transport and other protocol counts."""

    report_dir = Path(output_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    transport_counts = analysis_results.get("transport_counts", {})
    protocol_counts = analysis_results.get("protocol_counts", {})

    # Combine the counts for a single visualization.
    chart_counts = dict(transport_counts)

    for protocol, count in protocol_counts.items():
        chart_counts[protocol] = count

    if not chart_counts:
        print("No protocol data available to visualize.")
        return None

    protocols = list(chart_counts.keys())
    counts = list(chart_counts.values())

    fig, ax = plt.subplots(figsize=(9, 5))
    bars = ax.bar(protocols, counts)

    ax.set_title("NetGuard - Network Traffic by Protocol")
    ax.set_xlabel("Protocol")
    ax.set_ylabel("Number of Packets")
    ax.grid(axis="y", linestyle="--", alpha=0.4)

    for bar, count in zip(bars, counts):
        ax.annotate(
            str(count),
            (bar.get_x() + bar.get_width() / 2, bar.get_height()),
            xytext=(0, 4),
            textcoords="offset points",
            ha="center",
            va="bottom",
        )

    fig.tight_layout()

    output_path = report_dir / "protocol_traffic.png"
    fig.savefig(output_path, dpi=150)
    plt.close(fig)

    print(f"Protocol chart saved successfully: {output_path}")
    return output_path


if __name__ == "__main__":
    capture_path = Path("data/sample_traffic.pcap")

    if not capture_path.is_file():
        print(f"Capture file not found: {capture_path}")
    else:
        results = analyze_pcap(str(capture_path))
        create_protocol_chart(results)
