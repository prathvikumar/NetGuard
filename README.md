# NetGuard — Network Traffic Analysis & Threat Detection

NetGuard is a Python-based network traffic analysis and cybersecurity tool that analyzes saved PCAP files, identifies network protocols, visualizes traffic statistics, and detects potential port-scanning activity. It provides both a **desktop graphical user interface (GUI)** and a **command-line interface (CLI)**.

Developed as a hands-on cybersecurity learning project, NetGuard demonstrates packet analysis, protocol identification, IP activity inspection, basic threat detection, and automated report generation.

## Features

### Desktop GUI
- Modern dark-themed desktop interface built with CustomTkinter.
- Dashboard displaying packet statistics and potential threat alerts.
- PCAP file selection with navigation to the analysis page.
- Dedicated pages for protocol analysis, IP activity, threat investigation, and reports.
- Configurable port-scan detection threshold.
- Access to generated CSV reports, charts, and threat reports.

### Network Analysis
- Packet analysis using Scapy.
- Identification of TCP, UDP, ICMP, DNS, and ARP traffic.
- Source and destination IP address analysis.
- DNS query extraction and counting.
- Basic heuristic detection of potential port-scanning activity.
- Configurable port-scan detection threshold.
- Timestamped CSV traffic reports.
- Structured CSV threat reports.
- Protocol traffic visualization using Matplotlib.
- Command-line support for custom PCAP files.
- Synthetic PCAP files for testing normal, empty, non-IP, and suspicious traffic scenarios.

## Technologies Used

| Technology | Purpose |
|---|---|
| Python 3.12 | Application development |
| CustomTkinter | Desktop GUI |
| Scapy | Packet analysis |
| Pandas | Data handling and reporting |
| Matplotlib | Traffic visualization |
| Git | Version control |
| GitHub | Source code hosting |

## Project Structure

```text
NetGuard/
├── data/
│   ├── sample_traffic.pcap
│   ├── port_scan_test.pcap
│   ├── empty_test.pcap
│   └── non_ip_test.pcap
├── reports/
│   ├── protocol_traffic.png
│   └── threat_alerts.csv
├── src/
│   ├── main.py
│   ├── gui.py
│   ├── packet_analyzer.py
│   ├── report_generator.py
│   ├── visualizer.py
│   ├── threat_detector.py
│   ├── threat_reporter.py
│   ├── create_sample.py
│   ├── create_threat_test.py
│   ├── create_empty_test.py
│   └── create_non_ip_test.py
├── .gitignore
├── requirements.txt
└── README.md
```

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/prathvikumar/NetGuard.git
cd NetGuard
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

### 3. Activate the environment

Windows PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

If PowerShell blocks script execution, you can run the application using the virtual environment's Python executable directly.

### 4. Install dependencies

```bash
python -m pip install -r requirements.txt
```

## Usage

### Launch the desktop GUI

From the project root directory:

```bash
python src/gui.py
```

On Windows, you can also use:

```powershell
.\venv\Scripts\python.exe .\src\gui.py
```

### Analyze the default sample capture using the CLI

```bash
python src/main.py
```

### Analyze a specific PCAP file

```bash
python src/main.py data/port_scan_test.pcap
```

### Configure the port-scan detection threshold

The default threshold is 10 distinct destination ports for a source and destination IP address pair.

Use a lower threshold:

```bash
python src/main.py data/port_scan_test.pcap --port-threshold 5
```

Use a higher threshold:

```bash
python src/main.py data/port_scan_test.pcap --port-threshold 15
```

The threshold must be at least 2.

The GUI provides its own threshold setting for analysis. Both interfaces analyze saved capture files rather than performing live network capture.

## How to Use the GUI

1. Launch NetGuard using `python src/gui.py`.
2. Select **Choose PCAP** on the dashboard.
3. Select a `.pcap` or `.pcapng` file.
4. On the Analyze PCAP page, review the selected file and configure the detection threshold.
5. Click **Analyze capture**.
6. Review packet counts, protocol statistics, source and destination IP addresses, DNS queries, and potential alerts.
7. Visit the Protocols, IP Activity, Threats, and Reports pages to explore the results.
8. Open generated reports and charts from the Reports page.

## Testing

NetGuard includes synthetic packet captures for local testing.

| Capture file | Purpose |
|---|---|
| `sample_traffic.pcap` | Demonstrates normal TCP, UDP, ICMP, and DNS analysis |
| `port_scan_test.pcap` | Demonstrates potential port-scan detection |
| `empty_test.pcap` | Tests handling of an empty capture |
| `non_ip_test.pcap` | Tests handling of ARP-only traffic |

These sample captures are intended for local testing and do not require sending traffic to external systems.

## Generated Reports

Depending on the analysis and detected activity, NetGuard can generate:

- Timestamped CSV files containing traffic analysis results.
- Protocol traffic charts in PNG format.
- Threat alert CSV reports when alerts are detected.

Threat reports may include the timestamp, alert type, source IP, destination IP, number of distinct destination ports, observed ports, severity, configured threshold, protocols, and detection reason.

Generated files are stored in the `reports/` directory.

## How Threat Detection Works

NetGuard groups TCP and UDP traffic by source and destination IP address and counts distinct destination ports. When the configured threshold is reached, the detector flags the activity as a potential port scan.

The threshold can be configured through the CLI option `--port-threshold` or through the GUI.

This is a basic detection heuristic, not definitive proof of an attack. It may produce false positives or fail to detect some scanning techniques.

## Limitations

- The application analyzes saved PCAP files; live network capture is not implemented.
- Detection relies on a simple threshold-based heuristic.
- DNS packets can also be counted under their transport protocol, so some protocol counts may overlap.
- PCAP support can depend on the installed packet-processing dependencies and environment.
- NetGuard is an educational project, not a replacement for a production intrusion detection system.

## Future Improvements

- Detect additional suspicious traffic patterns.
- Add more advanced threat-detection techniques.
- Improve report filtering and traffic visualization.
- Add richer analysis summaries and export options.
- Expand automated testing and error handling.

## Author

**Prathvi Kumar**

GitHub: https://github.com/prathvikumar

## License

No open-source license has been added to this repository yet. Unless a license is added, usage and redistribution remain subject to the author's rights.
