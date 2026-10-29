
import os
import sys
import threading
import subprocess
from pathlib import Path
from datetime import datetime
from collections import Counter
import tkinter as tk
from tkinter import filedialog, messagebox

import customtkinter as ctk

# ---------- Project paths ----------
PROJECT_DIR = Path(__file__).resolve().parent.parent
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from packet_analyzer import analyze_pcap
from report_generator import generate_report
from threat_detector import detect_threats
from threat_reporter import save_threat_report
from visualizer import create_protocol_chart

# ---------- Theme ----------
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

BG = "#0A101B"
SIDEBAR = "#0E1726"
CARD = "#131E2E"
CARD_ALT = "#1A283B"
BORDER = "#26364B"
TEXT = "#E8EEF7"
MUTED = "#94A3B8"
CYAN = "#55E6D0"
BLUE = "#72A7FF"
GREEN = "#54D69A"
AMBER = "#FFC56B"
RED = "#FF7777"


def as_counter(value):
    """Convert common count dictionaries into a Counter."""
    if isinstance(value, Counter):
        return value
    if isinstance(value, dict):
        return Counter(value)
    return Counter()


class NetGuardApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("NetGuard | Network Analysis")
        self.geometry("1450x900")
        self.minsize(1000, 650)
        self.configure(fg_color=BG)

        self.capture_path = None
        self.results = None
        self.alerts = []
        self.report_path = None
        self.chart_path = None
        self.threat_report_path = None
        self.busy = False
        self.threshold = tk.StringVar(value="10")
        self.current_page = "Dashboard"
        self.last_threshold = 10

        sample = PROJECT_DIR / "data" / "sample_traffic.pcap"
        if sample.is_file():
            self.capture_path = sample

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.build_sidebar()
        self.build_main_area()
        self.show_dashboard()

    # ---------- Shared UI helpers ----------
    def label(self, parent, text, size=12, color=TEXT, bold=False,
              **kwargs):
        return ctk.CTkLabel(
            parent,
            text=text,
            font=ctk.CTkFont(
                size=size, weight="bold" if bold else "normal"
            ),
            text_color=color,
            **kwargs,
        )

    def card(self, parent):
        return ctk.CTkFrame(
            parent, fg_color=CARD,
            corner_radius=14, border_width=1, border_color=BORDER
        )

    def button(self, parent, text, command, primary=False, **kwargs):
        return ctk.CTkButton(
            parent,
            text=text,
            command=command,
            height=36,
            corner_radius=9,
            fg_color="#164641" if primary else CARD_ALT,
            hover_color="#21655D" if primary else "#263950",
            text_color=CYAN if primary else TEXT,
            font=ctk.CTkFont(size=12, weight="bold"),
            **kwargs,
        )

    def make_scroll_page(self):
        page = ctk.CTkScrollableFrame(
            self.content, fg_color="transparent",
            scrollbar_button_color=BORDER,
        )
        page.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        page.grid_columnconfigure(0, weight=1)
        return page

    def heading(self, parent, title, subtitle):
        self.label(
            parent, title, 27, TEXT, True
        ).pack(anchor="w", padx=25, pady=(22, 4))
        self.label(
            parent, subtitle, 12, MUTED
        ).pack(anchor="w", padx=25, pady=(0, 20))

    def clear_page(self):
        for widget in self.content.winfo_children():
            widget.destroy()

    def set_status(self, text, color=GREEN):
        self.status_label.configure(text=f"●  {text}", text_color=color)

    def text_box(self, parent, height=180):
        return ctk.CTkTextbox(
            parent,
            height=height,
            fg_color="#0D1523",
            text_color=TEXT,
            border_color=BORDER,
            border_width=1,
            corner_radius=9,
            font=ctk.CTkFont(size=12, family="Consolas"),
            wrap="word",
        )

    def stat_line(self, parent, name, value):
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=13, pady=4)
        self.label(row, str(name), 11, TEXT).pack(side="left")
        self.label(row, str(value), 11, CYAN, True).pack(side="right")

    # ---------- Application layout ----------
    def build_sidebar(self):
        self.sidebar = ctk.CTkFrame(
            self, width=220, fg_color=SIDEBAR, corner_radius=0
        )
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)

        brand = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        brand.pack(fill="x", padx=17, pady=(23, 28))

        logo = ctk.CTkFrame(
            brand, width=42, height=42,
            corner_radius=12, fg_color="#164641"
        )
        logo.pack(side="left")
        logo.pack_propagate(False)
        self.label(logo, "N", 23, CYAN, True).place(
            relx=0.5, rely=0.5, anchor="center"
        )

        brand_text = ctk.CTkFrame(brand, fg_color="transparent")
        brand_text.pack(side="left", padx=9)
        self.label(
            brand_text, "NETGUARD", 17, TEXT, True
        ).pack(anchor="w")
        self.label(
            brand_text, "NETWORK ANALYTICS", 9, CYAN, True
        ).pack(anchor="w")

        self.label(
            self.sidebar, "WORKSPACE", 10, MUTED, True
        ).pack(anchor="w", padx=20, pady=(0, 10))

        self.nav_buttons = {}
        items = [
            ("Dashboard", self.show_dashboard),
            ("Analyze PCAP", self.show_analyzer),
            ("Threats", self.show_threats),
            ("Protocols", self.show_protocols),
            ("IP Activity", self.show_ip_activity),
            ("Reports", self.show_reports),
        ]

        for name, command in items:
            btn = ctk.CTkButton(
                self.sidebar,
                text=f"    {name}",
                command=command,
                anchor="w",
                height=42,
                corner_radius=8,
                fg_color="transparent",
                hover_color=CARD_ALT,
                text_color=TEXT,
                font=ctk.CTkFont(size=12, weight="bold"),
            )
            btn.pack(fill="x", padx=12, pady=3)
            self.nav_buttons[name] = btn

        spacer = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        spacer.pack(fill="both", expand=True)

        status_card = self.card(self.sidebar)
        status_card.pack(fill="x", padx=12, pady=12)
        self.label(
            status_card, "●  LOCAL ANALYZER", 10, GREEN, True
        ).pack(anchor="w", padx=12, pady=(12, 5))
        self.label(
            status_card, "PCAP investigation", 10, MUTED
        ).pack(anchor="w", padx=12, pady=(0, 12))

        self.label(
            self.sidebar, "NETGUARD · LOCAL ANALYSIS", 9, MUTED
        ).pack(anchor="w", padx=15, pady=(0, 15))

    def build_main_area(self):
        self.main = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        self.main.grid(row=0, column=1, sticky="nsew")
        self.main.grid_columnconfigure(0, weight=1)
        self.main.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(
            self.main, fg_color=SIDEBAR, height=62, corner_radius=0
        )
        header.grid(row=0, column=0, sticky="ew")
        header.grid_propagate(False)
        header.grid_columnconfigure(0, weight=1)

        self.label(
            header, "Network Security Workbench", 14, TEXT, True
        ).grid(row=0, column=0, sticky="w", padx=22)

        self.status_label = self.label(
            header, "●  Ready", 11, GREEN
        )
        self.status_label.grid(row=0, column=1, padx=20)

        self.content = ctk.CTkFrame(
            self.main, fg_color=BG, corner_radius=0
        )
        self.content.grid(row=1, column=0, sticky="nsew")
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(0, weight=1)

    def navigate(self, page_name):
        self.current_page = page_name
        for name, btn in self.nav_buttons.items():
            selected = name == page_name
            btn.configure(
                fg_color="#164641" if selected else "transparent",
                text_color=CYAN if selected else TEXT,
            )

    # ---------- Dashboard ----------
    def show_dashboard(self):
        self.navigate("Dashboard")
        self.clear_page()
        page = self.make_scroll_page()

        self.heading(
            page, "Security dashboard",
            "Analyze saved network captures and review traffic activity.",
        )

        metrics = ctk.CTkFrame(page, fg_color="transparent")
        metrics.pack(fill="x", padx=20, pady=(0, 18))
        for i in range(3):
            metrics.grid_columnconfigure(i, weight=1, uniform="metric")

        packet_count = (
            self.results.get("total_packets", 0) if self.results else 0
        )
        source_count = (
            len(self.results.get("source_ips", {})) if self.results else 0
        )

        for i, (title, value, color) in enumerate([
            ("PACKETS ANALYZED", packet_count, CYAN),
            ("SOURCE ADDRESSES", source_count, BLUE),
            ("POTENTIAL ALERTS", len(self.alerts), AMBER),
        ]):
            panel = self.card(metrics)
            panel.grid(row=0, column=i, sticky="ew", padx=5)
            self.label(
                panel, title, 10, MUTED, True
            ).pack(anchor="w", padx=15, pady=(15, 5))
            self.label(
                panel, f"{value:,}", 25, color, True
            ).pack(anchor="w", padx=15, pady=(0, 15))

        capture = self.card(page)
        capture.pack(fill="x", padx=25, pady=(0, 16))
        self.label(
            capture, "PCAP INVESTIGATION", 10, CYAN, True
        ).pack(anchor="w", padx=17, pady=(16, 6))

        self.label(
            capture,
            str(self.capture_path) if self.capture_path else "No capture selected",
            12, TEXT, wraplength=850, justify="left",
        ).pack(anchor="w", padx=17, pady=(0, 12))

        actions = ctk.CTkFrame(capture, fg_color="transparent")
        actions.pack(fill="x", padx=17, pady=(0, 16))

        self.button(
            actions, "Choose PCAP  →", self.choose_capture, primary=True
        ).pack(side="left")
        self.button(
            actions, "Open analyzer", self.show_analyzer
        ).pack(side="left", padx=8)

        quick = self.card(page)
        quick.pack(fill="x", padx=25, pady=(0, 20))
        self.label(
            quick, "QUICK ACCESS", 13, TEXT, True
        ).pack(anchor="w", padx=17, pady=(15, 8))

        for title, command in [
            ("Analyze traffic", self.show_analyzer),
            ("Review possible threats", self.show_threats),
            ("View protocol statistics", self.show_protocols),
            ("Open reports", self.show_reports),
        ]:
            self.button(
                quick, title, command
            ).pack(fill="x", padx=15, pady=4)

        ctk.CTkFrame(
            quick, fg_color="transparent", height=8
        ).pack()

    def choose_capture(self):
        path = filedialog.askopenfilename(
            title="Select a PCAP file",
            filetypes=[
                ("Packet captures", "*.pcap *.pcapng"),
                ("All files", "*.*"),
            ],
        )
        if not path:
            return

        self.capture_path = Path(path)
        self.set_status("Capture selected", CYAN)
        # Automatically navigate to Analyze PCAP after selection.
        self.show_analyzer()

    # ---------- Analyze PCAP ----------
    def show_analyzer(self):
        self.navigate("Analyze PCAP")
        self.clear_page()
        page = self.make_scroll_page()

        self.heading(
            page, "Analyze PCAP",
            "Select a capture, configure detection and inspect the results.",
        )

        file_card = self.card(page)
        file_card.pack(fill="x", padx=25, pady=(0, 14))
        self.label(
            file_card, "01 · CAPTURE FILE", 10, CYAN, True
        ).pack(anchor="w", padx=17, pady=(15, 8))

        row = ctk.CTkFrame(file_card, fg_color="transparent")
        row.pack(fill="x", padx=17, pady=(0, 15))
        self.label(
            row, str(self.capture_path) if self.capture_path else "No file selected",
            11, MUTED, wraplength=650, justify="left",
        ).pack(side="left", fill="x", expand=True, padx=(0, 12))
        self.button(
            row, "Browse PCAP", self.choose_capture
        ).pack(side="right")

        settings = self.card(page)
        settings.pack(fill="x", padx=25, pady=(0, 14))
        self.label(
            settings, "02 · DETECTION SETTINGS", 10, CYAN, True
        ).pack(anchor="w", padx=17, pady=(15, 8))

        options = ctk.CTkFrame(settings, fg_color="transparent")
        options.pack(fill="x", padx=17, pady=(0, 15))
        self.label(
            options, "Port-scan threshold", 11, TEXT
        ).pack(side="left")

        self.threshold_entry = ctk.CTkEntry(
            options, width=80, textvariable=self.threshold,
            fg_color="#0D1523", border_color=BORDER,
        )
        self.threshold_entry.pack(side="left", padx=10)
        self.label(
            options, "Distinct ports · minimum 2", 10, MUTED
        ).pack(side="left")

        self.analyze_button = self.button(
            options, "Analyze capture  →", self.start_analysis,
            primary=True, width=155,
        )
        self.analyze_button.pack(side="right")

        results_card = self.card(page)
        results_card.pack(
            fill="both", expand=True, padx=25, pady=(0, 20)
        )
        self.label(
            results_card, "03 · ANALYSIS RESULTS", 10, CYAN, True
        ).pack(anchor="w", padx=17, pady=(15, 7))

        self.results_status = self.label(
            results_card, "Choose a file and click Analyze capture.",
            11, MUTED,
        )
        self.results_status.pack(anchor="w", padx=17, pady=(0, 10))

        self.results_body = ctk.CTkFrame(
            results_card, fg_color="transparent"
        )
        self.results_body.pack(
            fill="both", expand=True, padx=12, pady=(0, 12)
        )

        if self.results:
            self.render_results(self.results_body)

    def start_analysis(self):
        if self.busy:
            return
        if not self.capture_path or not self.capture_path.is_file():
            messagebox.showwarning(
                "Choose a PCAP", "Please select a valid capture file first."
            )
            return

        try:
            threshold = int(self.threshold.get())
            if threshold < 2:
                raise ValueError
        except ValueError:
            messagebox.showerror(
                "Invalid threshold",
                "Enter a whole number greater than or equal to 2.",
            )
            return

        self.busy = True
        self.analyze_button.configure(state="disabled", text="Analyzing...")
        self.threshold_entry.configure(state="disabled")
        self.results_status.configure(
            text="Analyzing packets and checking for possible port scans...",
            text_color=CYAN,
        )
        self.set_status("Analysis in progress", AMBER)

        threading.Thread(
            target=self.analysis_worker,
            args=(self.capture_path, threshold),
            daemon=True,
        ).start()

    def analysis_worker(self, capture_path, threshold):
        try:
            results = analyze_pcap(str(capture_path))
            report = generate_report(results)
            chart = create_protocol_chart(results)
            alerts = detect_threats(
                str(capture_path), port_threshold=threshold
            )
            threat_report = save_threat_report(alerts) if alerts else None

            data = {
                "results": results,
                "report": report,
                "chart": chart,
                "alerts": alerts,
                "threat_report": threat_report,
                "threshold": threshold,
                "error": None,
            }
        except Exception as exc:
            data = {"error": str(exc)}

        self.after(
            0, lambda: self.finish_analysis(capture_path, data)
        )

    def finish_analysis(self, capture_path, data):
        self.busy = False
        self.analyze_button.configure(
            state="normal", text="Analyze capture  →"
        )
        self.threshold_entry.configure(state="normal")

        if data.get("error"):
            self.results_status.configure(
                text="Analysis failed. See error details.",
                text_color=RED,
            )
            self.set_status("Analysis failed", RED)
            messagebox.showerror("Analysis failed", data["error"])
            return

        self.results = data["results"]
        self.report_path = data["report"]
        self.chart_path = data["chart"]
        self.alerts = data["alerts"]
        self.threat_report_path = data["threat_report"]
        self.last_threshold = data["threshold"]

        self.set_status("Analysis completed", GREEN)
        self.show_analyzer()
        self.results_status.configure(
            text=(
                f"Complete · {self.results.get('total_packets', 0):,} packets · "
                f"{len(self.alerts)} potential alert(s)"
            ),
            text_color=GREEN,
        )

    def render_results(self, parent):
        results = self.results
        box = self.text_box(parent, 260)
        box.pack(fill="both", expand=True, padx=5, pady=5)

        box.insert(
            "end",
            f"Capture: {self.capture_path}\n"
            f"Total packets: {results.get('total_packets', 0)}\n"
            f"Source IPs: {len(results.get('source_ips', {}))}\n"
            f"Destination IPs: {len(results.get('destination_ips', {}))}\n"
            f"Potential alerts: {len(self.alerts)}\n\n",
        )

        box.insert("end", "TRANSPORT COUNTS\n")
        for name, count in as_counter(
            results.get("transport_counts", {})
        ).most_common():
            box.insert("end", f"  {name}: {count}\n")

        box.insert("end", "\nPROTOCOL COUNTS\n")
        for name, count in as_counter(
            results.get("protocol_counts", {})
        ).most_common():
            box.insert("end", f"  {name}: {count}\n")

        box.insert("end", "\nTOP SOURCE IP ADDRESSES\n")
        for ip, count in as_counter(
            results.get("source_ips", {})
        ).most_common(10):
            box.insert("end", f"  {ip}: {count}\n")

        box.insert("end", "\nTOP DESTINATION IP ADDRESSES\n")
        for ip, count in as_counter(
            results.get("destination_ips", {})
        ).most_common(10):
            box.insert("end", f"  {ip}: {count}\n")

        box.insert("end", "\nDNS QUERIES\n")
        dns = as_counter(results.get("dns_queries", {}))
        if dns:
            for name, count in dns.most_common(30):
                box.insert("end", f"  {name}: {count}\n")
        else:
            box.insert("end", "  No DNS query names found.\n")

        box.insert("end", "\nPOTENTIAL THREATS\n")
        if not self.alerts:
            box.insert("end", "  No matching port-scan patterns detected.\n")
        else:
            for alert in self.alerts:
                box.insert("end", f"\n  {alert}\n")

        box.configure(state="disabled")

        actions = ctk.CTkFrame(parent, fg_color="transparent")
        actions.pack(fill="x", pady=(8, 0))
        self.button(
            actions, "Open CSV report", self.open_csv
        ).pack(side="left", padx=(0, 7))
        self.button(
            actions, "Open chart", self.open_chart
        ).pack(side="left", padx=7)
        self.button(
            actions, "Review threats", self.show_threats, primary=True
        ).pack(side="right")

    # ---------- Protocols ----------
    def show_protocols(self):
        self.navigate("Protocols")
        self.clear_page()
        page = self.make_scroll_page()
        self.heading(
            page, "Protocol analysis",
            "Explore protocol counts from the selected packet capture.",
        )

        panel = self.card(page)
        panel.pack(fill="x", padx=25, pady=(0, 20))

        if not self.results:
            self.label(
                panel, "Analyze a PCAP file to view protocol statistics.",
                12, MUTED,
            ).pack(anchor="w", padx=17, pady=18)
            self.button(
                panel, "Analyze PCAP", self.show_analyzer, primary=True
            ).pack(anchor="w", padx=17, pady=(0, 15))
            return

        counts = as_counter(self.results.get("transport_counts", {}))
        counts.update(self.results.get("protocol_counts", {}))

        for name, count in counts.most_common():
            self.stat_line(panel, name, f"{count} packets")

        self.button(
            panel, "Open protocol chart", self.open_chart
        ).pack(anchor="w", padx=15, pady=15)

    # ---------- IP Activity ----------
    def show_ip_activity(self):
        self.navigate("IP Activity")
        self.clear_page()
        page = self.make_scroll_page()
        self.heading(
            page, "IP activity",
            "Review the source and destination addresses in your capture.",
        )

        if not self.results:
            panel = self.card(page)
            panel.pack(fill="x", padx=25, pady=10)
            self.label(
                panel, "Analyze a PCAP file to see IP activity.",
                12, MUTED,
            ).pack(anchor="w", padx=17, pady=18)
            self.button(
                panel, "Analyze PCAP", self.show_analyzer, primary=True
            ).pack(anchor="w", padx=17, pady=(0, 15))
            return

        for title, key in [
            ("Top source IP addresses", "source_ips"),
            ("Top destination IP addresses", "destination_ips"),
        ]:
            panel = self.card(page)
            panel.pack(fill="x", padx=25, pady=(0, 14))
            self.label(
                panel, title, 14, TEXT, True
            ).pack(anchor="w", padx=16, pady=(14, 7))

            addresses = as_counter(self.results.get(key, {}))
            for ip, count in addresses.most_common(20):
                self.stat_line(panel, ip, f"{count} packets")

    # ---------- Threats ----------
    def show_threats(self):
        self.navigate("Threats")
        self.clear_page()
        page = self.make_scroll_page()
        self.heading(
            page, "Threat investigation",
            "Review potential port-scan patterns flagged by the detector.",
        )

        panel = self.card(page)
        panel.pack(fill="x", padx=25, pady=(0, 20))

        self.label(
            panel, f"{len(self.alerts)} potential alert(s)", 21,
            AMBER if self.alerts else GREEN, True,
        ).pack(anchor="w", padx=17, pady=(16, 5))

        self.label(
            panel, f"Port threshold: {self.last_threshold}", 11, MUTED
        ).pack(anchor="w", padx=17, pady=(0, 12))

        if not self.results:
            self.label(
                panel, "Run an analysis first to check for threats.",
                12, MUTED,
            ).pack(anchor="w", padx=17, pady=(0, 12))
            self.button(
                panel, "Analyze PCAP", self.show_analyzer, primary=True
            ).pack(anchor="w", padx=17, pady=(0, 16))
            return

        if not self.alerts:
            self.label(
                panel,
                "No port-scan patterns detected. This does not guarantee "
                "that all traffic is safe.",
                12, MUTED, wraplength=850, justify="left",
            ).pack(anchor="w", padx=17, pady=(0, 18))
            return

        box = self.text_box(panel, 300)
        box.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        for index, alert in enumerate(self.alerts, start=1):
            box.insert("end", f"POTENTIAL ALERT #{index}\n{alert}\n\n")
        box.configure(state="disabled")

        self.button(
            panel, "Open threat report", self.open_threat_report
        ).pack(anchor="w", padx=15, pady=(0, 15))

    # ---------- Reports ----------
    def show_reports(self):
        self.navigate("Reports")
        self.clear_page()
        page = self.make_scroll_page()
        self.heading(
            page, "Reports & exports",
            "Open generated traffic reports, charts and threat reports.",
        )

        panel = self.card(page)
        panel.pack(fill="x", padx=25, pady=(0, 15))
        self.label(
            panel, "LATEST ANALYSIS FILES", 12, CYAN, True
        ).pack(anchor="w", padx=17, pady=(15, 8))

        for title, path, command in [
            ("Traffic report (CSV)", self.report_path, self.open_csv),
            ("Protocol chart (PNG)", self.chart_path, self.open_chart),
            ("Threat report", self.threat_report_path,
             self.open_threat_report),
        ]:
            row = ctk.CTkFrame(panel, fg_color=CARD_ALT, corner_radius=8)
            row.pack(fill="x", padx=12, pady=5)

            self.label(row, title, 11, TEXT, True).pack(
                side="left", padx=12, pady=12
            )
            self.label(
                row, Path(path).name if path else "Not generated yet",
                10, MUTED,
            ).pack(side="left", padx=8)

            self.button(
                row, "Open", command, width=70
            ).pack(side="right", padx=9, pady=6)

        files_panel = self.card(page)
        files_panel.pack(fill="x", padx=25, pady=(0, 20))
        self.label(
            files_panel, "FILES IN REPORTS FOLDER", 12, CYAN, True
        ).pack(anchor="w", padx=17, pady=(15, 8))

        report_dir = PROJECT_DIR / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        files = sorted(
            report_dir.glob("*"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )

        if not files:
            self.label(
                files_panel, "No files generated yet.", 11, MUTED
            ).pack(anchor="w", padx=17, pady=(0, 15))

        for path in files[:30]:
            row = ctk.CTkFrame(files_panel, fg_color=CARD_ALT)
            row.pack(fill="x", padx=12, pady=4)
            self.label(row, path.name, 11, TEXT).pack(
                side="left", padx=10, pady=8
            )
            self.button(
                row, "Open",
                lambda selected=path: self.open_path(selected),
                width=70,
            ).pack(side="right", padx=8, pady=4)

    # ---------- File opening ----------
    def open_path(self, path):
        if not path:
            messagebox.showinfo(
                "Not available", "Generate the file by analyzing a PCAP first."
            )
            return

        path = Path(path)
        if not path.exists():
            messagebox.showwarning("File not found", str(path))
            return

        try:
            os.startfile(str(path))
        except Exception as exc:
            messagebox.showerror("Unable to open file", str(exc))

    def open_csv(self):
        self.open_path(self.report_path)

    def open_chart(self):
        self.open_path(self.chart_path)

    def open_threat_report(self):
        self.open_path(self.threat_report_path)


if __name__ == "__main__":
    app = NetGuardApp()
    app.mainloop()
