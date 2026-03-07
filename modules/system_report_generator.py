"""
System Report Generator — Comprehensive security report combining all
scanner outputs into a single exportable security assessment.
Supports TXT, JSON, and HTML export formats.
"""

import os
import platform
import socket
import subprocess
import psutil
import time
import json
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box


def run_cmd(args, timeout=15):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception as e:
        return str(e)


def format_bytes(b: int) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


class SystemReportGenerator:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold bright_white]SYSTEM REPORT GENERATOR[/bold bright_white]\n"
                         "[dim]Comprehensive security & system assessment export[/dim]"),
            border_style="bright_white", box=box.DOUBLE_EDGE,
        ))

        while True:
            c.print()
            table = Table(box=box.ROUNDED, border_style="bright_white", header_style="bold bright_cyan")
            table.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            table.add_column("ACTION", style="bold bright_white", width=50)
            table.add_row("1", "Generate full security report (console)")
            table.add_row("2", "Export report to text file")
            table.add_row("3", "Export report to JSON")
            table.add_row("4", "Export report to HTML")
            table.add_row("5", "Quick system overview")
            table.add_row("6", "Network status report")
            table.add_row("7", "Security posture score")
            table.add_row("0", "Return to main menu")
            c.print(Align.center(table))

            choice = Prompt.ask("  [bold bright_white]report[/bold bright_white][dim]>[/dim]", default="0")

            if choice == "1":
                self._full_report()
            elif choice == "2":
                self._export_text()
            elif choice == "3":
                self._export_json()
            elif choice == "4":
                self._export_html()
            elif choice == "5":
                self._quick_overview()
            elif choice == "6":
                self._network_report()
            elif choice == "7":
                self._security_score()
            elif choice == "0":
                break

    def _gather_data(self) -> dict:
        data = {
            "timestamp": datetime.now().isoformat(),
            "hostname": socket.gethostname(),
            "os": {},
            "hardware": {},
            "network": {},
            "security": {},
            "processes": {},
        }

        # OS Info
        data["os"]["version"] = platform.version()
        data["os"]["platform"] = platform.platform()
        data["os"]["architecture"] = platform.machine()
        data["os"]["edition"] = str(platform.win32_edition()) if hasattr(platform, "win32_edition") else "N/A"

        # Hardware
        data["hardware"]["cpu_count"] = psutil.cpu_count()
        data["hardware"]["cpu_physical"] = psutil.cpu_count(logical=False)
        data["hardware"]["cpu_freq"] = str(psutil.cpu_freq().current if psutil.cpu_freq() else "N/A") + " MHz"
        mem = psutil.virtual_memory()
        data["hardware"]["ram_total"] = format_bytes(mem.total)
        data["hardware"]["ram_used"] = format_bytes(mem.used)
        data["hardware"]["ram_percent"] = f"{mem.percent}%"

        # Disk
        disks = []
        for part in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(part.mountpoint)
                disks.append({
                    "mount": part.mountpoint,
                    "total": format_bytes(usage.total),
                    "used": format_bytes(usage.used),
                    "free": format_bytes(usage.free),
                    "percent": f"{usage.percent}%",
                })
            except Exception:
                continue
        data["hardware"]["disks"] = disks

        # Network
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            data["network"]["local_ip"] = s.getsockname()[0]
            s.close()
        except Exception:
            data["network"]["local_ip"] = "N/A"

        conns = psutil.net_connections(kind="inet")
        data["network"]["total_connections"] = len(conns)
        data["network"]["established"] = sum(1 for c in conns if c.status == "ESTABLISHED")
        data["network"]["listening"] = sum(1 for c in conns if c.status == "LISTEN")

        # Security checks
        import winreg
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                                 0, winreg.KEY_READ)
            val, _ = winreg.QueryValueEx(key, "EnableLUA")
            data["security"]["uac"] = "Enabled" if val == 1 else "Disabled"
            winreg.CloseKey(key)
        except Exception:
            data["security"]["uac"] = "Unknown"

        fw_output = run_cmd(["netsh", "advfirewall", "show", "allprofiles", "state"])
        data["security"]["firewall"] = "ON" if "ON" in fw_output.upper() else "OFF"

        sb_output = run_cmd(["powershell", "-Command", "Confirm-SecureBootUEFI"])
        data["security"]["secure_boot"] = "Enabled" if "True" in sb_output else "Disabled"

        # Processes
        data["processes"]["total"] = len(list(psutil.process_iter()))
        data["processes"]["cpu_usage"] = f"{psutil.cpu_percent(interval=1)}%"

        return data

    def _full_report(self):
        c = self.console

        with Progress(
            SpinnerColumn(style="bright_white"),
            TextColumn("[bold bright_white]{task.description}[/bold bright_white]"),
            BarColumn(bar_width=40),
            TimeElapsedColumn(),
            console=c,
        ) as progress:
            t = progress.add_task("Gathering system data...", total=None)
            data = self._gather_data()

        self._display_report(data)

    def _display_report(self, data: dict):
        c = self.console

        # Header
        c.print()
        c.print(Panel(
            Align.center(
                f"[bold bright_white]COSMOS.WIN SECURITY REPORT[/bold bright_white]\n"
                f"[dim]Generated: {data['timestamp']}[/dim]\n"
                f"[dim]Hostname: {data['hostname']}[/dim]"
            ),
            border_style="bright_cyan", box=box.DOUBLE_EDGE,
        ))

        # OS Section
        os_table = Table(title="[bold bright_cyan]Operating System[/bold bright_cyan]",
                         box=box.ROUNDED, border_style="bright_cyan", header_style="bold bright_cyan")
        os_table.add_column("PROPERTY", style="bold bright_white", width=20)
        os_table.add_column("VALUE", style="bright_cyan", width=50)
        for key, val in data["os"].items():
            os_table.add_row(key.replace("_", " ").title(), str(val))
        c.print(os_table)

        # Hardware Section
        hw_table = Table(title="[bold bright_yellow]Hardware[/bold bright_yellow]",
                         box=box.ROUNDED, border_style="bright_yellow", header_style="bold bright_cyan")
        hw_table.add_column("PROPERTY", style="bold bright_white", width=20)
        hw_table.add_column("VALUE", style="bright_yellow", width=50)
        for key, val in data["hardware"].items():
            if key != "disks":
                hw_table.add_row(key.replace("_", " ").title(), str(val))
        c.print(hw_table)

        # Disk Section
        if data["hardware"]["disks"]:
            disk_table = Table(title="[bold bright_magenta]Disk Usage[/bold bright_magenta]",
                               box=box.ROUNDED, border_style="bright_magenta", header_style="bold bright_cyan")
            disk_table.add_column("MOUNT", style="bold bright_white", width=10)
            disk_table.add_column("TOTAL", style="bright_cyan", width=12, justify="right")
            disk_table.add_column("USED", style="bright_yellow", width=12, justify="right")
            disk_table.add_column("FREE", style="bright_green", width=12, justify="right")
            disk_table.add_column("USAGE", style="bold", width=10, justify="center")
            for disk in data["hardware"]["disks"]:
                disk_table.add_row(disk["mount"], disk["total"], disk["used"], disk["free"], disk["percent"])
            c.print(disk_table)

        # Network Section
        net_table = Table(title="[bold bright_blue]Network[/bold bright_blue]",
                          box=box.ROUNDED, border_style="bright_blue", header_style="bold bright_cyan")
        net_table.add_column("PROPERTY", style="bold bright_white", width=20)
        net_table.add_column("VALUE", style="bright_blue", width=50)
        for key, val in data["network"].items():
            net_table.add_row(key.replace("_", " ").title(), str(val))
        c.print(net_table)

        # Security Section
        sec_table = Table(title="[bold bright_red]Security Status[/bold bright_red]",
                          box=box.ROUNDED, border_style="bright_red", header_style="bold bright_cyan")
        sec_table.add_column("CHECK", style="bold bright_white", width=20)
        sec_table.add_column("STATUS", style="bold", width=50)
        for key, val in data["security"].items():
            col = "bright_green" if val in ("Enabled", "ON") else "bright_red"
            sec_table.add_row(key.replace("_", " ").upper(), f"[{col}]{val}[/{col}]")
        c.print(sec_table)

    def _export_text(self):
        c = self.console
        data = self._gather_data()
        path = os.path.join(os.path.expanduser("~"), "Desktop", f"cosmos_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")

        try:
            with open(path, "w") as f:
                f.write("=" * 60 + "\n")
                f.write("COSMOS.WIN SECURITY REPORT\n")
                f.write(f"Generated: {data['timestamp']}\n")
                f.write(f"Hostname: {data['hostname']}\n")
                f.write("=" * 60 + "\n\n")

                for section, items in data.items():
                    if section in ("timestamp", "hostname"):
                        continue
                    f.write(f"\n--- {section.upper()} ---\n")
                    if isinstance(items, dict):
                        for key, val in items.items():
                            f.write(f"  {key}: {val}\n")
                    else:
                        f.write(f"  {items}\n")

            c.print(f"\n  [bold bright_green]Report saved to {path}[/bold bright_green]")
        except Exception as e:
            c.print(f"  [bright_red]Error: {e}[/bright_red]")

    def _export_json(self):
        c = self.console
        data = self._gather_data()
        path = os.path.join(os.path.expanduser("~"), "Desktop", f"cosmos_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

        try:
            with open(path, "w") as f:
                json.dump(data, f, indent=2, default=str)
            c.print(f"\n  [bold bright_green]JSON report saved to {path}[/bold bright_green]")
        except Exception as e:
            c.print(f"  [bright_red]Error: {e}[/bright_red]")

    def _quick_overview(self):
        c = self.console
        c.print()
        mem = psutil.virtual_memory()
        cpu = psutil.cpu_percent(interval=1)
        conns = len(psutil.net_connections(kind="inet"))
        procs = len(list(psutil.process_iter()))

        c.print(Panel(
            f"[bright_cyan]CPU Usage:[/bright_cyan] {cpu}%\n"
            f"[bright_cyan]RAM Usage:[/bright_cyan] {mem.percent}% ({format_bytes(mem.used)} / {format_bytes(mem.total)})\n"
            f"[bright_cyan]Processes:[/bright_cyan] {procs}\n"
            f"[bright_cyan]Network Connections:[/bright_cyan] {conns}\n"
            f"[bright_cyan]Hostname:[/bright_cyan] {socket.gethostname()}\n"
            f"[bright_cyan]OS:[/bright_cyan] {platform.platform()}",
            title="[bold bright_white]Quick Overview[/bold bright_white]",
            border_style="bright_cyan", box=box.DOUBLE_EDGE,
        ))

    def _network_report(self):
        c = self.console
        conns = psutil.net_connections(kind="inet")

        table = Table(
            title="[bold bright_blue]Network Status Report[/bold bright_blue]",
            box=box.DOUBLE_EDGE, border_style="bright_blue", header_style="bold bright_cyan",
        )
        table.add_column("METRIC", style="bold bright_white", width=30)
        table.add_column("VALUE", style="bright_cyan", width=20, justify="center")

        statuses = {}
        for conn in conns:
            statuses[conn.status] = statuses.get(conn.status, 0) + 1

        table.add_row("Total Connections", str(len(conns)))
        for status, count in sorted(statuses.items(), key=lambda x: x[1], reverse=True):
            table.add_row(f"  {status}", str(count))

        # Network interfaces
        table.add_row("", "")
        table.add_row("[bold]Network Interfaces[/bold]", "")
        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    table.add_row(f"  {name}", addr.address)

        c.print()
        c.print(Align.center(table))

    def _export_html(self):
        c = self.console
        data = self._gather_data()
        path = os.path.join(os.path.expanduser("~"), "Desktop",
                           f"cosmos_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")

        try:
            html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Cosmos.win Security Report</title>
<style>
body {{ font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #e6edf3; margin: 0; padding: 2rem; }}
.container {{ max-width: 900px; margin: 0 auto; }}
h1 {{ color: #00ffcc; text-align: center; font-size: 2rem; }}
h2 {{ color: #4fc3f7; border-bottom: 1px solid #333; padding-bottom: 0.5rem; }}
.meta {{ text-align: center; color: #888; margin-bottom: 2rem; }}
table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
th {{ background: #161b22; color: #00ffcc; padding: 10px; text-align: left; border: 1px solid #333; }}
td {{ padding: 8px 10px; border: 1px solid #222; }}
tr:nth-child(even) {{ background: #161b22; }}
.pass {{ color: #00e676; font-weight: bold; }}
.fail {{ color: #ff1744; font-weight: bold; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.85rem; }}
.badge-green {{ background: #00e67622; color: #00e676; }}
.badge-red {{ background: #ff174422; color: #ff1744; }}
</style>
</head>
<body>
<div class="container">
<h1>COSMOS.WIN SECURITY REPORT</h1>
<div class="meta">Generated: {data['timestamp']} | Hostname: {data['hostname']}</div>

<h2>Operating System</h2>
<table>"""
            for key, val in data["os"].items():
                html += f"<tr><td><strong>{key.replace('_', ' ').title()}</strong></td><td>{val}</td></tr>\n"
            html += "</table>\n"

            html += "<h2>Hardware</h2><table>\n"
            for key, val in data["hardware"].items():
                if key != "disks":
                    html += f"<tr><td><strong>{key.replace('_', ' ').title()}</strong></td><td>{val}</td></tr>\n"
            html += "</table>\n"

            if data["hardware"]["disks"]:
                html += "<h2>Disk Usage</h2><table><tr><th>Mount</th><th>Total</th><th>Used</th><th>Free</th><th>Usage</th></tr>\n"
                for disk in data["hardware"]["disks"]:
                    html += f"<tr><td>{disk['mount']}</td><td>{disk['total']}</td><td>{disk['used']}</td><td>{disk['free']}</td><td>{disk['percent']}</td></tr>\n"
                html += "</table>\n"

            html += "<h2>Network</h2><table>\n"
            for key, val in data["network"].items():
                html += f"<tr><td><strong>{key.replace('_', ' ').title()}</strong></td><td>{val}</td></tr>\n"
            html += "</table>\n"

            html += "<h2>Security Status</h2><table>\n"
            for key, val in data["security"].items():
                css_class = "pass" if val in ("Enabled", "ON") else "fail"
                html += f'<tr><td><strong>{key.replace("_", " ").upper()}</strong></td><td class="{css_class}">{val}</td></tr>\n'
            html += "</table>\n"

            html += """
</div>
</body>
</html>"""

            with open(path, "w", encoding="utf-8") as f:
                f.write(html)

            c.print(f"\n  [bold bright_green]HTML report saved to {path}[/bold bright_green]")
        except Exception as e:
            c.print(f"  [bright_red]Error: {e}[/bright_red]")

    def _security_score(self):
        """Calculate an overall security posture score."""
        c = self.console
        score = 100
        findings = []

        with Progress(
            SpinnerColumn(style="bright_white"),
            TextColumn("[bold bright_white]{task.description}[/bold bright_white]"),
            BarColumn(bar_width=40),
            console=c,
        ) as progress:
            t = progress.add_task("Evaluating security posture...", total=None)
            data = self._gather_data()

        # Evaluate security settings
        if data["security"].get("firewall") != "ON":
            score -= 25
            findings.append(("[bright_red]FAIL[/bright_red]", "Firewall is OFF", "-25"))
        else:
            findings.append(("[bright_green]PASS[/bright_green]", "Firewall is ON", "+0"))

        if data["security"].get("uac") != "Enabled":
            score -= 20
            findings.append(("[bright_red]FAIL[/bright_red]", "UAC is disabled", "-20"))
        else:
            findings.append(("[bright_green]PASS[/bright_green]", "UAC is enabled", "+0"))

        if data["security"].get("secure_boot") != "Enabled":
            score -= 10
            findings.append(("[bright_yellow]WARN[/bright_yellow]", "Secure Boot not confirmed", "-10"))
        else:
            findings.append(("[bright_green]PASS[/bright_green]", "Secure Boot is enabled", "+0"))

        # Check RAM usage
        mem_pct = float(data["hardware"].get("ram_percent", "0%").replace("%", ""))
        if mem_pct > 90:
            score -= 5
            findings.append(("[bright_yellow]WARN[/bright_yellow]", f"High RAM usage: {mem_pct}%", "-5"))

        # Check listening ports
        listening = data["network"].get("listening", 0)
        if listening > 20:
            score -= 10
            findings.append(("[bright_yellow]WARN[/bright_yellow]", f"Many listening ports: {listening}", "-10"))

        score = max(0, score)

        if score >= 80:
            grade, grade_col = "A - EXCELLENT", "bright_green"
        elif score >= 60:
            grade, grade_col = "B - GOOD", "bright_cyan"
        elif score >= 40:
            grade, grade_col = "C - FAIR", "bright_yellow"
        else:
            grade, grade_col = "D - POOR", "bright_red"

        c.print(Panel(
            Align.center(
                f"[bold {grade_col}]{grade}[/bold {grade_col}]\n\n"
                f"[bold bright_white]Security Score: {score}/100[/bold bright_white]"
            ),
            title="[bold bright_white]Security Posture[/bold bright_white]",
            border_style=grade_col, box=box.DOUBLE_EDGE,
        ))

        table = Table(box=box.ROUNDED, border_style="bright_cyan", header_style="bold bright_cyan")
        table.add_column("STATUS", width=12, justify="center")
        table.add_column("CHECK", style="bold bright_white", width=35)
        table.add_column("IMPACT", style="dim", width=10, justify="center")
        for status, check, impact in findings:
            table.add_row(status, check, impact)

        c.print()
        c.print(Align.center(table))
