"""
Attack Surface Analyzer — Enumerate the system's attack surface including
open ports, running services, network shares, exposed RPC endpoints,
remote access tools, and provide a comprehensive risk score.
"""

import os
import socket
import subprocess
import psutil
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box


HIGH_RISK_PORTS = {
    21: ("FTP", "Cleartext auth"), 23: ("Telnet", "Cleartext remote access"),
    135: ("RPC", "DCE/RPC exploitation"), 139: ("NetBIOS", "Legacy info leak"),
    445: ("SMB", "EternalBlue / ransomware"), 1433: ("MSSQL", "DB exposed"),
    3306: ("MySQL", "DB exposed"), 3389: ("RDP", "BlueKeep / brute force"),
    5432: ("PostgreSQL", "DB exposed"), 5900: ("VNC", "Screen sharing"),
    5985: ("WinRM", "Remote management"), 6379: ("Redis", "No auth default"),
    8080: ("HTTP-Alt", "Admin panels"), 27017: ("MongoDB", "No auth default"),
}

REMOTE_ACCESS_TOOLS = [
    "teamviewer", "anydesk", "splashtop", "vnc", "ultraviewer",
    "rustdesk", "parsec", "ammyy", "logmein", "bomgar",
    "supremo", "connectwise", "gotomypc", "chrome remote",
]


def scan_port(ip: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def run_cmd(args, timeout=15):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception:
        return ""


class AttackSurfaceAnalyzer:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold #00ffcc]ATTACK SURFACE ANALYZER[/bold #00ffcc]\n"
                         "[dim]Enumerate open ports, services, shares, remote tools & risk score[/dim]"),
            border_style="#00ffcc", box=box.DOUBLE_EDGE,
        ))

        while True:
            c.print()
            table = Table(box=box.ROUNDED, border_style="#00ffcc", header_style="bold bright_cyan")
            table.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            table.add_column("ACTION", style="bold #00ffcc", width=55)
            table.add_row("1", "Full attack surface assessment")
            table.add_row("2", "Open port enumeration (localhost)")
            table.add_row("3", "Detect remote access tools")
            table.add_row("4", "Enumerate network shares")
            table.add_row("5", "Check exposed Windows services")
            table.add_row("6", "WMI / PowerShell Remoting status")
            table.add_row("0", "Return to main menu")
            c.print(Align.center(table))

            choice = Prompt.ask("  [bold #00ffcc]attack[/bold #00ffcc][dim]>[/dim]", default="0")

            if choice == "1":
                self._full_assessment()
            elif choice == "2":
                self._port_enum()
            elif choice == "3":
                self._detect_rat()
            elif choice == "4":
                self._enum_shares()
            elif choice == "5":
                self._exposed_services()
            elif choice == "6":
                self._remoting_status()
            elif choice == "0":
                break

    def _full_assessment(self):
        c = self.console
        risk_score = 0
        findings = []

        with Progress(
            SpinnerColumn(style="#00ffcc"),
            TextColumn("[bold #00ffcc]{task.description}[/bold #00ffcc]"),
            BarColumn(bar_width=40, complete_style="#00ffcc"),
            TimeElapsedColumn(),
            console=c,
        ) as progress:
            t = progress.add_task("Assessing attack surface...", total=5)

            # Port scan
            progress.update(t, description="Scanning high-risk ports")
            open_risky = []
            with ThreadPoolExecutor(max_workers=50) as ex:
                futures = {ex.submit(scan_port, "127.0.0.1", p): p for p in HIGH_RISK_PORTS}
                for fut in as_completed(futures):
                    p = futures[fut]
                    if fut.result():
                        svc, risk = HIGH_RISK_PORTS[p]
                        open_risky.append((p, svc, risk))
                        risk_score += 15

            for p, svc, risk in open_risky:
                findings.append(("OPEN PORT", f"{p}/{svc}", risk, "HIGH"))
            progress.advance(t)

            # Remote access
            progress.update(t, description="Detecting remote access tools")
            for proc in psutil.process_iter(["name"]):
                try:
                    name = (proc.info["name"] or "").lower()
                    for rat in REMOTE_ACCESS_TOOLS:
                        if rat in name:
                            findings.append(("REMOTE ACCESS", proc.info["name"], "Remote control software", "MED"))
                            risk_score += 10
                            break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            progress.advance(t)

            # Network shares
            progress.update(t, description="Enumerating shares")
            shares_output = run_cmd(["net", "share"])
            share_count = 0
            for line in shares_output.splitlines():
                if "$" not in line and "Share name" not in line and "---" not in line and line.strip():
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] not in ("The", "command"):
                        share_count += 1
                        findings.append(("SHARE", parts[0], "Non-default network share", "MED"))
                        risk_score += 5
            progress.advance(t)

            # Listening services count
            progress.update(t, description="Counting listening ports")
            conns = psutil.net_connections(kind="inet")
            listening = [c for c in conns if c.status == "LISTEN"]
            if len(listening) > 20:
                findings.append(("SERVICES", f"{len(listening)} listening", "Large attack surface", "HIGH"))
                risk_score += 15
            else:
                findings.append(("SERVICES", f"{len(listening)} listening", "Normal range", "LOW"))
            progress.advance(t)

            # Firewall check
            progress.update(t, description="Checking firewall")
            fw = run_cmd(["netsh", "advfirewall", "show", "allprofiles", "state"])
            if "OFF" in fw.upper():
                findings.append(("FIREWALL", "Profile disabled", "Firewall not fully active", "HIGH"))
                risk_score += 25
            else:
                findings.append(("FIREWALL", "All profiles ON", "Protected", "LOW"))
            progress.advance(t)

        # Display
        table = Table(
            title=f"[bold #00ffcc]Attack Surface Assessment ({len(findings)} items)[/bold #00ffcc]",
            box=box.DOUBLE_EDGE, border_style="#00ffcc", header_style="bold bright_cyan",
        )
        table.add_column("CATEGORY", style="bright_yellow", width=15)
        table.add_column("FINDING", style="bold bright_white", width=25)
        table.add_column("DETAIL", style="dim", width=35)
        table.add_column("RISK", style="bold", width=8)

        risk_col = {"HIGH": "bright_red", "MED": "bright_yellow", "LOW": "bright_green"}
        for cat, finding, detail, risk in findings:
            col = risk_col.get(risk, "white")
            table.add_row(cat, finding[:25], detail[:35], f"[{col}]{risk}[/{col}]")

        c.print()
        c.print(Align.center(table))

        # Risk score
        if risk_score >= 80:
            grade, grade_col = "F", "bright_red"
        elif risk_score >= 60:
            grade, grade_col = "D", "bright_red"
        elif risk_score >= 40:
            grade, grade_col = "C", "bright_yellow"
        elif risk_score >= 20:
            grade, grade_col = "B", "bright_green"
        else:
            grade, grade_col = "A", "bright_green"

        c.print(Panel(
            Align.center(
                f"[bold {grade_col}]SECURITY GRADE: {grade}[/bold {grade_col}]\n"
                f"[dim]Risk Score: {risk_score}/100[/dim]"
            ),
            border_style=grade_col, box=box.DOUBLE,
        ))

    def _port_enum(self):
        c = self.console
        table = Table(
            title="[bold #00ffcc]Listening Ports on Localhost[/bold #00ffcc]",
            box=box.DOUBLE_EDGE, border_style="#00ffcc", header_style="bold bright_cyan",
        )
        table.add_column("PORT", style="bright_yellow", width=8, justify="center")
        table.add_column("PROTOCOL", style="dim", width=8)
        table.add_column("PROCESS", style="bold bright_white", width=22)
        table.add_column("PID", style="dim", width=8)
        table.add_column("ADDRESS", style="bright_cyan", width=20)
        table.add_column("RISK", style="bold", width=10)

        conns = psutil.net_connections(kind="inet")
        listening = sorted([c for c in conns if c.status == "LISTEN"], key=lambda x: x.laddr.port)

        for conn in listening[:60]:
            port = conn.laddr.port
            try:
                proc_name = psutil.Process(conn.pid).name() if conn.pid else "?"
            except Exception:
                proc_name = "?"

            is_risky = port in HIGH_RISK_PORTS
            risk = f"[bright_red]HIGH[/bright_red]" if is_risky else "[bright_green]LOW[/bright_green]"
            addr = f"{conn.laddr.ip}:{port}"

            table.add_row(str(port), "TCP", proc_name[:22], str(conn.pid or "?"), addr, risk)

        c.print()
        c.print(Align.center(table))

    def _detect_rat(self):
        c = self.console
        found = []
        for proc in psutil.process_iter(["name", "pid", "exe"]):
            try:
                name = (proc.info["name"] or "").lower()
                for rat in REMOTE_ACCESS_TOOLS:
                    if rat in name:
                        found.append(proc.info)
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if not found:
            c.print("\n  [bold bright_green]No remote access tools detected.[/bold bright_green]")
            return

        table = Table(
            title=f"[bold bright_yellow]Remote Access Tools ({len(found)})[/bold bright_yellow]",
            box=box.DOUBLE_EDGE, border_style="bright_yellow", header_style="bold bright_cyan",
        )
        table.add_column("PROCESS", style="bold bright_red", width=25)
        table.add_column("PID", style="bright_yellow", width=8)
        table.add_column("PATH", style="dim", width=55)

        for p in found:
            table.add_row(p["name"][:25], str(p["pid"]), (p.get("exe") or "?")[:55])

        c.print()
        c.print(Align.center(table))

    def _enum_shares(self):
        c = self.console
        output = run_cmd(["net", "share"])
        c.print(Panel(f"[dim]{output[:500]}[/dim]",
                       title="[bold #00ffcc]Network Shares[/bold #00ffcc]",
                       border_style="#00ffcc"))

    def _exposed_services(self):
        c = self.console
        output = run_cmd(["sc", "query", "state=", "all"])

        running = []
        current = {}
        for line in output.splitlines():
            if "SERVICE_NAME:" in line:
                if current and current.get("state") == "RUNNING":
                    running.append(current)
                current = {"name": line.split(":", 1)[1].strip()}
            elif "STATE" in line and "RUNNING" in line:
                current["state"] = "RUNNING"

        if current and current.get("state") == "RUNNING":
            running.append(current)

        c.print(f"\n  [bold bright_cyan]{len(running)} running services[/bold bright_cyan]")
        for svc in running[:30]:
            c.print(f"    [bright_green]RUNNING[/bright_green]  {svc['name']}")

    def _remoting_status(self):
        c = self.console
        # WinRM
        winrm = run_cmd(["sc", "query", "WinRM"])
        winrm_running = "RUNNING" in winrm

        # PS Remoting
        ps_remote = run_cmd(["powershell", "-Command",
            "Test-WSMan -ErrorAction SilentlyContinue"])
        ps_enabled = "wsmid" in ps_remote.lower()

        # WMI
        wmi_running = "RUNNING" in run_cmd(["sc", "query", "Winmgmt"])

        c.print(Panel(
            f"[bright_cyan]WinRM Service:[/bright_cyan] [bold {'bright_red]RUNNING' if winrm_running else 'bright_green]STOPPED'}[/bold]\n"
            f"[bright_cyan]PS Remoting:[/bright_cyan] [bold {'bright_red]ENABLED' if ps_enabled else 'bright_green]DISABLED'}[/bold]\n"
            f"[bright_cyan]WMI Service:[/bright_cyan] [bold {'bright_yellow]RUNNING' if wmi_running else 'bright_green]STOPPED'}[/bold]\n\n"
            f"[dim]WinRM + PS Remoting allow remote code execution.\n"
            f"Disable if not explicitly needed.[/dim]",
            title="[bold #00ffcc]Remote Management Status[/bold #00ffcc]",
            border_style="#00ffcc",
        ))
