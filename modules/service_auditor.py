"""
Service Auditor — Enumerate Windows services, detect risky configurations,
find unquoted service paths, check permissions, and manage services.
"""

import subprocess
import os
import re
import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box


RISKY_SERVICE_CONFIGS = {
    "unquoted_path": "Unquoted service path (privilege escalation vector)",
    "writable_path": "Service binary in writable directory",
    "auto_start_disabled_defender": "Windows Defender disabled but auto-start",
    "remote_access": "Remote access service running",
}

REMOTE_ACCESS_SERVICES = {
    "termservice", "remoteregistry", "tlntsvr", "msrdp",
    "sessionenv", "umrdpservice", "sshd",
}

DANGEROUS_SERVICES = {
    "remoteregistry": "Remote Registry",
    "tlntsvr": "Telnet Server",
    "w3svc": "IIS Web Server",
    "ftpsvc": "FTP Server",
    "snmptrap": "SNMP Trap",
    "sshd": "OpenSSH Server",
}


def run_cmd(args, timeout=20):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception as e:
        return str(e)


def parse_sc_query_all(output: str) -> list[dict]:
    services = []
    current = {}
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("SERVICE_NAME:"):
            if current:
                services.append(current)
            current = {"name": line.split(":", 1)[1].strip()}
        elif "DISPLAY_NAME:" in line:
            current["display"] = line.split(":", 1)[1].strip()
        elif "STATE" in line:
            match = re.search(r'(\d+)\s+(\w+)', line)
            if match:
                current["state"] = match.group(2)
        elif "WIN32_OWN" in line or "WIN32_SHARE" in line:
            current["type"] = line.strip()

    if current:
        services.append(current)
    return services


class ServiceAuditor:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold bright_green]SERVICE AUDITOR[/bold bright_green]\n"
                         "[dim]Windows service enumeration, vulnerability scan & management[/dim]"),
            border_style="bright_green", box=box.DOUBLE_EDGE,
        ))

        while True:
            c.print()
            table = Table(box=box.ROUNDED, border_style="bright_green", header_style="bold bright_cyan")
            table.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            table.add_column("ACTION", style="bold bright_green", width=50)
            table.add_row("1", "List all running services")
            table.add_row("2", "List all stopped services")
            table.add_row("3", "Search services by name")
            table.add_row("4", "Scan for unquoted service paths")
            table.add_row("5", "Detect risky / dangerous services")
            table.add_row("6", "Start / Stop a service")
            table.add_row("7", "Get detailed service info")
            table.add_row("0", "Return to main menu")
            c.print(Align.center(table))

            choice = Prompt.ask("  [bold bright_green]svc[/bold bright_green][dim]>[/dim]", default="0")

            if choice == "1":
                self._list_services("running")
            elif choice == "2":
                self._list_services("stopped")
            elif choice == "3":
                self._search_service()
            elif choice == "4":
                self._scan_unquoted()
            elif choice == "5":
                self._detect_risky()
            elif choice == "6":
                self._start_stop()
            elif choice == "7":
                self._service_detail()
            elif choice == "0":
                break

    def _list_services(self, state: str):
        c = self.console
        output = run_cmd(["sc", "query", "type=", "service", "state=", "all"])
        services = parse_sc_query_all(output)

        if state == "running":
            services = [s for s in services if s.get("state") == "RUNNING"]
            title = "Running Services"
        else:
            services = [s for s in services if s.get("state") == "STOPPED"]
            title = "Stopped Services"

        table = Table(
            title=f"[bold bright_green]{title} ({len(services)})[/bold bright_green]",
            box=box.DOUBLE_EDGE, border_style="bright_green", header_style="bold bright_cyan",
        )
        table.add_column("#", style="dim", width=5)
        table.add_column("SERVICE NAME", style="bold bright_white", width=30)
        table.add_column("DISPLAY NAME", style="dim", width=45)
        table.add_column("STATE", style="bold", width=12)

        for i, svc in enumerate(services[:80], 1):
            state_col = "bright_green" if svc.get("state") == "RUNNING" else "bright_red"
            table.add_row(
                str(i),
                svc.get("name", "?")[:30],
                svc.get("display", "?")[:45],
                f"[{state_col}]{svc.get('state', '?')}[/{state_col}]",
            )

        c.print()
        c.print(table)

    def _search_service(self):
        c = self.console
        term = Prompt.ask("  [bright_cyan]Search term[/bright_cyan]")
        if not term.strip():
            return

        output = run_cmd(["sc", "query", "type=", "service", "state=", "all"])
        services = parse_sc_query_all(output)
        matches = [s for s in services
                   if term.lower() in s.get("name", "").lower()
                   or term.lower() in s.get("display", "").lower()]

        if not matches:
            c.print(f"  [bright_yellow]No services matching '{term}'[/bright_yellow]")
            return

        table = Table(box=box.ROUNDED, border_style="bright_green", header_style="bold bright_cyan")
        table.add_column("NAME", style="bold bright_white", width=30)
        table.add_column("DISPLAY", style="dim", width=40)
        table.add_column("STATE", style="bold", width=12)

        for s in matches:
            state_col = "bright_green" if s.get("state") == "RUNNING" else "bright_red"
            table.add_row(s.get("name", "?"), s.get("display", "?")[:40],
                          f"[{state_col}]{s.get('state', '?')}[/{state_col}]")

        c.print()
        c.print(Align.center(table))

    def _scan_unquoted(self):
        c = self.console
        c.print("\n  [bold bright_cyan]Scanning for unquoted service paths...[/bold bright_cyan]")

        output = run_cmd(["wmic", "service", "get", "name,displayname,pathname,startmode"])
        vulnerable = []

        for line in output.splitlines():
            line = line.strip()
            if not line or "PathName" in line:
                continue
            # Check for paths with spaces that are not quoted
            if " " in line and "C:\\" in line:
                # Extract the path portion
                match = re.search(r'([A-Z]:\\[^\s].*?\.\w{2,4})', line, re.IGNORECASE)
                if match:
                    path = match.group(1)
                    if " " in path and not path.startswith('"'):
                        vulnerable.append(line[:100])

        if not vulnerable:
            c.print("  [bold bright_green]No unquoted service paths found.[/bold bright_green]")
            return

        table = Table(
            title=f"[bold bright_red]Unquoted Service Paths ({len(vulnerable)})[/bold bright_red]",
            box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
        )
        table.add_column("#", style="dim", width=5)
        table.add_column("SERVICE DETAILS", style="bright_red", width=90)

        for i, v in enumerate(vulnerable, 1):
            table.add_row(str(i), v)

        c.print()
        c.print(Align.center(table))
        c.print("\n  [bright_yellow]Unquoted paths with spaces can be exploited for privilege escalation.[/bright_yellow]")

    def _detect_risky(self):
        c = self.console
        output = run_cmd(["sc", "query", "type=", "service", "state=", "all"])
        services = parse_sc_query_all(output)

        risky = []
        for svc in services:
            name = svc.get("name", "").lower()
            if name in DANGEROUS_SERVICES and svc.get("state") == "RUNNING":
                risky.append({
                    "name": svc.get("name", "?"),
                    "display": DANGEROUS_SERVICES.get(name, svc.get("display", "?")),
                    "reason": "Potentially dangerous service running",
                })
            if name in REMOTE_ACCESS_SERVICES and svc.get("state") == "RUNNING":
                risky.append({
                    "name": svc.get("name", "?"),
                    "display": svc.get("display", "?"),
                    "reason": "Remote access service active",
                })

        if not risky:
            c.print("  [bold bright_green]No risky services detected.[/bold bright_green]")
            return

        table = Table(
            title=f"[bold bright_red]Risky Services ({len(risky)})[/bold bright_red]",
            box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
        )
        table.add_column("SERVICE", style="bold bright_red", width=25)
        table.add_column("DESCRIPTION", style="bright_white", width=30)
        table.add_column("RISK", style="bright_yellow", width=40)

        for r in risky:
            table.add_row(r["name"], r["display"], r["reason"])

        c.print()
        c.print(Align.center(table))

    def _start_stop(self):
        c = self.console
        name = Prompt.ask("  [bright_cyan]Service name[/bright_cyan]")
        action = Prompt.ask("  Action", choices=["start", "stop"], default="stop")
        try:
            subprocess.run(["sc", action, name], capture_output=True, timeout=15)
            c.print(f"  [bright_green]Service '{name}' {action} command sent.[/bright_green]")
        except Exception as e:
            c.print(f"  [bright_red]Error: {e}[/bright_red]")

    def _service_detail(self):
        c = self.console
        name = Prompt.ask("  [bright_cyan]Service name[/bright_cyan]")
        output = run_cmd(["sc", "qc", name])

        table = Table(
            title=f"[bold bright_green]Service: {name}[/bold bright_green]",
            box=box.DOUBLE_EDGE, border_style="bright_green", header_style="bold bright_cyan",
        )
        table.add_column("PROPERTY", style="bold bright_white", width=25)
        table.add_column("VALUE", style="bright_cyan", width=60)

        for line in output.splitlines():
            if ":" in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    key = parts[0].strip()
                    val = parts[1].strip()
                    if key and val:
                        table.add_row(key, val)

        c.print()
        c.print(Align.center(table))
