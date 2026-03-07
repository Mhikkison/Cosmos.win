"""
Log Analyzer — Parse and analyze Windows Event Logs for security events,
failed logins, privilege escalations, service changes, and suspicious activity.
"""

import subprocess
import re
import time
from datetime import datetime, timedelta
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box


SECURITY_EVENT_IDS = {
    4624: ("Successful Logon", "bright_green"),
    4625: ("Failed Logon", "bright_red"),
    4626: ("User/Device Claims", "dim"),
    4634: ("Logoff", "dim"),
    4648: ("Explicit Credential Logon", "bright_yellow"),
    4672: ("Special Privileges Assigned", "bright_magenta"),
    4688: ("Process Created", "bright_cyan"),
    4689: ("Process Terminated", "dim"),
    4697: ("Service Installed", "bright_yellow"),
    4698: ("Scheduled Task Created", "bright_yellow"),
    4720: ("User Account Created", "bright_yellow"),
    4722: ("User Account Enabled", "bright_yellow"),
    4724: ("Password Reset Attempt", "bright_magenta"),
    4725: ("User Account Disabled", "bright_yellow"),
    4726: ("User Account Deleted", "bright_red"),
    4728: ("Member Added to Security Group", "bright_yellow"),
    4732: ("Member Added to Local Group", "bright_yellow"),
    4735: ("Local Group Changed", "bright_yellow"),
    4738: ("User Account Changed", "bright_yellow"),
    4740: ("Account Locked Out", "bright_red"),
    4756: ("Member Added to Universal Group", "bright_yellow"),
    4767: ("Account Unlocked", "bright_cyan"),
    4776: ("NTLM Authentication", "bright_cyan"),
    5140: ("Network Share Accessed", "bright_cyan"),
    5156: ("Windows Filtering Platform Connection", "dim"),
    7045: ("New Service Installed", "bright_yellow"),
}

BRUTE_FORCE_THRESHOLD = 5
SUSPICIOUS_LOGON_TYPES = {"3": "Network", "10": "RemoteInteractive", "8": "NetworkCleartext"}


def run_ps(command: str, timeout: int = 30) -> str:
    try:
        r = subprocess.run(
            ["powershell", "-Command", command],
            capture_output=True, text=True, timeout=timeout
        )
        return r.stdout
    except Exception as e:
        return str(e)


class LogAnalyzer:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold bright_blue]LOG ANALYZER[/bold bright_blue]\n"
                         "[dim]Windows Event Log parser for security analysis & threat detection[/dim]"),
            border_style="bright_blue", box=box.DOUBLE_EDGE,
        ))

        while True:
            c.print()
            table = Table(box=box.ROUNDED, border_style="bright_blue", header_style="bold bright_cyan")
            table.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            table.add_column("ACTION", style="bold bright_blue", width=50)
            table.add_row("1", "View recent security events")
            table.add_row("2", "Detect failed login attempts (brute force)")
            table.add_row("3", "Check privilege escalation events")
            table.add_row("4", "View new service installations")
            table.add_row("5", "Account management events")
            table.add_row("6", "Search events by ID")
            table.add_row("7", "Security event summary (last 24h)")
            table.add_row("0", "Return to main menu")
            c.print(Align.center(table))

            choice = Prompt.ask("  [bold bright_blue]log[/bold bright_blue][dim]>[/dim]", default="0")

            if choice == "1":
                self._recent_security()
            elif choice == "2":
                self._detect_brute_force()
            elif choice == "3":
                self._privilege_escalation()
            elif choice == "4":
                self._service_installs()
            elif choice == "5":
                self._account_management()
            elif choice == "6":
                self._search_by_id()
            elif choice == "7":
                self._event_summary()
            elif choice == "0":
                break

    def _recent_security(self):
        c = self.console
        count = Prompt.ask("  [bright_cyan]Number of events[/bright_cyan]", default="50")
        output = run_ps(
            f"Get-WinEvent -LogName Security -MaxEvents {count} | "
            f"Select-Object TimeCreated, Id, LevelDisplayName, Message | "
            f"Format-List"
        )

        events = self._parse_events(output)
        if not events:
            c.print("  [bright_yellow]No events found or access denied.[/bright_yellow]")
            return

        table = Table(
            title=f"[bold bright_blue]Recent Security Events ({len(events)})[/bold bright_blue]",
            box=box.DOUBLE_EDGE, border_style="bright_blue", header_style="bold bright_cyan",
        )
        table.add_column("TIME", style="dim", width=22)
        table.add_column("ID", style="bright_yellow", width=8, justify="center")
        table.add_column("EVENT", style="bold bright_white", width=30)
        table.add_column("DETAIL", style="dim", width=40)

        for ev in events[:60]:
            event_id = ev.get("id", 0)
            name, col = SECURITY_EVENT_IDS.get(event_id, (f"Event {event_id}", "dim"))
            table.add_row(
                ev.get("time", "?")[:22],
                str(event_id),
                f"[{col}]{name}[/{col}]",
                ev.get("message", "")[:40],
            )

        c.print()
        c.print(Align.center(table))

    def _detect_brute_force(self):
        c = self.console
        c.print("\n  [bold bright_cyan]Checking for brute force attempts (Event 4625)...[/bold bright_cyan]")

        output = run_ps(
            "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 500 -ErrorAction SilentlyContinue | "
            "Select-Object TimeCreated, Message | Format-List"
        )

        events = self._parse_events(output)
        if not events:
            c.print("  [bright_green]No failed login events found.[/bright_green]")
            return

        # Group by source IP or account
        account_fails: dict[str, int] = {}
        for ev in events:
            msg = ev.get("message", "")
            account_match = re.search(r"Account Name:\s*(\S+)", msg)
            if account_match:
                acct = account_match.group(1)
                account_fails[acct] = account_fails.get(acct, 0) + 1

        table = Table(
            title=f"[bold bright_red]Failed Login Attempts ({len(events)} total)[/bold bright_red]",
            box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
        )
        table.add_column("ACCOUNT", style="bold bright_white", width=30)
        table.add_column("FAILURES", style="bold", width=12, justify="center")
        table.add_column("ASSESSMENT", style="bold", width=20)

        for acct, count in sorted(account_fails.items(), key=lambda x: x[1], reverse=True):
            if count >= BRUTE_FORCE_THRESHOLD:
                assess = "[bright_red]BRUTE FORCE[/bright_red]"
            elif count >= 3:
                assess = "[bright_yellow]SUSPICIOUS[/bright_yellow]"
            else:
                assess = "[bright_green]NORMAL[/bright_green]"
            col = "bright_red" if count >= BRUTE_FORCE_THRESHOLD else "bright_yellow"
            table.add_row(acct, f"[{col}]{count}[/{col}]", assess)

        c.print()
        c.print(Align.center(table))

    def _privilege_escalation(self):
        c = self.console
        output = run_ps(
            "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4672} -MaxEvents 100 -ErrorAction SilentlyContinue | "
            "Select-Object TimeCreated, Message | Format-List"
        )
        events = self._parse_events(output)
        if not events:
            c.print("  [dim]No privilege escalation events found.[/dim]")
            return

        table = Table(
            title=f"[bold bright_magenta]Privilege Escalation Events ({len(events)})[/bold bright_magenta]",
            box=box.DOUBLE_EDGE, border_style="bright_magenta", header_style="bold bright_cyan",
        )
        table.add_column("TIME", style="dim", width=22)
        table.add_column("ACCOUNT", style="bold bright_white", width=25)
        table.add_column("PRIVILEGES", style="bright_magenta", width=50)

        for ev in events[:30]:
            msg = ev.get("message", "")
            acct_match = re.search(r"Account Name:\s*(\S+)", msg)
            acct = acct_match.group(1) if acct_match else "?"
            table.add_row(ev.get("time", "?")[:22], acct, "Special privileges assigned")

        c.print()
        c.print(Align.center(table))

    def _service_installs(self):
        c = self.console
        output = run_ps(
            "Get-WinEvent -FilterHashtable @{LogName='System';Id=7045} -MaxEvents 50 -ErrorAction SilentlyContinue | "
            "Select-Object TimeCreated, Message | Format-List"
        )
        events = self._parse_events(output)
        if not events:
            c.print("  [dim]No recent service installations found.[/dim]")
            return

        table = Table(
            title=f"[bold bright_yellow]New Service Installations ({len(events)})[/bold bright_yellow]",
            box=box.DOUBLE_EDGE, border_style="bright_yellow", header_style="bold bright_cyan",
        )
        table.add_column("TIME", style="dim", width=22)
        table.add_column("DETAIL", style="bright_white", width=70)

        for ev in events:
            table.add_row(ev.get("time", "?")[:22], ev.get("message", "?")[:70])

        c.print()
        c.print(Align.center(table))

    def _account_management(self):
        c = self.console
        acct_ids = [4720, 4722, 4724, 4725, 4726, 4738, 4740, 4767]
        id_filter = ",".join(str(i) for i in acct_ids)
        output = run_ps(
            f"Get-WinEvent -FilterHashtable @{{LogName='Security';Id={id_filter}}} -MaxEvents 100 -ErrorAction SilentlyContinue | "
            f"Select-Object TimeCreated, Id, Message | Format-List"
        )
        events = self._parse_events(output)
        if not events:
            c.print("  [dim]No account management events found.[/dim]")
            return

        table = Table(
            title=f"[bold bright_yellow]Account Management Events ({len(events)})[/bold bright_yellow]",
            box=box.DOUBLE_EDGE, border_style="bright_yellow", header_style="bold bright_cyan",
        )
        table.add_column("TIME", style="dim", width=22)
        table.add_column("ID", style="bright_yellow", width=8)
        table.add_column("EVENT", style="bold bright_white", width=30)
        table.add_column("DETAIL", style="dim", width=40)

        for ev in events[:40]:
            eid = ev.get("id", 0)
            name, col = SECURITY_EVENT_IDS.get(eid, (f"Event {eid}", "dim"))
            table.add_row(ev.get("time", "?")[:22], str(eid), f"[{col}]{name}[/{col}]",
                          ev.get("message", "")[:40])

        c.print()
        c.print(Align.center(table))

    def _search_by_id(self):
        c = self.console
        event_id = Prompt.ask("  [bright_cyan]Event ID[/bright_cyan]")
        log_name = Prompt.ask("  Log", choices=["Security", "System", "Application"], default="Security")
        output = run_ps(
            f"Get-WinEvent -FilterHashtable @{{LogName='{log_name}';Id={event_id}}} -MaxEvents 30 -ErrorAction SilentlyContinue | "
            f"Select-Object TimeCreated, Id, Message | Format-List"
        )
        events = self._parse_events(output)
        if not events:
            c.print(f"  [dim]No events with ID {event_id} found in {log_name}.[/dim]")
            return

        for ev in events[:10]:
            c.print(Panel(
                f"[bright_yellow]Time:[/bright_yellow] {ev.get('time', '?')}\n"
                f"[bright_yellow]ID:[/bright_yellow] {ev.get('id', '?')}\n"
                f"[dim]{ev.get('message', '?')[:200]}[/dim]",
                border_style="bright_blue",
            ))

    def _event_summary(self):
        c = self.console
        c.print("\n  [bold bright_cyan]Generating 24h security event summary...[/bold bright_cyan]")

        output = run_ps(
            "Get-WinEvent -FilterHashtable @{LogName='Security';StartTime=(Get-Date).AddDays(-1)} -ErrorAction SilentlyContinue | "
            "Group-Object Id | Select-Object Name, Count | Sort-Object Count -Descending | Format-Table -AutoSize"
        )

        if not output.strip():
            c.print("  [dim]No events in the last 24 hours or access denied.[/dim]")
            return

        table = Table(
            title="[bold bright_blue]24h Security Event Summary[/bold bright_blue]",
            box=box.DOUBLE_EDGE, border_style="bright_blue", header_style="bold bright_cyan",
        )
        table.add_column("EVENT ID", style="bright_yellow", width=12, justify="center")
        table.add_column("EVENT NAME", style="bold bright_white", width=35)
        table.add_column("COUNT", style="bright_cyan", width=10, justify="center")

        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("Name") or line.startswith("-"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                try:
                    eid = int(parts[0])
                    count = parts[1]
                    name, col = SECURITY_EVENT_IDS.get(eid, (f"Event {eid}", "dim"))
                    table.add_row(str(eid), f"[{col}]{name}[/{col}]", count)
                except ValueError:
                    continue

        c.print()
        c.print(Align.center(table))

    def _parse_events(self, output: str) -> list[dict]:
        events = []
        current: dict = {}
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("TimeCreated"):
                if current:
                    events.append(current)
                current = {"time": line.split(":", 1)[1].strip() if ":" in line else "?"}
            elif line.startswith("Id") and ":" in line:
                try:
                    current["id"] = int(line.split(":")[-1].strip())
                except ValueError:
                    pass
            elif line.startswith("Message") and ":" in line:
                current["message"] = line.split(":", 1)[1].strip()
            elif line.startswith("LevelDisplayName") and ":" in line:
                current["level"] = line.split(":")[-1].strip()
            elif current and "message" in current:
                current["message"] += " " + line
        if current:
            events.append(current)
        return events
