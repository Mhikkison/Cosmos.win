"""
Firewall Manager — View, create, delete, toggle Windows Firewall rules.
Includes profile status, quick-block IPs, and port management.
"""

import subprocess
import re
import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box


def run_netsh(args: list[str], timeout: int = 15) -> str:
    try:
        result = subprocess.run(
            ["netsh"] + args, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout
    except Exception as e:
        return f"Error: {e}"


class FirewallManager:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold bright_red]FIREWALL MANAGER[/bold bright_red]\n"
                         "[dim]Windows Firewall rule viewer, editor & IP blocker[/dim]"),
            border_style="bright_red", box=box.DOUBLE_EDGE,
        ))

        while True:
            c.print()
            table = Table(box=box.ROUNDED, border_style="bright_red", header_style="bold bright_cyan")
            table.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            table.add_column("ACTION", style="bold bright_red", width=45)
            table.add_row("1", "View firewall profile status")
            table.add_row("2", "List all inbound rules")
            table.add_row("3", "List all outbound rules")
            table.add_row("4", "Search rules by name")
            table.add_row("5", "Block an IP address")
            table.add_row("6", "Block a port (inbound)")
            table.add_row("7", "Allow a port (inbound)")
            table.add_row("8", "Delete a rule by name")
            table.add_row("9", "Enable / Disable firewall profile")
            table.add_row("0", "Return to main menu")
            c.print(Align.center(table))

            choice = Prompt.ask("  [bold bright_red]fw[/bold bright_red][dim]>[/dim]", default="0")

            if choice == "1":
                self._profile_status()
            elif choice == "2":
                self._list_rules("in")
            elif choice == "3":
                self._list_rules("out")
            elif choice == "4":
                self._search_rules()
            elif choice == "5":
                self._block_ip()
            elif choice == "6":
                self._block_port()
            elif choice == "7":
                self._allow_port()
            elif choice == "8":
                self._delete_rule()
            elif choice == "9":
                self._toggle_profile()
            elif choice == "0":
                break

    def _profile_status(self):
        c = self.console
        output = run_netsh(["advfirewall", "show", "allprofiles"])

        table = Table(
            title="[bold bright_red]Firewall Profile Status[/bold bright_red]",
            box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
        )
        table.add_column("PROFILE", style="bold bright_white", width=20)
        table.add_column("STATE", style="bold", width=12)
        table.add_column("INBOUND", style="dim", width=18)
        table.add_column("OUTBOUND", style="dim", width=18)

        profiles = ["Domain", "Private", "Public"]
        sections = output.split("\n\n")

        for profile in profiles:
            state = "Unknown"
            inbound = "Unknown"
            outbound = "Unknown"
            for section in sections:
                if profile in section:
                    for line in section.split("\n"):
                        if "State" in line and "ON" in line.upper():
                            state = "ON"
                        elif "State" in line and "OFF" in line.upper():
                            state = "OFF"
                        if "Inbound" in line:
                            inbound = line.split(":")[-1].strip() if ":" in line else "?"
                        if "Outbound" in line:
                            outbound = line.split(":")[-1].strip() if ":" in line else "?"

            state_col = "bright_green" if state == "ON" else "bright_red"
            table.add_row(profile, f"[{state_col}]{state}[/{state_col}]", inbound, outbound)

        c.print()
        c.print(Align.center(table))

    def _list_rules(self, direction: str):
        c = self.console
        dir_str = "in" if direction == "in" else "out"
        dir_label = "Inbound" if direction == "in" else "Outbound"

        with Progress(
            SpinnerColumn(style="bright_red"),
            TextColumn(f"[bold bright_red]Loading {dir_label} rules...[/bold bright_red]"),
            console=c,
        ) as progress:
            t = progress.add_task("Loading...", total=None)
            output = run_netsh(["advfirewall", "firewall", "show", "rule",
                                f"name=all", f"dir={dir_str}"])

        rules = self._parse_rules(output)
        if not rules:
            c.print(f"  [dim]No {dir_label} rules found or access denied.[/dim]")
            return

        table = Table(
            title=f"[bold bright_red]{dir_label} Rules ({len(rules)} total)[/bold bright_red]",
            box=box.ROUNDED, border_style="bright_red", header_style="bold bright_cyan",
        )
        table.add_column("#", style="dim", width=5)
        table.add_column("NAME", style="bold bright_white", width=35)
        table.add_column("ENABLED", style="bold", width=9)
        table.add_column("ACTION", style="bold", width=10)
        table.add_column("PROTOCOL", style="dim", width=10)
        table.add_column("LOCAL PORT", style="bright_cyan", width=14)
        table.add_column("REMOTE IP", style="dim", width=20)

        for i, rule in enumerate(rules[:80], 1):
            enabled_col = "bright_green" if rule.get("enabled") == "Yes" else "bright_red"
            action_col = "bright_green" if rule.get("action") == "Allow" else "bright_red"
            table.add_row(
                str(i),
                (rule.get("name", "?"))[:35],
                f"[{enabled_col}]{rule.get('enabled', '?')}[/{enabled_col}]",
                f"[{action_col}]{rule.get('action', '?')}[/{action_col}]",
                rule.get("protocol", "?"),
                rule.get("localport", "Any"),
                (rule.get("remoteip", "Any"))[:20],
            )

        c.print()
        c.print(table)
        if len(rules) > 80:
            c.print(f"  [dim]... showing 80 of {len(rules)} rules[/dim]")

    def _parse_rules(self, output: str) -> list[dict]:
        rules = []
        current = {}
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Rule Name:"):
                if current:
                    rules.append(current)
                current = {"name": line.split(":", 1)[1].strip()}
            elif ":" in line and current:
                key, val = line.split(":", 1)
                key = key.strip().lower().replace(" ", "")
                current[key] = val.strip()
        if current:
            rules.append(current)
        return rules

    def _search_rules(self):
        c = self.console
        term = Prompt.ask("  [bright_cyan]Search term[/bright_cyan]")
        if not term.strip():
            return

        output = run_netsh(["advfirewall", "firewall", "show", "rule", "name=all"])
        rules = self._parse_rules(output)
        matches = [r for r in rules if term.lower() in r.get("name", "").lower()]

        if not matches:
            c.print(f"  [bright_yellow]No rules matching '{term}'[/bright_yellow]")
            return

        table = Table(box=box.ROUNDED, border_style="bright_cyan", header_style="bold bright_cyan")
        table.add_column("NAME", style="bold bright_white", width=40)
        table.add_column("ENABLED", style="bold", width=9)
        table.add_column("ACTION", style="bold", width=10)
        table.add_column("DIR", style="dim", width=8)

        for r in matches[:30]:
            table.add_row(r.get("name", "?")[:40], r.get("enabled", "?"),
                          r.get("action", "?"), r.get("direction", "?"))

        c.print()
        c.print(Align.center(table))

    def _block_ip(self):
        c = self.console
        ip = Prompt.ask("  [bright_red]IP address to block[/bright_red]")
        if not ip.strip():
            return
        rule_name = f"COSMOS_BLOCK_{ip.replace('.', '_')}"
        try:
            # Block inbound
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}_IN", "dir=in", "action=block",
                f"remoteip={ip}", "protocol=any",
            ], capture_output=True, timeout=15)
            # Block outbound
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}_OUT", "dir=out", "action=block",
                f"remoteip={ip}", "protocol=any",
            ], capture_output=True, timeout=15)
            c.print(f"\n  [bold bright_green]Blocked {ip} (inbound + outbound)[/bold bright_green]")
        except Exception as e:
            c.print(f"  [bright_red]Error: {e}[/bright_red]")

    def _block_port(self):
        c = self.console
        port = Prompt.ask("  [bright_red]Port to block (inbound)[/bright_red]")
        proto = Prompt.ask("  Protocol", choices=["tcp", "udp", "any"], default="tcp")
        rule_name = f"COSMOS_BLOCK_PORT_{port}_{proto}"
        try:
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}", "dir=in", "action=block",
                f"protocol={proto}", f"localport={port}",
            ], capture_output=True, timeout=15)
            c.print(f"\n  [bold bright_green]Blocked port {port}/{proto} inbound[/bold bright_green]")
        except Exception as e:
            c.print(f"  [bright_red]Error: {e}[/bright_red]")

    def _allow_port(self):
        c = self.console
        port = Prompt.ask("  [bright_green]Port to allow (inbound)[/bright_green]")
        proto = Prompt.ask("  Protocol", choices=["tcp", "udp", "any"], default="tcp")
        rule_name = f"COSMOS_ALLOW_PORT_{port}_{proto}"
        try:
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}", "dir=in", "action=allow",
                f"protocol={proto}", f"localport={port}",
            ], capture_output=True, timeout=15)
            c.print(f"\n  [bold bright_green]Allowed port {port}/{proto} inbound[/bold bright_green]")
        except Exception as e:
            c.print(f"  [bright_red]Error: {e}[/bright_red]")

    def _delete_rule(self):
        c = self.console
        name = Prompt.ask("  [bright_yellow]Rule name to delete[/bright_yellow]")
        if not name.strip():
            return
        if Confirm.ask(f"  Delete rule '{name}'?", default=False):
            try:
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={name}",
                ], capture_output=True, timeout=15)
                c.print(f"\n  [bright_green]Rule '{name}' deleted.[/bright_green]")
            except Exception as e:
                c.print(f"  [bright_red]Error: {e}[/bright_red]")

    def _toggle_profile(self):
        c = self.console
        profile = Prompt.ask("  Profile", choices=["domain", "private", "public", "all"], default="all")
        state = Prompt.ask("  State", choices=["on", "off"], default="on")
        try:
            if profile == "all":
                for p in ["domain", "private", "public"]:
                    subprocess.run(
                        ["netsh", "advfirewall", "set", f"{p}profile", "state", state],
                        capture_output=True, timeout=15
                    )
            else:
                subprocess.run(
                    ["netsh", "advfirewall", "set", f"{profile}profile", "state", state],
                    capture_output=True, timeout=15
                )
            c.print(f"\n  [bold bright_green]Firewall {profile} set to {state.upper()}[/bold bright_green]")
        except Exception as e:
            c.print(f"  [bright_red]Error: {e}[/bright_red]")
