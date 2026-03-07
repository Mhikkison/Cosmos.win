"""
WiFi Analyzer — Scan nearby wireless networks, analyze signal strength,
detect encryption types, identify rogue APs, and show saved profiles.
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


def run_cmd(args, timeout=20):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception as e:
        return str(e)


def signal_bar(quality: int) -> str:
    filled = quality // 10
    empty = 10 - filled
    if quality >= 70:
        col = "bright_green"
    elif quality >= 40:
        col = "bright_yellow"
    else:
        col = "bright_red"
    return f"[{col}]{'█' * filled}{'░' * empty}[/{col}] {quality}%"


class WiFiAnalyzer:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold bright_blue]WIFI ANALYZER[/bold bright_blue]\n"
                         "[dim]Wireless network scanner, signal analysis & profile manager[/dim]"),
            border_style="bright_blue", box=box.DOUBLE_EDGE,
        ))

        while True:
            c.print()
            table = Table(box=box.ROUNDED, border_style="bright_blue", header_style="bold bright_cyan")
            table.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            table.add_column("ACTION", style="bold bright_blue", width=45)
            table.add_row("1", "Scan nearby Wi-Fi networks")
            table.add_row("2", "Show current connection details")
            table.add_row("3", "List saved Wi-Fi profiles")
            table.add_row("4", "Show saved Wi-Fi passwords")
            table.add_row("5", "Detect rogue / evil twin APs")
            table.add_row("6", "Delete a saved Wi-Fi profile")
            table.add_row("7", "Export all profiles to text")
            table.add_row("0", "Return to main menu")
            c.print(Align.center(table))

            choice = Prompt.ask("  [bold bright_blue]wifi[/bold bright_blue][dim]>[/dim]", default="0")

            if choice == "1":
                self._scan_networks()
            elif choice == "2":
                self._current_connection()
            elif choice == "3":
                self._list_profiles()
            elif choice == "4":
                self._show_passwords()
            elif choice == "5":
                self._detect_rogue()
            elif choice == "6":
                self._delete_profile()
            elif choice == "7":
                self._export_profiles()
            elif choice == "0":
                break

    def _scan_networks(self):
        c = self.console
        with Progress(
            SpinnerColumn(style="bright_blue"),
            TextColumn("[bold bright_blue]Scanning wireless networks...[/bold bright_blue]"),
            console=c,
        ) as progress:
            t = progress.add_task("Scanning...", total=None)
            output = run_cmd(["netsh", "wlan", "show", "networks", "mode=bssid"])

        networks = self._parse_networks(output)
        if not networks:
            c.print("  [bright_yellow]No networks found. Is Wi-Fi enabled?[/bright_yellow]")
            return

        table = Table(
            title=f"[bold bright_blue]Nearby Wi-Fi Networks ({len(networks)})[/bold bright_blue]",
            box=box.DOUBLE_EDGE, border_style="bright_blue", header_style="bold bright_cyan",
        )
        table.add_column("SSID", style="bold bright_white", width=28)
        table.add_column("BSSID", style="dim", width=20)
        table.add_column("SIGNAL", width=22)
        table.add_column("CHANNEL", style="bright_cyan", width=9, justify="center")
        table.add_column("AUTH", style="bright_yellow", width=18)
        table.add_column("CIPHER", style="dim", width=12)

        networks.sort(key=lambda x: x.get("signal", 0), reverse=True)
        for net in networks:
            auth = net.get("auth", "Open")
            auth_col = "bright_green" if "WPA3" in auth else "bright_yellow" if "WPA2" in auth else "bright_red"
            table.add_row(
                net.get("ssid", "Hidden"),
                net.get("bssid", "?"),
                signal_bar(net.get("signal", 0)),
                str(net.get("channel", "?")),
                f"[{auth_col}]{auth}[/{auth_col}]",
                net.get("cipher", "?"),
            )

        c.print()
        c.print(Align.center(table))

    def _parse_networks(self, output: str) -> list[dict]:
        networks = []
        current = {}
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("SSID") and "BSSID" not in line:
                if ":" in line:
                    ssid = line.split(":", 1)[1].strip()
                    if current and current.get("bssid"):
                        networks.append(current)
                    current = {"ssid": ssid if ssid else "Hidden"}
            elif "BSSID" in line and ":" in line:
                parts = line.split(":", 1)
                if len(parts) > 1:
                    bssid_val = parts[1].strip()
                    # Reconstruct BSSID (netsh splits on :)
                    bssid_match = re.search(r'([0-9a-fA-F:]{17})', line)
                    if bssid_match:
                        current["bssid"] = bssid_match.group(1)
                    else:
                        current["bssid"] = bssid_val[:17]
            elif "Signal" in line:
                match = re.search(r'(\d+)%', line)
                if match:
                    current["signal"] = int(match.group(1))
            elif "Channel" in line and ":" in line:
                match = re.search(r'(\d+)', line.split(":")[-1])
                if match:
                    current["channel"] = int(match.group(1))
            elif "Authentication" in line and ":" in line:
                current["auth"] = line.split(":")[-1].strip()
            elif "Cipher" in line and ":" in line:
                current["cipher"] = line.split(":")[-1].strip()

        if current and current.get("ssid"):
            networks.append(current)
        return networks

    def _current_connection(self):
        c = self.console
        output = run_cmd(["netsh", "wlan", "show", "interfaces"])

        table = Table(
            title="[bold bright_blue]Current Wi-Fi Connection[/bold bright_blue]",
            box=box.DOUBLE_EDGE, border_style="bright_blue", header_style="bold bright_cyan",
        )
        table.add_column("PROPERTY", style="bold bright_white", width=25)
        table.add_column("VALUE", style="bright_cyan", width=50)

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

    def _list_profiles(self):
        c = self.console
        output = run_cmd(["netsh", "wlan", "show", "profiles"])
        profiles = re.findall(r"All User Profile\s*:\s*(.+)", output)

        if not profiles:
            c.print("  [dim]No saved Wi-Fi profiles found.[/dim]")
            return

        table = Table(
            title=f"[bold bright_blue]Saved Wi-Fi Profiles ({len(profiles)})[/bold bright_blue]",
            box=box.ROUNDED, border_style="bright_blue", header_style="bold bright_cyan",
        )
        table.add_column("#", style="dim", width=5)
        table.add_column("PROFILE NAME", style="bold bright_white", width=40)

        for i, p in enumerate(profiles, 1):
            table.add_row(str(i), p.strip())

        c.print()
        c.print(Align.center(table))

    def _show_passwords(self):
        c = self.console
        output = run_cmd(["netsh", "wlan", "show", "profiles"])
        profiles = re.findall(r"All User Profile\s*:\s*(.+)", output)

        if not profiles:
            c.print("  [dim]No profiles found.[/dim]")
            return

        table = Table(
            title="[bold bright_blue]Saved Wi-Fi Passwords[/bold bright_blue]",
            box=box.DOUBLE_EDGE, border_style="bright_blue", header_style="bold bright_cyan",
        )
        table.add_column("PROFILE", style="bold bright_white", width=30)
        table.add_column("PASSWORD", style="bright_yellow", width=30)
        table.add_column("AUTH", style="dim", width=20)

        for profile in profiles:
            profile = profile.strip()
            detail = run_cmd(["netsh", "wlan", "show", "profile", profile, "key=clear"])
            pw = "N/A"
            auth = "?"
            for line in detail.splitlines():
                if "Key Content" in line and ":" in line:
                    pw = line.split(":")[-1].strip()
                if "Authentication" in line and ":" in line:
                    auth = line.split(":")[-1].strip()
            table.add_row(profile, pw, auth)

        c.print()
        c.print(Align.center(table))

    def _detect_rogue(self):
        c = self.console
        c.print("\n  [bold bright_cyan]Scanning for rogue / evil twin APs...[/bold bright_cyan]")
        output = run_cmd(["netsh", "wlan", "show", "networks", "mode=bssid"])
        networks = self._parse_networks(output)

        # Group by SSID
        ssid_groups: dict[str, list] = {}
        for net in networks:
            ssid = net.get("ssid", "Hidden")
            if ssid not in ssid_groups:
                ssid_groups[ssid] = []
            ssid_groups[ssid].append(net)

        rogue_found = False
        for ssid, nets in ssid_groups.items():
            if len(nets) > 1:
                auths = set(n.get("auth", "?") for n in nets)
                if len(auths) > 1:
                    rogue_found = True
                    c.print(f"\n  [bold bright_red]Potential rogue AP detected for SSID: {ssid}[/bold bright_red]")
                    c.print(f"  [dim]Multiple APs with different auth types: {auths}[/dim]")
                    for n in nets:
                        c.print(f"    BSSID: {n.get('bssid', '?')} | Auth: {n.get('auth', '?')} | Signal: {n.get('signal', '?')}%")

        if not rogue_found:
            c.print("  [bold bright_green]No rogue APs detected.[/bold bright_green]")

    def _delete_profile(self):
        c = self.console
        name = Prompt.ask("  [bright_red]Profile name to delete[/bright_red]")
        if name.strip():
            if Confirm.ask(f"  Delete profile '{name}'?", default=False):
                run_cmd(["netsh", "wlan", "delete", "profile", f"name={name}"])
                c.print(f"  [bright_green]Profile '{name}' deleted.[/bright_green]")

    def _export_profiles(self):
        c = self.console
        output = run_cmd(["netsh", "wlan", "show", "profiles"])
        profiles = re.findall(r"All User Profile\s*:\s*(.+)", output)

        export_path = os.path.join(os.path.expanduser("~"), "Desktop", "cosmos_wifi_export.txt")
        try:
            with open(export_path, "w") as f:
                f.write("=== COSMOS.WIN WiFi Profile Export ===\n\n")
                for profile in profiles:
                    profile = profile.strip()
                    detail = run_cmd(["netsh", "wlan", "show", "profile", profile, "key=clear"])
                    f.write(f"--- {profile} ---\n")
                    f.write(detail + "\n\n")
            c.print(f"  [bright_green]Exported to {export_path}[/bright_green]")
        except Exception as e:
            c.print(f"  [bright_red]Error: {e}[/bright_red]")


import os
