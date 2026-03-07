"""
AdGuard DNS Blocker — Block ads, trackers, and malicious domains system-wide
by switching the system DNS to AdGuard DNS or custom DNS servers.
Includes DNS leak testing and domain blacklist management.
"""

import os
import subprocess
import socket
import time
import re
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich import box

DNS_PROVIDERS = {
    "AdGuard Default": ("94.140.14.14", "94.140.15.15"),
    "AdGuard Family":  ("94.140.14.15", "94.140.15.16"),
    "Cloudflare Malware": ("1.1.1.2", "1.0.0.2"),
    "Cloudflare Family": ("1.1.1.3", "1.0.0.3"),
    "Quad9 Secure":    ("9.9.9.9", "149.112.112.112"),
    "OpenDNS Home":    ("208.67.222.222", "208.67.220.220"),
    "Google DNS":      ("8.8.8.8", "8.8.4.4"),
    "Restore Default (DHCP)": (None, None),
}

MALICIOUS_TEST_DOMAINS = [
    "malware.testcategory.com",
    "phishing.testcategory.com",
    "adserver.example.org",
    "tracking.example.net",
]

HOSTS_FILE = r"C:\Windows\System32\drivers\etc\hosts"

KNOWN_AD_DOMAINS = [
    "0.0.0.0 doubleclick.net",
    "0.0.0.0 ad.doubleclick.net",
    "0.0.0.0 googleadservices.com",
    "0.0.0.0 pagead2.googlesyndication.com",
    "0.0.0.0 adservice.google.com",
    "0.0.0.0 ads.facebook.com",
    "0.0.0.0 pixel.facebook.com",
    "0.0.0.0 analytics.tiktok.com",
    "0.0.0.0 ads.yahoo.com",
    "0.0.0.0 advertising.microsoft.com",
    "0.0.0.0 telemetry.microsoft.com",
    "0.0.0.0 vortex.data.microsoft.com",
    "0.0.0.0 settings-win.data.microsoft.com",
    "0.0.0.0 static.ads-twitter.com",
    "0.0.0.0 ads-api.twitter.com",
]


def get_active_interfaces() -> list[str]:
    """Return list of active network interface names."""
    interfaces = []
    try:
        result = subprocess.run(
            ["netsh", "interface", "show", "interface"],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines():
            if "Connected" in line:
                parts = line.split()
                if len(parts) >= 4:
                    name = " ".join(parts[3:])
                    interfaces.append(name)
    except Exception:
        interfaces = ["Wi-Fi", "Ethernet"]
    return interfaces


def get_current_dns(interface: str) -> list[str]:
    """Get current DNS servers for an interface."""
    servers = []
    try:
        result = subprocess.run(
            ["netsh", "interface", "ipv4", "show", "dnsservers", interface],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines():
            match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            if match:
                servers.append(match.group(1))
    except Exception:
        pass
    return servers


class DNSBlocker:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold bright_green]DNS BLOCKER[/bold bright_green]\n"
                         "[dim]System-wide ad/tracker/malware blocking via DNS & hosts file[/dim]"),
            border_style="bright_green", box=box.DOUBLE_EDGE,
        ))
        c.print()

        while True:
            c.print()
            table = Table(box=box.ROUNDED, border_style="bright_green", header_style="bold bright_cyan")
            table.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            table.add_column("ACTION", style="bold bright_green", width=40)
            table.add_row("1", "View current DNS configuration")
            table.add_row("2", "Switch DNS provider (system-wide)")
            table.add_row("3", "DNS leak test")
            table.add_row("4", "Block domains via hosts file")
            table.add_row("5", "View / edit hosts file entries")
            table.add_row("6", "Flush DNS cache")
            table.add_row("0", "Return to main menu")
            c.print(Align.center(table))
            c.print()

            choice = Prompt.ask("  [bold bright_green]dns[/bold bright_green][dim]>[/dim]", default="0")

            if choice == "1":
                self._view_dns()
            elif choice == "2":
                self._switch_dns()
            elif choice == "3":
                self._leak_test()
            elif choice == "4":
                self._block_domains()
            elif choice == "5":
                self._view_hosts()
            elif choice == "6":
                self._flush_dns()
            elif choice == "0":
                break

    def _view_dns(self):
        c = self.console
        interfaces = get_active_interfaces()
        table = Table(title="[bold bright_green]Current DNS Configuration[/bold bright_green]",
                      box=box.DOUBLE_EDGE, border_style="bright_green", header_style="bold bright_cyan")
        table.add_column("INTERFACE", style="bold bright_white", width=25)
        table.add_column("DNS SERVERS", style="bright_cyan", width=40)
        table.add_column("STATUS", style="bold", width=15)

        for iface in interfaces:
            servers = get_current_dns(iface)
            server_str = ", ".join(servers) if servers else "DHCP (Auto)"
            # Check if using a known secure DNS
            is_secure = any(
                s in server_str for provider in DNS_PROVIDERS.values()
                if provider[0] for s in [provider[0], provider[1]] if s
            )
            status = "[bright_green]PROTECTED[/bright_green]" if is_secure else "[bright_yellow]DEFAULT[/bright_yellow]"
            table.add_row(iface, server_str, status)

        c.print()
        c.print(Align.center(table))

    def _switch_dns(self):
        c = self.console
        interfaces = get_active_interfaces()

        if not interfaces:
            c.print("[bright_red]No active network interfaces found.[/bright_red]")
            return

        c.print()
        c.print("[bold bright_cyan]Available DNS Providers:[/bold bright_cyan]")
        providers = list(DNS_PROVIDERS.keys())
        for i, name in enumerate(providers, 1):
            ips = DNS_PROVIDERS[name]
            ip_str = f"{ips[0]}, {ips[1]}" if ips[0] else "DHCP"
            c.print(f"  [bright_yellow]{i}[/bright_yellow]) {name} [dim]({ip_str})[/dim]")

        choice_idx = Prompt.ask("\n  Select provider", default="1")
        try:
            provider = providers[int(choice_idx) - 1]
        except (ValueError, IndexError):
            c.print("[bright_red]Invalid selection.[/bright_red]")
            return

        primary, secondary = DNS_PROVIDERS[provider]

        with Progress(
            SpinnerColumn(style="bright_green"),
            TextColumn("[bold bright_green]{task.description}[/bold bright_green]"),
            BarColumn(bar_width=40, style="bright_green", complete_style="bright_cyan"),
            TimeElapsedColumn(),
            console=c,
        ) as progress:
            t = progress.add_task("Applying DNS...", total=len(interfaces))

            for iface in interfaces:
                try:
                    if primary is None:
                        # Restore DHCP
                        subprocess.run(
                            ["netsh", "interface", "ipv4", "set", "dnsservers",
                             iface, "source=dhcp"],
                            capture_output=True, timeout=15
                        )
                    else:
                        subprocess.run(
                            ["netsh", "interface", "ipv4", "set", "dnsservers",
                             iface, "static", primary, "primary"],
                            capture_output=True, timeout=15
                        )
                        if secondary:
                            subprocess.run(
                                ["netsh", "interface", "ipv4", "add", "dnsservers",
                                 iface, secondary, "index=2"],
                                capture_output=True, timeout=15
                            )
                except Exception as e:
                    c.print(f"  [dim]Error on {iface}: {e}[/dim]")
                progress.advance(t)

        self._flush_dns_silent()
        c.print(f"\n  [bold bright_green]DNS switched to {provider} on all interfaces.[/bold bright_green]")

    def _leak_test(self):
        c = self.console
        c.print()
        c.print("[bold bright_cyan]Running DNS leak test...[/bold bright_cyan]")
        c.print()

        test_domains = [
            ("whoami.akamai.net", "Akamai resolver check"),
            ("myip.opendns.com", "OpenDNS resolver check"),
            ("o-o.myaddr.l.google.com", "Google resolver check"),
        ]

        table = Table(box=box.ROUNDED, border_style="bright_cyan", header_style="bold bright_cyan")
        table.add_column("TEST", style="bright_white", width=30)
        table.add_column("RESOLVED IP", style="bright_cyan", width=20)
        table.add_column("STATUS", style="bold", width=15)

        for domain, desc in test_domains:
            try:
                ip = socket.gethostbyname(domain)
                table.add_row(desc, ip, "[bright_green]OK[/bright_green]")
            except Exception:
                table.add_row(desc, "FAILED", "[bright_red]ERROR[/bright_red]")

        c.print(Align.center(table))
        c.print()
        c.print("[dim]If resolved IPs match your DNS provider, no leak detected.[/dim]")

    def _block_domains(self):
        c = self.console
        c.print()
        c.print(f"[bold bright_cyan]This will add {len(KNOWN_AD_DOMAINS)} known ad/tracker domains to your hosts file.[/bold bright_cyan]")
        ans = Confirm.ask("  Proceed?", default=False)
        if not ans:
            return

        try:
            with open(HOSTS_FILE, "r") as f:
                existing = f.read()

            added = 0
            with open(HOSTS_FILE, "a") as f:
                f.write("\n# === COSMOS.WIN DNS BLOCKER ===\n")
                for entry in KNOWN_AD_DOMAINS:
                    domain = entry.split()[-1]
                    if domain not in existing:
                        f.write(entry + "\n")
                        added += 1

            self._flush_dns_silent()
            c.print(f"\n  [bold bright_green]Added {added} domain blocks to hosts file.[/bold bright_green]")
        except PermissionError:
            c.print("[bright_red]  Permission denied. Run as Administrator.[/bright_red]")
        except Exception as e:
            c.print(f"[bright_red]  Error: {e}[/bright_red]")

    def _view_hosts(self):
        c = self.console
        try:
            with open(HOSTS_FILE, "r") as f:
                lines = f.readlines()

            cosmos_entries = [l.strip() for l in lines if l.strip() and not l.startswith("#")]
            if not cosmos_entries:
                c.print("[dim]  Hosts file has no custom entries.[/dim]")
                return

            table = Table(title="[bold bright_green]Hosts File Entries[/bold bright_green]",
                          box=box.ROUNDED, border_style="bright_green", header_style="bold bright_cyan")
            table.add_column("#", style="dim", width=5)
            table.add_column("IP", style="bright_cyan", width=16)
            table.add_column("DOMAIN", style="bright_white", width=50)

            for i, line in enumerate(cosmos_entries[:50], 1):
                parts = line.split()
                if len(parts) >= 2:
                    table.add_row(str(i), parts[0], parts[1])

            c.print()
            c.print(Align.center(table))
            if len(cosmos_entries) > 50:
                c.print(f"[dim]  ... and {len(cosmos_entries) - 50} more entries[/dim]")
        except Exception as e:
            c.print(f"[bright_red]  Error reading hosts file: {e}[/bright_red]")

    def _flush_dns(self):
        c = self.console
        try:
            subprocess.run(["ipconfig", "/flushdns"], capture_output=True, timeout=10)
            c.print("\n  [bold bright_green]DNS cache flushed successfully.[/bold bright_green]")
        except Exception as e:
            c.print(f"[bright_red]  Error: {e}[/bright_red]")

    def _flush_dns_silent(self):
        try:
            subprocess.run(["ipconfig", "/flushdns"], capture_output=True, timeout=10)
        except Exception:
            pass
