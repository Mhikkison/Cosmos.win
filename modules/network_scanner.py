"""
Network Scanner — ARP discovery, port scanner, OS fingerprinting.
Real-time output with live table updates.
"""

import os
import socket
import subprocess
import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.live import Live
from rich.text import Text
from rich import box

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-alt", 8443: "HTTPS-alt", 27017: "MongoDB",
    1433: "MSSQL", 5432: "PostgreSQL", 1521: "Oracle",
}

# Risk colours for services
HIGH_RISK_PORTS = {23, 21, 445, 3389, 5900, 27017, 6379, 1433, 1521}
MED_RISK_PORTS  = {25, 110, 143, 8080}


def get_local_ip() -> str:
    """Return the local IP."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "192.168.1.1"


def get_local_network() -> str:
    """Return the local /24 subnet, e.g. 192.168.1.0/24"""
    ip = get_local_ip()
    parts = ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


def ping_host(ip: str) -> bool:
    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", "150", str(ip)],
            capture_output=True, timeout=2
        )
        return result.returncode == 0
    except Exception:
        return False


def scan_port(ip: str, port: int, timeout: float = 0.3) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def get_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def get_mac_from_arp(ip: str) -> str:
    """Try to get MAC from ARP table."""
    try:
        result = subprocess.run(
            ["arp", "-a", ip], capture_output=True, text=True, timeout=3
        )
        for line in result.stdout.splitlines():
            if ip in line:
                parts = line.split()
                for p in parts:
                    if "-" in p and len(p) == 17:
                        return p.upper()
                    if ":" in p and len(p) == 17:
                        return p.upper()
    except Exception:
        pass
    return ""


def guess_os(open_ports: list[int]) -> str:
    """Rough OS fingerprint based on open ports."""
    port_set = set(open_ports)
    if 3389 in port_set or 445 in port_set:
        return "🪟 Windows"
    if 22 in port_set and 80 in port_set:
        return "🐧 Linux"
    if 22 in port_set:
        return "🐧 Linux/Mac"
    if 80 in port_set or 443 in port_set:
        return "🌐 Web device"
    if 53 in port_set:
        return "📡 Router/DNS"
    return "❓ Unknown"


class NetworkScanner:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        c = self.console

        while True:
            os.system("cls")
            c.print()
            c.print(Panel(
                Align.center(Text.from_markup(
                    "[bold bright_blue]📡  NETWORK SCANNER[/bold bright_blue]\n\n"
                    "[bright_cyan]ARP Discovery[/bright_cyan] [dim]·[/dim] "
                    "[bright_cyan]Port Scanner[/bright_cyan] [dim]·[/dim] "
                    "[bright_cyan]OS Fingerprinting[/bright_cyan] [dim]·[/dim] "
                    "[bright_cyan]MAC Lookup[/bright_cyan]"
                )),
                border_style="bright_blue",
                box=box.DOUBLE,
                padding=(1, 3),
            ))
            c.print()

            # ── Network info ──
            local_ip = get_local_ip()
            subnet = get_local_network()

            info_table = Table(show_header=False, box=box.SIMPLE, border_style="dim",
                               pad_edge=True, expand=False)
            info_table.add_column("KEY", style="bright_cyan", width=18)
            info_table.add_column("VALUE", style="bold bright_white", width=30)
            info_table.add_row("  🖥️  Local IP", local_ip)
            info_table.add_row("  🌐  Subnet", subnet)
            info_table.add_row("  📡  Gateway", subnet.replace(".0/24", ".1"))
            c.print(Align.center(info_table))
            c.print()

            # ── Sub-menu ──
            menu = Table(box=box.ROUNDED, border_style="bright_blue", header_style="bold bright_cyan",
                         expand=False, show_header=False)
            menu.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            menu.add_column("ACTION", style="bold bright_blue", width=45)
            menu.add_row("1", "⚡  Quick scan (top 20 ports)")
            menu.add_row("2", "🔍  Full scan (ports 1-1024)")
            menu.add_row("3", "🎯  Scan a single host")
            menu.add_row("4", "🌐  Scan custom subnet")
            menu.add_row("0", "🔙  Return to main menu")
            c.print(Align.center(menu))
            c.print()

            choice = Prompt.ask("  [bold bright_blue]net[/bold bright_blue][dim]>[/dim]", default="0")

            if choice == "0":
                break
            elif choice == "1":
                self._run_scan(subnet, "quick")
            elif choice == "2":
                self._run_scan(subnet, "full")
            elif choice == "3":
                target = Prompt.ask("  [bright_cyan]Target IP[/bright_cyan]")
                if target.strip():
                    self._scan_single_host(target.strip())
            elif choice == "4":
                custom = Prompt.ask(f"  [bright_cyan]Subnet[/bright_cyan]", default=subnet)
                mode = Prompt.ask("  Mode", choices=["quick", "full"], default="quick")
                self._run_scan(custom.strip(), mode)

    def _run_scan(self, subnet: str, mode: str):
        c = self.console
        c.print()

        # ── Phase 1: Host Discovery ──
        live_hosts = self._discover_hosts(subnet)

        if not live_hosts:
            c.print(Panel(
                Align.center("[bold bright_yellow]⚠️  No live hosts found on this subnet.[/bold bright_yellow]"),
                border_style="bright_yellow", box=box.ROUNDED,
            ))
            c.input("\n[dim]Press Enter to continue...[/dim]")
            return

        # ── Phase 2: Port Scan with live results ──
        self._scan_hosts_live(live_hosts, mode)

    def _scan_single_host(self, ip: str):
        """Quick scan of a single IP with all common ports."""
        c = self.console
        c.print(f"\n  [bold bright_blue]🎯  Scanning {ip}...[/bold bright_blue]\n")

        hostname = get_hostname(ip)
        mac = get_mac_from_arp(ip)
        ports = list(COMMON_PORTS.keys())
        open_ports = []

        with Progress(
            SpinnerColumn("dots", style="bright_cyan"),
            TextColumn("[bold bright_blue]Scanning ports...[/bold bright_blue]"),
            BarColumn(bar_width=30, style="bright_blue", complete_style="bright_green"),
            TextColumn("[bright_white]{task.completed}[/bright_white][dim]/{task.total}[/dim]"),
            TimeElapsedColumn(),
            console=c,
        ) as progress:
            t = progress.add_task("Ports", total=len(ports))
            with ThreadPoolExecutor(max_workers=100) as ex:
                futures = {ex.submit(scan_port, ip, p): p for p in ports}
                for fut in as_completed(futures):
                    p = futures[fut]
                    try:
                        if fut.result():
                            open_ports.append(p)
                    except Exception:
                        pass
                    progress.advance(t)

        open_ports.sort()
        os_guess = guess_os(open_ports)
        c.print()
        self._print_host_result(ip, hostname, mac, open_ports, os_guess)
        c.input(f"\n[dim]Press Enter to continue...[/dim]")

    def _discover_hosts(self, subnet: str) -> list[str]:
        c = self.console
        live = []
        try:
            network = ipaddress.IPv4Network(subnet, strict=False)
            hosts = list(network.hosts())
        except ValueError as e:
            c.print(f"[bright_red]❌  Invalid subnet: {e}[/bright_red]")
            return []

        c.print(Panel(
            f"[bold bright_blue]🔎  HOST DISCOVERY[/bold bright_blue]  [dim]— Scanning {len(hosts)} addresses on {subnet}[/dim]",
            border_style="bright_blue",
            box=box.ROUNDED,
            expand=False,
        ))
        c.print()

        found_display = []

        with Progress(
            SpinnerColumn("dots", style="bright_cyan"),
            TextColumn("[bold bright_blue]{task.description}[/bold bright_blue]"),
            BarColumn(bar_width=40, style="bright_blue", complete_style="bright_green"),
            TextColumn("[bright_white]{task.completed}[/bright_white][dim]/{task.total}[/dim]"),
            TextColumn("[bright_green]{task.fields[found]} found[/bright_green]"),
            TimeElapsedColumn(),
            console=c,
        ) as progress:
            t = progress.add_task("Pinging hosts", total=len(hosts), found=0)

            with ThreadPoolExecutor(max_workers=80) as ex:
                future_map = {ex.submit(ping_host, str(h)): str(h) for h in hosts}
                for future in as_completed(future_map):
                    ip = future_map[future]
                    try:
                        if future.result():
                            live.append(ip)
                            progress.update(t, found=len(live))
                    except Exception:
                        pass
                    progress.advance(t)

        c.print()
        if live:
            # Show discovered hosts immediately
            sorted_hosts = sorted(live, key=lambda ip: [int(x) for x in ip.split(".")])
            host_chips = "  ".join(
                f"[bold bright_green]●[/bold bright_green] [bright_white]{ip}[/bright_white]"
                for ip in sorted_hosts
            )
            c.print(Panel(
                f"[bold bright_green]✅  {len(live)} live host(s) discovered:[/bold bright_green]\n\n{host_chips}",
                border_style="bright_green",
                box=box.ROUNDED,
                expand=False,
                padding=(1, 2),
            ))
            c.print()
            return sorted_hosts
        return []

    def _scan_hosts_live(self, hosts: list[str], mode: str):
        """Scan ports on each host and print results as each host completes."""
        c = self.console
        ports = list(COMMON_PORTS.keys()) if mode == "quick" else list(range(1, 1025))
        port_count = len(ports)
        total_work = len(hosts)

        c.print(Panel(
            f"[bold bright_blue]🔬  PORT SCAN[/bold bright_blue]  "
            f"[dim]— {port_count} ports × {len(hosts)} hosts  "
            f"({'Quick' if mode == 'quick' else 'Full'} mode)[/dim]",
            border_style="bright_blue",
            box=box.ROUNDED,
            expand=False,
        ))
        c.print()

        # Overall progress for hosts
        with Progress(
            SpinnerColumn("dots", style="bright_cyan"),
            TextColumn("[bold bright_blue]{task.description}[/bold bright_blue]"),
            BarColumn(bar_width=30, style="bright_blue", complete_style="bright_green"),
            TextColumn("[bright_white]{task.completed}[/bright_white][dim]/{task.total}[/dim] hosts"),
            TimeElapsedColumn(),
            console=c,
        ) as progress:
            main_task = progress.add_task("Scanning ports", total=total_work)

            all_results = []

            for ip in hosts:
                # Scan this host
                hostname = get_hostname(ip)
                mac = get_mac_from_arp(ip)
                open_ports = []

                with ThreadPoolExecutor(max_workers=120) as ex:
                    futures = {ex.submit(scan_port, ip, p): p for p in ports}
                    for fut in as_completed(futures):
                        p = futures[fut]
                        try:
                            if fut.result():
                                open_ports.append(p)
                        except Exception:
                            pass

                open_ports.sort()
                os_guess = guess_os(open_ports)
                all_results.append((ip, hostname, mac, open_ports, os_guess))

                progress.update(main_task,
                                description=f"Scanned {ip} → {len(open_ports)} open ports")
                progress.advance(main_task)

                # Print result for this host immediately
                self._print_host_result(ip, hostname, mac, open_ports, os_guess)

        # ── Summary table ──
        c.print()
        self._print_summary_table(all_results)
        c.input(f"\n[dim]Press Enter to return to menu...[/dim]")

    def _print_host_result(self, ip: str, hostname: str, mac: str, open_ports: list[int], os_guess: str):
        """Print a single host result card immediately after scanning."""
        c = self.console

        # Build port display with risk colours
        port_strs = []
        for p in open_ports:
            svc = COMMON_PORTS.get(p, "???")
            if p in HIGH_RISK_PORTS:
                port_strs.append(f"[bold bright_red]⚠ {p}/{svc}[/bold bright_red]")
            elif p in MED_RISK_PORTS:
                port_strs.append(f"[bright_yellow]{p}/{svc}[/bright_yellow]")
            else:
                port_strs.append(f"[bright_green]{p}/{svc}[/bright_green]")

        ports_display = "  ".join(port_strs) if port_strs else "[dim]No open ports[/dim]"

        # Host info line
        host_label = f"[bold bright_white]{ip}[/bold bright_white]"
        if hostname:
            host_label += f"  [dim]({hostname})[/dim]"
        if mac:
            host_label += f"  [dim bright_cyan]MAC: {mac}[/dim bright_cyan]"

        # Status indicator
        if not open_ports:
            status = "[bright_green]✅ Clean[/bright_green]"
        elif any(p in HIGH_RISK_PORTS for p in open_ports):
            status = f"[bold bright_red]⚠️  {len(open_ports)} open ({sum(1 for p in open_ports if p in HIGH_RISK_PORTS)} high-risk)[/bold bright_red]"
        else:
            status = f"[bright_yellow]📋  {len(open_ports)} open[/bright_yellow]"

        card_content = (
            f"{host_label}\n"
            f"  {os_guess}  │  {status}\n"
            f"  {ports_display}"
        )

        border = "bright_red" if any(p in HIGH_RISK_PORTS for p in open_ports) else "bright_blue"

        c.print(Panel(
            card_content,
            border_style=border,
            box=box.ROUNDED,
            expand=False,
            padding=(0, 2),
        ))

    def _print_summary_table(self, results: list):
        """Print final summary table."""
        c = self.console

        c.print(Panel(
            Align.center("[bold bright_blue]📊  SCAN SUMMARY[/bold bright_blue]"),
            border_style="bright_blue", box=box.DOUBLE, expand=False,
        ))
        c.print()

        table = Table(
            box=box.ROUNDED,
            border_style="bright_blue",
            header_style="bold bright_cyan",
            expand=False,
            min_width=80,
        )
        table.add_column("IP ADDRESS", style="bold bright_white", width=16)
        table.add_column("HOSTNAME", style="bright_cyan", width=22)
        table.add_column("MAC", style="dim", width=18)
        table.add_column("OS", style="bright_yellow", width=14)
        table.add_column("PORTS", style="bright_green", justify="center", width=8)
        table.add_column("RISK", justify="center", width=10)

        total_high = 0
        total_open = 0

        for ip, hostname, mac, open_ports, os_guess in results:
            high = sum(1 for p in open_ports if p in HIGH_RISK_PORTS)
            total_high += high
            total_open += len(open_ports)

            if high > 0:
                risk = f"[bold bright_red]🔴 HIGH[/bold bright_red]"
            elif open_ports:
                risk = f"[bright_yellow]🟡 MED[/bright_yellow]"
            else:
                risk = f"[bright_green]🟢 LOW[/bright_green]"

            table.add_row(
                ip,
                hostname or "[dim]—[/dim]",
                mac or "[dim]—[/dim]",
                os_guess,
                str(len(open_ports)),
                risk,
            )

        c.print(Align.center(table))
        c.print()

        # Stats footer
        c.print(Align.center(
            f"[bold bright_white]🖥️  {len(results)} hosts[/bold bright_white]  │  "
            f"[bold bright_green]🔓 {total_open} open ports[/bold bright_green]  │  "
            f"[bold bright_red]⚠️  {total_high} high-risk services[/bold bright_red]"
        ))
        c.print()
