"""
Honeypot Detector — Detect if connected services might be honeypots
by checking response timing, banner grabbing, and anomaly detection.
"""

import socket
import time
import re
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box


HONEYPOT_INDICATORS = {
    "too_many_open": "Unusually many ports open (>15 common ports)",
    "instant_response": "Response time < 5ms (suspicious for complex services)",
    "generic_banner": "Generic or known honeypot banner detected",
    "all_ports_open": "All tested ports are open (classic honeypot sign)",
    "fake_service": "Service response does not match expected protocol behavior",
}

KNOWN_HONEYPOT_BANNERS = [
    "cowrie", "kippo", "dionaea", "glastopf", "honeyd",
    "conpot", "elastichoney", "mailoney", "shockpot",
]

TEST_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 445, 993, 995,
              3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]


def grab_banner(ip: str, port: int, timeout: float = 3.0) -> tuple[str, float]:
    """Returns (banner, response_time_ms)."""
    try:
        start = time.time()
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(2)
        try:
            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
        except socket.timeout:
            banner = ""
        elapsed = (time.time() - start) * 1000
        s.close()
        return banner, elapsed
    except Exception:
        return "", -1


class HoneypotDetector:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold bright_yellow]HONEYPOT DETECTOR[/bold bright_yellow]\n"
                         "[dim]Detect fake services, honeypots & deception systems[/dim]"),
            border_style="bright_yellow", box=box.DOUBLE_EDGE,
        ))

        while True:
            c.print()
            table = Table(box=box.ROUNDED, border_style="bright_yellow", header_style="bold bright_cyan")
            table.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            table.add_column("ACTION", style="bold bright_yellow", width=50)
            table.add_row("1", "Full honeypot analysis on a target")
            table.add_row("2", "Banner grab analysis")
            table.add_row("3", "Response time anomaly check")
            table.add_row("4", "Open port ratio analysis")
            table.add_row("0", "Return to main menu")
            c.print(Align.center(table))

            choice = Prompt.ask("  [bold bright_yellow]honey[/bold bright_yellow][dim]>[/dim]", default="0")

            if choice == "1":
                self._full_analysis()
            elif choice == "2":
                self._banner_analysis()
            elif choice == "3":
                self._timing_analysis()
            elif choice == "4":
                self._port_ratio()
            elif choice == "0":
                break

    def _full_analysis(self):
        c = self.console
        target = Prompt.ask("  [bright_cyan]Target IP[/bright_cyan]")
        indicators = []
        open_ports = []
        banners = {}
        timings = {}

        with Progress(
            SpinnerColumn(style="bright_yellow"),
            TextColumn("[bold bright_yellow]Analyzing target...[/bold bright_yellow]"),
            BarColumn(bar_width=30),
            TextColumn("{task.completed}/{task.total}"),
            console=c,
        ) as progress:
            t = progress.add_task("Scanning...", total=len(TEST_PORTS))
            for port in TEST_PORTS:
                banner, timing = grab_banner(target, port)
                if timing >= 0:
                    open_ports.append(port)
                    banners[port] = banner
                    timings[port] = timing
                progress.advance(t)

        # Analysis
        open_ratio = len(open_ports) / len(TEST_PORTS)
        if open_ratio > 0.8:
            indicators.append("all_ports_open")
        elif len(open_ports) > 15:
            indicators.append("too_many_open")

        instant = [p for p, t in timings.items() if t < 5]
        if len(instant) > 3:
            indicators.append("instant_response")

        for port, banner in banners.items():
            banner_lower = banner.lower()
            if any(hp in banner_lower for hp in KNOWN_HONEYPOT_BANNERS):
                indicators.append("generic_banner")
                break

        # Display
        table = Table(
            title=f"[bold bright_yellow]Honeypot Analysis: {target}[/bold bright_yellow]",
            box=box.DOUBLE_EDGE, border_style="bright_yellow", header_style="bold bright_cyan",
        )
        table.add_column("PORT", style="bright_yellow", width=8, justify="center")
        table.add_column("BANNER", style="bright_white", width=40)
        table.add_column("RESPONSE (ms)", style="bright_cyan", width=15, justify="right")
        table.add_column("SUSPICIOUS", style="bold", width=12)

        for port in sorted(open_ports):
            banner = banners.get(port, "")[:40]
            timing = timings.get(port, 0)
            suspicious = timing < 5 or any(hp in banner.lower() for hp in KNOWN_HONEYPOT_BANNERS)
            sus_str = "[bright_red]YES[/bright_red]" if suspicious else "[bright_green]NO[/bright_green]"
            table.add_row(str(port), banner if banner else "[dim]no banner[/dim]", f"{timing:.1f}", sus_str)

        c.print()
        c.print(Align.center(table))

        # Verdict
        c.print()
        score = len(indicators)
        if score >= 3:
            c.print(Panel("[bold bright_red]HIGH probability of honeypot[/bold bright_red]",
                          border_style="bright_red"))
        elif score >= 1:
            c.print(Panel("[bold bright_yellow]POSSIBLE honeypot indicators found[/bold bright_yellow]",
                          border_style="bright_yellow"))
        else:
            c.print(Panel("[bold bright_green]No honeypot indicators detected[/bold bright_green]",
                          border_style="bright_green"))

        if indicators:
            for ind in indicators:
                c.print(f"  [bright_yellow]- {HONEYPOT_INDICATORS.get(ind, ind)}[/bright_yellow]")

    def _banner_analysis(self):
        c = self.console
        target = Prompt.ask("  [bright_cyan]Target IP[/bright_cyan]")
        port = int(Prompt.ask("  [bright_cyan]Port[/bright_cyan]", default="22"))

        banner, timing = grab_banner(target, port)
        if timing < 0:
            c.print(f"  [bright_red]Could not connect to {target}:{port}[/bright_red]")
            return

        is_honeypot = any(hp in banner.lower() for hp in KNOWN_HONEYPOT_BANNERS)
        col = "bright_red" if is_honeypot else "bright_green"

        c.print(Panel(
            f"[bright_cyan]Banner:[/bright_cyan] {banner if banner else '[dim]empty[/dim]'}\n"
            f"[bright_cyan]Response:[/bright_cyan] {timing:.1f}ms\n"
            f"[bright_cyan]Honeypot Banner:[/bright_cyan] [{col}]{'YES' if is_honeypot else 'NO'}[/{col}]",
            title=f"[bold bright_yellow]{target}:{port}[/bold bright_yellow]",
            border_style="bright_yellow",
        ))

    def _timing_analysis(self):
        c = self.console
        target = Prompt.ask("  [bright_cyan]Target IP[/bright_cyan]")

        results = []
        with Progress(
            SpinnerColumn(style="bright_yellow"),
            TextColumn("[bold bright_yellow]Testing response times...[/bold bright_yellow]"),
            BarColumn(bar_width=30),
            console=c,
        ) as progress:
            t = progress.add_task("", total=len(TEST_PORTS))
            for port in TEST_PORTS:
                _, timing = grab_banner(target, port)
                if timing >= 0:
                    results.append((port, timing))
                progress.advance(t)

        if not results:
            c.print("  [dim]No open ports found.[/dim]")
            return

        avg_time = sum(t for _, t in results) / len(results)
        instant = sum(1 for _, t in results if t < 5)

        c.print(f"\n  [bright_cyan]Open ports:[/bright_cyan] {len(results)}")
        c.print(f"  [bright_cyan]Average response:[/bright_cyan] {avg_time:.1f}ms")
        c.print(f"  [bright_cyan]Instant responses (<5ms):[/bright_cyan] {instant}")

        if instant > len(results) * 0.5:
            c.print("  [bold bright_red]Suspicious: Too many instant responses[/bold bright_red]")

    def _port_ratio(self):
        c = self.console
        target = Prompt.ask("  [bright_cyan]Target IP[/bright_cyan]")

        open_count = 0
        with Progress(
            SpinnerColumn(style="bright_yellow"),
            TextColumn("[bold bright_yellow]Checking ports...[/bold bright_yellow]"),
            BarColumn(bar_width=30),
            console=c,
        ) as progress:
            t = progress.add_task("", total=len(TEST_PORTS))
            for port in TEST_PORTS:
                _, timing = grab_banner(target, port, timeout=2)
                if timing >= 0:
                    open_count += 1
                progress.advance(t)

        ratio = open_count / len(TEST_PORTS) * 100
        col = "bright_red" if ratio > 80 else "bright_yellow" if ratio > 50 else "bright_green"

        c.print(f"\n  [bright_cyan]Open ports:[/bright_cyan] {open_count}/{len(TEST_PORTS)}")
        c.print(f"  [bright_cyan]Open ratio:[/bright_cyan] [{col}]{ratio:.1f}%[/{col}]")

        if ratio > 80:
            c.print("  [bold bright_red]Very high open ratio - likely a honeypot![/bold bright_red]")
        elif ratio > 50:
            c.print("  [bright_yellow]Elevated open ratio - investigate further[/bright_yellow]")
