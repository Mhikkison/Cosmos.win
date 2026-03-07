"""
Traceroute Mapper — Visual traceroute with geolocation of each hop,
latency analysis, and anomaly detection for suspicious routing.
"""

import subprocess
import socket
import re
import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from utils.api_keys import get_api_key

HIGH_RISK_COUNTRIES = {"CN", "RU", "KP", "IR", "SY"}

GEO_CACHE: dict[str, dict] = {}


def geolocate_ip(ip: str) -> dict:
    if ip in GEO_CACHE:
        return GEO_CACHE[ip]
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.") or ip.startswith("127."):
        return {"country": "LOCAL", "countryCode": "LO", "city": "Private", "isp": "Local", "query": ip}
    if not HAS_REQUESTS:
        return {"country": "?", "countryCode": "?", "city": "?", "isp": "?", "query": ip}

    ipinfo_token = get_api_key("ipinfo")
    if ipinfo_token:
        try:
            resp = requests.get(f"https://ipinfo.io/{ip}/json",
                                params={"token": ipinfo_token}, timeout=4)
            if resp.status_code == 200:
                d = resp.json()
                result = {"country": d.get("country", "?"), "countryCode": d.get("country", "?"),
                          "city": d.get("city", "?"), "isp": d.get("org", "?"), "query": ip}
                GEO_CACHE[ip] = result
                return result
        except Exception:
            pass

    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=country,countryCode,city,isp,query",
                            timeout=4)
        if resp.status_code == 200:
            d = resp.json()
            GEO_CACHE[ip] = d
            return d
    except Exception:
        pass
    return {"country": "?", "countryCode": "?", "city": "?", "isp": "?", "query": ip}


def parse_tracert(output: str) -> list[dict]:
    """Parse Windows tracert output into structured hops."""
    hops = []
    for line in output.splitlines():
        line = line.strip()
        # Match lines like: "  1    <1 ms    <1 ms    <1 ms  192.168.1.1"
        match = re.match(
            r'^\s*(\d+)\s+'
            r'([<\d]+\s*ms|\*)\s+'
            r'([<\d]+\s*ms|\*)\s+'
            r'([<\d]+\s*ms|\*)\s+'
            r'(.+)$', line)
        if match:
            hop_num = int(match.group(1))
            times = []
            for g in [match.group(2), match.group(3), match.group(4)]:
                if g == "*":
                    times.append(None)
                else:
                    try:
                        times.append(float(g.replace("<", "").replace("ms", "").strip()))
                    except ValueError:
                        times.append(None)

            host_str = match.group(5).strip()
            # Extract IP from hostname string
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', host_str)
            ip = ip_match.group(1) if ip_match else host_str
            hostname = host_str.replace(f"[{ip}]", "").replace(ip, "").strip().strip("[] ")

            avg_time = sum(t for t in times if t is not None) / max(1, sum(1 for t in times if t is not None))
            hops.append({
                "hop": hop_num, "ip": ip, "hostname": hostname,
                "times": times, "avg_ms": avg_time,
            })
    return hops


class TracerouteMapper:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold bright_blue]TRACEROUTE MAPPER[/bold bright_blue]\n"
                         "[dim]Visual traceroute with geolocation, latency & routing anomaly detection[/dim]"),
            border_style="bright_blue", box=box.DOUBLE_EDGE,
        ))

        while True:
            c.print()
            table = Table(box=box.ROUNDED, border_style="bright_blue", header_style="bold bright_cyan")
            table.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            table.add_column("ACTION", style="bold bright_blue", width=55)
            table.add_row("1", "Traceroute with geolocation")
            table.add_row("2", "Compare traceroutes (detect routing changes)")
            table.add_row("3", "Quick latency test to common targets")
            table.add_row("4", "MTR-style continuous trace (5 rounds)")
            table.add_row("0", "Return to main menu")
            c.print(Align.center(table))

            choice = Prompt.ask("  [bold bright_blue]trace[/bold bright_blue][dim]>[/dim]", default="0")

            if choice == "1":
                self._trace_geo()
            elif choice == "2":
                self._compare_traces()
            elif choice == "3":
                self._quick_latency()
            elif choice == "4":
                self._mtr_style()
            elif choice == "0":
                break

    def _trace_geo(self):
        c = self.console
        target = Prompt.ask("  [bright_cyan]Target (IP or domain)[/bright_cyan]")
        max_hops = Prompt.ask("  Max hops", default="30")

        c.print(f"\n  [dim]Running traceroute to {target} (max {max_hops} hops)...[/dim]")
        output = ""
        try:
            result = subprocess.run(
                ["tracert", "-d", "-h", str(max_hops), "-w", "1000", target],
                capture_output=True, text=True, timeout=120
            )
            output = result.stdout
        except subprocess.TimeoutExpired:
            c.print("  [bright_yellow]Traceroute timed out.[/bright_yellow]")
            return
        except Exception as e:
            c.print(f"  [bright_red]Error: {e}[/bright_red]")
            return

        hops = parse_tracert(output)
        if not hops:
            c.print("  [dim]No hops could be parsed.[/dim]")
            return

        # Geolocate each hop
        table = Table(
            title=f"[bold bright_blue]Traceroute to {target} ({len(hops)} hops)[/bold bright_blue]",
            box=box.DOUBLE_EDGE, border_style="bright_blue", header_style="bold bright_cyan",
        )
        table.add_column("HOP", style="bright_yellow", width=5, justify="center")
        table.add_column("IP", style="bold bright_white", width=16)
        table.add_column("HOSTNAME", style="dim", width=25)
        table.add_column("AVG (ms)", style="bright_cyan", width=10, justify="right")
        table.add_column("COUNTRY", style="bright_green", width=14)
        table.add_column("CITY", style="dim", width=14)
        table.add_column("ISP", style="dim", width=22)
        table.add_column("RISK", style="bold", width=8)

        with Progress(
            SpinnerColumn(style="bright_blue"),
            TextColumn("[bold bright_blue]Geolocating hops...[/bold bright_blue]"),
            BarColumn(bar_width=25),
            console=c,
        ) as progress:
            t = progress.add_task("", total=len(hops))
            for hop in hops:
                geo = geolocate_ip(hop["ip"])
                cc = geo.get("countryCode", "?")
                risk = "[bright_red]HIGH[/bright_red]" if cc in HIGH_RISK_COUNTRIES else "[bright_green]OK[/bright_green]"

                avg_col = "bright_red" if hop["avg_ms"] > 200 else "bright_yellow" if hop["avg_ms"] > 100 else "bright_green"
                table.add_row(
                    str(hop["hop"]),
                    hop["ip"],
                    (hop["hostname"] or "-")[:25],
                    f"[{avg_col}]{hop['avg_ms']:.1f}[/{avg_col}]",
                    f"{geo.get('country', '?')} ({cc})",
                    geo.get("city", "?")[:14],
                    geo.get("isp", "?")[:22],
                    risk,
                )
                progress.advance(t)
                time.sleep(0.05)

        c.print()
        c.print(Align.center(table))

        # Summary
        high_risk = [h for h in hops if geolocate_ip(h["ip"]).get("countryCode", "") in HIGH_RISK_COUNTRIES]
        high_latency = [h for h in hops if h["avg_ms"] > 200]
        if high_risk:
            c.print(f"\n  [bold bright_red]Routing passes through {len(high_risk)} high-risk country hop(s)![/bold bright_red]")
        if high_latency:
            c.print(f"  [bright_yellow]{len(high_latency)} hop(s) with latency > 200ms[/bright_yellow]")

    def _compare_traces(self):
        c = self.console
        target = Prompt.ask("  [bright_cyan]Target[/bright_cyan]")
        c.print("  [dim]Running first traceroute...[/dim]")

        try:
            r1 = subprocess.run(["tracert", "-d", "-h", "20", "-w", "1000", target],
                                capture_output=True, text=True, timeout=90)
            hops1 = parse_tracert(r1.stdout)
        except Exception:
            hops1 = []

        c.print("  [dim]Waiting 5 seconds before second traceroute...[/dim]")
        time.sleep(5)

        try:
            r2 = subprocess.run(["tracert", "-d", "-h", "20", "-w", "1000", target],
                                capture_output=True, text=True, timeout=90)
            hops2 = parse_tracert(r2.stdout)
        except Exception:
            hops2 = []

        if not hops1 or not hops2:
            c.print("  [bright_red]Could not complete both traceroutes.[/bright_red]")
            return

        table = Table(
            title="[bold bright_blue]Traceroute Comparison[/bold bright_blue]",
            box=box.DOUBLE_EDGE, border_style="bright_blue", header_style="bold bright_cyan",
        )
        table.add_column("HOP", style="bright_yellow", width=5)
        table.add_column("TRACE 1 IP", style="bright_white", width=16)
        table.add_column("TRACE 2 IP", style="bright_white", width=16)
        table.add_column("MATCH", style="bold", width=10)

        max_hops = max(len(hops1), len(hops2))
        changes = 0
        for i in range(max_hops):
            ip1 = hops1[i]["ip"] if i < len(hops1) else "-"
            ip2 = hops2[i]["ip"] if i < len(hops2) else "-"
            match = ip1 == ip2
            if not match:
                changes += 1
            col = "bright_green" if match else "bright_red"
            table.add_row(str(i+1), ip1, ip2, f"[{col}]{'YES' if match else 'CHANGED'}[/{col}]")

        c.print()
        c.print(Align.center(table))
        if changes > 0:
            c.print(f"\n  [bright_yellow]{changes} routing change(s) detected between traces.[/bright_yellow]")
        else:
            c.print("\n  [bright_green]Routes are consistent.[/bright_green]")

    def _quick_latency(self):
        c = self.console
        targets = [
            ("8.8.8.8", "Google DNS"),
            ("1.1.1.1", "Cloudflare DNS"),
            ("9.9.9.9", "Quad9 DNS"),
            ("208.67.222.222", "OpenDNS"),
            ("google.com", "Google"),
            ("github.com", "GitHub"),
        ]

        table = Table(
            title="[bold bright_blue]Quick Latency Test[/bold bright_blue]",
            box=box.DOUBLE_EDGE, border_style="bright_blue", header_style="bold bright_cyan",
        )
        table.add_column("TARGET", style="bold bright_white", width=20)
        table.add_column("IP", style="dim", width=16)
        table.add_column("LATENCY (ms)", style="bold", width=14, justify="right")
        table.add_column("STATUS", style="bold", width=10)

        for ip, name in targets:
            try:
                result = subprocess.run(
                    ["ping", "-n", "3", "-w", "2000", ip],
                    capture_output=True, text=True, timeout=10)
                avg_match = re.search(r'Average\s*=\s*(\d+)ms', result.stdout)
                if avg_match:
                    avg = int(avg_match.group(1))
                    col = "bright_green" if avg < 50 else "bright_yellow" if avg < 150 else "bright_red"
                    table.add_row(name, ip, f"[{col}]{avg}[/{col}]", f"[{col}]OK[/{col}]")
                else:
                    table.add_row(name, ip, "-", "[bright_red]TIMEOUT[/bright_red]")
            except Exception:
                table.add_row(name, ip, "-", "[bright_red]ERROR[/bright_red]")

        c.print()
        c.print(Align.center(table))

    def _mtr_style(self):
        c = self.console
        target = Prompt.ask("  [bright_cyan]Target[/bright_cyan]")
        rounds = 5

        c.print(f"\n  [dim]Running {rounds}-round trace to {target}...[/dim]")

        all_hops: dict[int, list[float]] = {}
        all_ips: dict[int, str] = {}

        for r in range(rounds):
            c.print(f"  [dim]Round {r+1}/{rounds}...[/dim]")
            try:
                result = subprocess.run(
                    ["tracert", "-d", "-h", "20", "-w", "1000", target],
                    capture_output=True, text=True, timeout=90)
                hops = parse_tracert(result.stdout)
                for hop in hops:
                    n = hop["hop"]
                    if n not in all_hops:
                        all_hops[n] = []
                        all_ips[n] = hop["ip"]
                    all_hops[n].append(hop["avg_ms"])
            except Exception:
                pass

        if not all_hops:
            c.print("  [bright_red]No data collected.[/bright_red]")
            return

        table = Table(
            title=f"[bold bright_blue]MTR-style Report to {target} ({rounds} rounds)[/bold bright_blue]",
            box=box.DOUBLE_EDGE, border_style="bright_blue", header_style="bold bright_cyan",
        )
        table.add_column("HOP", style="bright_yellow", width=5)
        table.add_column("IP", style="bold bright_white", width=16)
        table.add_column("BEST", style="bright_green", width=10, justify="right")
        table.add_column("AVG", style="bright_cyan", width=10, justify="right")
        table.add_column("WORST", style="bright_red", width=10, justify="right")
        table.add_column("LOSS %", style="bold", width=10, justify="right")

        for n in sorted(all_hops.keys()):
            times = all_hops[n]
            best = min(times)
            avg = sum(times) / len(times)
            worst = max(times)
            loss = ((rounds - len(times)) / rounds) * 100

            loss_col = "bright_red" if loss > 30 else "bright_yellow" if loss > 0 else "bright_green"
            table.add_row(
                str(n), all_ips[n],
                f"{best:.1f}ms", f"{avg:.1f}ms", f"{worst:.1f}ms",
                f"[{loss_col}]{loss:.0f}%[/{loss_col}]",
            )

        c.print()
        c.print(Align.center(table))
