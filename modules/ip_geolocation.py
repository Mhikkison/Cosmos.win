"""
IP Geolocation — Geolocate IP addresses, map active connections,
identify foreign connections, and detect suspicious geographic patterns.
"""

import socket
import psutil
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

GEO_CACHE: dict[str, dict] = {}
HIGH_RISK_COUNTRIES = {"CN", "RU", "KP", "IR", "SY", "CU", "VE"}


def geolocate_ip(ip: str) -> dict:
    if ip in GEO_CACHE:
        return GEO_CACHE[ip]

    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.") or ip.startswith("127."):
        result = {"country": "LOCAL", "countryCode": "LO", "city": "Private Network",
                  "isp": "Local", "org": "Local", "lat": 0, "lon": 0, "query": ip}
        GEO_CACHE[ip] = result
        return result

    if not HAS_REQUESTS:
        return {"country": "UNKNOWN", "countryCode": "??", "city": "N/A",
                "isp": "N/A", "query": ip}

    # Try IPinfo first (free tier 50k/month, more reliable)
    ipinfo_token = get_api_key("ipinfo")
    if ipinfo_token:
        try:
            resp = requests.get(f"https://ipinfo.io/{ip}/json",
                                params={"token": ipinfo_token}, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                loc = data.get("loc", "0,0").split(",")
                result = {
                    "country": data.get("country", "?"),
                    "countryCode": data.get("country", "?"),
                    "city": data.get("city", "?"),
                    "region": data.get("region", "?"),
                    "isp": data.get("org", "?"),
                    "org": data.get("org", "?"),
                    "lat": float(loc[0]) if len(loc) > 0 else 0,
                    "lon": float(loc[1]) if len(loc) > 1 else 0,
                    "query": ip,
                    "hostname": data.get("hostname", ""),
                    "timezone": data.get("timezone", ""),
                }
                GEO_CACHE[ip] = result
                return result
        except Exception:
            pass

    # Fallback to ip-api.com (free, 45 req/min, no key needed)
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,isp,org,lat,lon,query",
                            timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                GEO_CACHE[ip] = data
                return data
    except Exception:
        pass

    return {"country": "UNKNOWN", "countryCode": "??", "city": "N/A",
            "isp": "N/A", "query": ip}


class IPGeolocation:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold bright_blue]IP GEOLOCATION[/bold bright_blue]\n"
                         "[dim]Geolocate IPs, map connections & detect foreign access[/dim]"),
            border_style="bright_blue", box=box.DOUBLE_EDGE,
        ))

        while True:
            c.print()
            table = Table(box=box.ROUNDED, border_style="bright_blue", header_style="bold bright_cyan")
            table.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            table.add_column("ACTION", style="bold bright_blue", width=50)
            table.add_row("1", "Lookup single IP geolocation")
            table.add_row("2", "Map all active connections")
            table.add_row("3", "Detect high-risk country connections")
            table.add_row("4", "Get your public IP & location")
            table.add_row("5", "Bulk IP geolocation")
            table.add_row("0", "Return to main menu")
            c.print(Align.center(table))

            choice = Prompt.ask("  [bold bright_blue]geo[/bold bright_blue][dim]>[/dim]", default="0")

            if choice == "1":
                self._lookup_single()
            elif choice == "2":
                self._map_connections()
            elif choice == "3":
                self._detect_high_risk()
            elif choice == "4":
                self._my_ip()
            elif choice == "5":
                self._bulk_lookup()
            elif choice == "0":
                break

    def _lookup_single(self):
        c = self.console
        ip = Prompt.ask("  [bright_cyan]IP address[/bright_cyan]")
        geo = geolocate_ip(ip)

        c.print(Panel(
            f"[bright_cyan]IP:[/bright_cyan] {geo.get('query', ip)}\n"
            f"[bright_cyan]Country:[/bright_cyan] {geo.get('country', '?')} ({geo.get('countryCode', '?')})\n"
            f"[bright_cyan]City:[/bright_cyan] {geo.get('city', '?')}\n"
            f"[bright_cyan]ISP:[/bright_cyan] {geo.get('isp', '?')}\n"
            f"[bright_cyan]Org:[/bright_cyan] {geo.get('org', '?')}\n"
            f"[bright_cyan]Lat/Lon:[/bright_cyan] {geo.get('lat', '?')}, {geo.get('lon', '?')}",
            title="[bold bright_blue]Geolocation[/bold bright_blue]",
            border_style="bright_blue",
        ))

    def _map_connections(self):
        c = self.console
        connections = psutil.net_connections(kind="inet")
        remote_ips = set()
        conn_map: dict[str, list] = {}

        for conn in connections:
            if conn.raddr and conn.status == "ESTABLISHED":
                ip = conn.raddr.ip
                remote_ips.add(ip)
                try:
                    proc = psutil.Process(conn.pid).name() if conn.pid else "?"
                except Exception:
                    proc = "?"
                if ip not in conn_map:
                    conn_map[ip] = []
                conn_map[ip].append({"port": conn.raddr.port, "proc": proc, "pid": conn.pid})

        if not remote_ips:
            c.print("  [dim]No active outbound connections.[/dim]")
            return

        table = Table(
            title=f"[bold bright_blue]Connection Geolocation Map ({len(remote_ips)} IPs)[/bold bright_blue]",
            box=box.DOUBLE_EDGE, border_style="bright_blue", header_style="bold bright_cyan",
        )
        table.add_column("IP", style="bold bright_white", width=16)
        table.add_column("COUNTRY", style="bright_cyan", width=18)
        table.add_column("CITY", style="dim", width=15)
        table.add_column("ISP", style="dim", width=20)
        table.add_column("PROCESS", style="bright_yellow", width=15)
        table.add_column("RISK", style="bold", width=8)

        with Progress(
            SpinnerColumn(style="bright_blue"),
            TextColumn("[bold bright_blue]Geolocating...[/bold bright_blue]"),
            BarColumn(bar_width=30),
            console=c,
        ) as progress:
            t = progress.add_task("", total=len(remote_ips))
            for ip in sorted(remote_ips):
                geo = geolocate_ip(ip)
                cc = geo.get("countryCode", "?")
                risk = "[bright_red]HIGH[/bright_red]" if cc in HIGH_RISK_COUNTRIES else "[bright_green]OK[/bright_green]"
                procs = ", ".join(set(c_["proc"] for c_ in conn_map.get(ip, [])))

                table.add_row(
                    ip, f"{geo.get('country', '?')} ({cc})",
                    geo.get("city", "?")[:15],
                    geo.get("isp", "?")[:20],
                    procs[:15],
                    risk,
                )
                progress.advance(t)
                time.sleep(0.1)  # Rate limit

        c.print()
        c.print(Align.center(table))

    def _detect_high_risk(self):
        c = self.console
        connections = psutil.net_connections(kind="inet")
        alerts = []

        for conn in connections:
            if conn.raddr and conn.status == "ESTABLISHED":
                ip = conn.raddr.ip
                geo = geolocate_ip(ip)
                cc = geo.get("countryCode", "?")
                if cc in HIGH_RISK_COUNTRIES:
                    try:
                        proc = psutil.Process(conn.pid).name() if conn.pid else "?"
                    except Exception:
                        proc = "?"
                    alerts.append({
                        "ip": ip, "country": geo.get("country", "?"),
                        "city": geo.get("city", "?"), "proc": proc,
                        "pid": conn.pid, "port": conn.raddr.port,
                    })
                time.sleep(0.1)

        if not alerts:
            c.print("  [bold bright_green]No connections to high-risk countries detected.[/bold bright_green]")
            return

        table = Table(
            title=f"[bold bright_red]High-Risk Country Connections ({len(alerts)})[/bold bright_red]",
            box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
        )
        table.add_column("IP", style="bold bright_red", width=16)
        table.add_column("COUNTRY", style="bright_red", width=18)
        table.add_column("PROCESS", style="bright_yellow", width=15)
        table.add_column("PID", style="dim", width=8)
        table.add_column("PORT", style="dim", width=8)

        for a in alerts:
            table.add_row(a["ip"], a["country"], a["proc"], str(a["pid"] or "?"), str(a["port"]))

        c.print()
        c.print(Align.center(table))

    def _my_ip(self):
        c = self.console
        if not HAS_REQUESTS:
            c.print("  [bright_red]'requests' library required.[/bright_red]")
            return

        try:
            resp = requests.get("http://ip-api.com/json/?fields=status,country,countryCode,city,isp,org,lat,lon,query",
                                timeout=5)
            data = resp.json()
            c.print(Panel(
                f"[bright_cyan]Public IP:[/bright_cyan] [bold]{data.get('query', '?')}[/bold]\n"
                f"[bright_cyan]Country:[/bright_cyan] {data.get('country', '?')} ({data.get('countryCode', '?')})\n"
                f"[bright_cyan]City:[/bright_cyan] {data.get('city', '?')}\n"
                f"[bright_cyan]ISP:[/bright_cyan] {data.get('isp', '?')}\n"
                f"[bright_cyan]Org:[/bright_cyan] {data.get('org', '?')}",
                title="[bold bright_blue]Your Public IP[/bold bright_blue]",
                border_style="bright_blue",
            ))
        except Exception as e:
            c.print(f"  [bright_red]Error: {e}[/bright_red]")

    def _bulk_lookup(self):
        c = self.console
        ips_input = Prompt.ask("  [bright_cyan]IPs (comma-separated)[/bright_cyan]")
        ips = [ip.strip() for ip in ips_input.split(",") if ip.strip()]

        table = Table(
            title="[bold bright_blue]Bulk Geolocation[/bold bright_blue]",
            box=box.DOUBLE_EDGE, border_style="bright_blue", header_style="bold bright_cyan",
        )
        table.add_column("IP", style="bold bright_white", width=16)
        table.add_column("COUNTRY", style="bright_cyan", width=20)
        table.add_column("CITY", style="dim", width=15)
        table.add_column("ISP", style="dim", width=25)

        for ip in ips[:20]:
            geo = geolocate_ip(ip)
            table.add_row(ip, geo.get("country", "?"), geo.get("city", "?"), geo.get("isp", "?")[:25])
            time.sleep(0.15)

        c.print()
        c.print(Align.center(table))
