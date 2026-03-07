"""
Open Port Monitor — Continuous monitoring of open ports, detect new listeners,
alert on suspicious port activity, check external exposure via Shodan/Censys free APIs.
"""

import socket
import time
import psutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from utils.api_keys import get_api_key

WELL_KNOWN_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1434: "MSSQL-Mon",
    1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 5985: "WinRM", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}

DANGER_PORTS = {21, 23, 135, 139, 445, 1433, 3306, 3389, 5900, 5985, 6379, 27017}


def scan_port(ip: str, port: int, timeout: float = 0.4) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def get_public_ip() -> str:
    try:
        resp = requests.get("https://api.ipify.org", timeout=5)
        if resp.status_code == 200:
            return resp.text.strip()
    except Exception:
        pass
    return "?"


class OpenPortMonitor:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold #00e676]OPEN PORT MONITOR[/bold #00e676]\n"
                         "[dim]Monitor open ports, detect changes & check external exposure[/dim]"),
            border_style="#00e676", box=box.DOUBLE_EDGE,
        ))

        while True:
            c.print()
            table = Table(box=box.ROUNDED, border_style="#00e676", header_style="bold bright_cyan")
            table.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            table.add_column("ACTION", style="bold #00e676", width=55)
            table.add_row("1", "Current open ports (detailed)")
            table.add_row("2", "Port change detection (snapshot compare)")
            table.add_row("3", "Scan custom port range")
            table.add_row("4", "Check external exposure (Shodan)")
            table.add_row("5", "Alert on danger ports (live scan)")
            table.add_row("6", "Service banner grabbing")
            table.add_row("0", "Return to main menu")
            c.print(Align.center(table))

            choice = Prompt.ask("  [bold #00e676]port[/bold #00e676][dim]>[/dim]", default="0")

            if choice == "1":
                self._current_ports()
            elif choice == "2":
                self._change_detection()
            elif choice == "3":
                self._scan_range()
            elif choice == "4":
                self._external_exposure()
            elif choice == "5":
                self._danger_scan()
            elif choice == "6":
                self._banner_grab()
            elif choice == "0":
                break

    def _current_ports(self):
        c = self.console
        connections = psutil.net_connections(kind="inet")
        listening = sorted(
            [conn for conn in connections if conn.status == "LISTEN"],
            key=lambda x: x.laddr.port
        )

        table = Table(
            title=f"[bold #00e676]Open Listening Ports ({len(listening)})[/bold #00e676]",
            box=box.DOUBLE_EDGE, border_style="#00e676", header_style="bold bright_cyan",
        )
        table.add_column("PORT", style="bright_yellow", width=7, justify="center")
        table.add_column("SERVICE", style="bold bright_white", width=14)
        table.add_column("PROCESS", style="bright_cyan", width=22)
        table.add_column("PID", style="dim", width=8)
        table.add_column("ADDRESS", style="dim", width=22)
        table.add_column("RISK", style="bold", width=10)

        for conn in listening:
            port = conn.laddr.port
            try:
                proc = psutil.Process(conn.pid) if conn.pid else None
                proc_name = proc.name() if proc else "?"
            except Exception:
                proc_name = "?"

            svc = WELL_KNOWN_PORTS.get(port, "")
            is_danger = port in DANGER_PORTS
            risk = "[bright_red]HIGH[/bright_red]" if is_danger else "[bright_green]LOW[/bright_green]"
            addr = f"{conn.laddr.ip}:{port}"

            # Check if externally bound
            if conn.laddr.ip == "0.0.0.0" or conn.laddr.ip == "::":
                addr += " [bold bright_yellow]*[/bold bright_yellow]"

            table.add_row(str(port), svc, proc_name[:22], str(conn.pid or "?"), addr, risk)

        c.print()
        c.print(Align.center(table))
        c.print("  [dim]* = bound to all interfaces (externally accessible)[/dim]")

        danger_count = sum(1 for conn in listening if conn.laddr.port in DANGER_PORTS)
        if danger_count:
            c.print(f"\n  [bold bright_red]{danger_count} high-risk port(s) open![/bold bright_red]")

    def _change_detection(self):
        c = self.console
        c.print("\n  [dim]Taking first snapshot of open ports...[/dim]")

        def get_snapshot() -> set:
            conns = psutil.net_connections(kind="inet")
            return {conn.laddr.port for conn in conns if conn.status == "LISTEN"}

        snap1 = get_snapshot()
        c.print(f"  [bright_cyan]Snapshot 1: {len(snap1)} ports open[/bright_cyan]")
        c.print("  [dim]Waiting 10 seconds for second snapshot...[/dim]")

        for i in range(10, 0, -1):
            c.print(f"  [dim]{i}...[/dim]", end="")
            time.sleep(1)
        c.print()

        snap2 = get_snapshot()
        c.print(f"  [bright_cyan]Snapshot 2: {len(snap2)} ports open[/bright_cyan]")

        new_ports = snap2 - snap1
        closed_ports = snap1 - snap2

        if new_ports:
            c.print(f"\n  [bold bright_red]NEW ports opened: {sorted(new_ports)}[/bold bright_red]")
            for p in new_ports:
                svc = WELL_KNOWN_PORTS.get(p, "unknown")
                c.print(f"    [bright_red]{p}/{svc}[/bright_red]")
        if closed_ports:
            c.print(f"\n  [bold bright_green]Ports closed: {sorted(closed_ports)}[/bold bright_green]")
        if not new_ports and not closed_ports:
            c.print("\n  [bright_green]No changes detected between snapshots.[/bright_green]")

    def _scan_range(self):
        c = self.console
        target = Prompt.ask("  [bright_cyan]Target IP[/bright_cyan]", default="127.0.0.1")
        start = int(Prompt.ask("  Start port", default="1"))
        end = int(Prompt.ask("  End port", default="1024"))

        if end - start > 10000:
            c.print("  [bright_yellow]Range too large (max 10000 ports).[/bright_yellow]")
            return

        open_ports = []
        total = end - start + 1

        with Progress(
            SpinnerColumn(style="#00e676"),
            TextColumn("[bold #00e676]Scanning {task.description}[/bold #00e676]"),
            BarColumn(bar_width=40, complete_style="#00e676"),
            TimeElapsedColumn(),
            console=c,
        ) as progress:
            t = progress.add_task(f"{target}:{start}-{end}", total=total)
            with ThreadPoolExecutor(max_workers=100) as ex:
                futures = {
                    ex.submit(scan_port, target, p): p
                    for p in range(start, end + 1)
                }
                for fut in as_completed(futures):
                    p = futures[fut]
                    if fut.result():
                        open_ports.append(p)
                    progress.advance(t)

        open_ports.sort()

        table = Table(
            title=f"[bold #00e676]Scan Results: {target} ({len(open_ports)} open)[/bold #00e676]",
            box=box.DOUBLE_EDGE, border_style="#00e676", header_style="bold bright_cyan",
        )
        table.add_column("PORT", style="bright_yellow", width=8, justify="center")
        table.add_column("SERVICE", style="bold bright_white", width=18)
        table.add_column("RISK", style="bold", width=10)

        for p in open_ports:
            svc = WELL_KNOWN_PORTS.get(p, "unknown")
            risk = "[bright_red]HIGH[/bright_red]" if p in DANGER_PORTS else "[bright_green]LOW[/bright_green]"
            table.add_row(str(p), svc, risk)

        c.print()
        c.print(Align.center(table))

    def _external_exposure(self):
        c = self.console
        if not HAS_REQUESTS:
            c.print("  [bright_red]requests library required.[/bright_red]")
            return

        shodan_key = get_api_key("shodan")
        if not shodan_key:
            c.print("  [bright_yellow]Add your Shodan API key in the API Key Manager (K).[/bright_yellow]")
            c.print("  [dim]Free Shodan API: https://account.shodan.io/register[/dim]")

            # Still show public IP
            pub_ip = get_public_ip()
            c.print(f"\n  [bright_cyan]Your public IP:[/bright_cyan] [bold bright_white]{pub_ip}[/bold bright_white]")
            return

        pub_ip = get_public_ip()
        c.print(f"\n  [bright_cyan]Public IP:[/bright_cyan] {pub_ip}")
        c.print("  [dim]Querying Shodan...[/dim]")

        try:
            resp = requests.get(f"https://api.shodan.io/shodan/host/{pub_ip}?key={shodan_key}",
                                timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                ports = data.get("ports", [])
                vulns = data.get("vulns", [])
                org = data.get("org", "?")
                os_name = data.get("os", "?")

                table = Table(
                    title=f"[bold bright_red]External Exposure: {pub_ip}[/bold bright_red]",
                    box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
                )
                table.add_column("PORT", style="bright_yellow", width=8)
                table.add_column("SERVICE", style="bold bright_white", width=18)
                table.add_column("PRODUCT", style="dim", width=25)
                table.add_column("RISK", style="bold", width=10)

                for item in data.get("data", [])[:20]:
                    port = item.get("port", "?")
                    product = item.get("product", "?")
                    transport = item.get("transport", "?")
                    is_danger = port in DANGER_PORTS
                    risk = "[bright_red]HIGH[/bright_red]" if is_danger else "[bright_yellow]MED[/bright_yellow]"
                    table.add_row(str(port), transport, str(product)[:25], risk)

                c.print()
                c.print(Align.center(table))
                c.print(f"\n  [bright_cyan]Org:[/bright_cyan] {org}")
                c.print(f"  [bright_cyan]OS:[/bright_cyan] {os_name}")
                c.print(f"  [bright_cyan]Open ports:[/bright_cyan] {len(ports)}")

                if vulns:
                    c.print(f"\n  [bold bright_red]Known vulnerabilities: {len(vulns)}[/bold bright_red]")
                    for v in vulns[:10]:
                        c.print(f"    [bright_red]{v}[/bright_red]")
            elif resp.status_code == 404:
                c.print("  [bright_green]No Shodan data found for your IP (good - low exposure).[/bright_green]")
            else:
                c.print(f"  [dim]Shodan returned HTTP {resp.status_code}[/dim]")
        except Exception as e:
            c.print(f"  [bright_red]Error: {e}[/bright_red]")

    def _danger_scan(self):
        c = self.console
        c.print("\n  [bold bright_red]Scanning high-risk ports on localhost...[/bold bright_red]")

        open_danger = []
        with ThreadPoolExecutor(max_workers=30) as ex:
            futures = {ex.submit(scan_port, "127.0.0.1", p): p for p in DANGER_PORTS}
            for fut in as_completed(futures):
                p = futures[fut]
                if fut.result():
                    svc = WELL_KNOWN_PORTS.get(p, "?")
                    try:
                        conns = psutil.net_connections(kind="inet")
                        proc_name = "?"
                        for conn in conns:
                            if conn.laddr.port == p and conn.status == "LISTEN":
                                try:
                                    proc_name = psutil.Process(conn.pid).name()
                                except Exception:
                                    pass
                                break
                    except Exception:
                        proc_name = "?"
                    open_danger.append((p, svc, proc_name))

        if not open_danger:
            c.print("\n  [bold bright_green]No high-risk ports are open. System looks good.[/bold bright_green]")
            return

        table = Table(
            title=f"[bold bright_red]DANGER: {len(open_danger)} High-Risk Ports Open[/bold bright_red]",
            box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
        )
        table.add_column("PORT", style="bright_yellow", width=8)
        table.add_column("SERVICE", style="bold bright_red", width=16)
        table.add_column("PROCESS", style="bright_white", width=25)
        table.add_column("RECOMMENDATION", style="dim", width=40)

        recommendations = {
            21: "Disable FTP, use SFTP instead",
            23: "Disable Telnet immediately, use SSH",
            135: "Block with firewall if not needed",
            139: "Disable NetBIOS over TCP",
            445: "Block SMB from external access",
            1433: "Restrict MSSQL to localhost only",
            3306: "Restrict MySQL to localhost only",
            3389: "Use VPN for RDP, enable NLA",
            5900: "Disable VNC or restrict to localhost",
            5985: "Disable WinRM if not needed",
            6379: "Enable Redis authentication",
            27017: "Enable MongoDB authentication",
        }

        for p, svc, proc in open_danger:
            rec = recommendations.get(p, "Review and restrict if not needed")
            table.add_row(str(p), svc, proc[:25], rec)

        c.print()
        c.print(Align.center(table))

    def _banner_grab(self):
        c = self.console
        target = Prompt.ask("  [bright_cyan]Target IP[/bright_cyan]", default="127.0.0.1")
        port = int(Prompt.ask("  [bright_cyan]Port[/bright_cyan]", default="80"))

        c.print(f"\n  [dim]Grabbing banner from {target}:{port}...[/dim]")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))

            # Try sending HTTP request for web servers
            if port in (80, 443, 8080, 8443):
                sock.send(b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            else:
                sock.send(b"\r\n")

            banner = sock.recv(1024).decode("utf-8", errors="replace")
            sock.close()

            if banner.strip():
                c.print(Panel(
                    f"[dim]{banner[:500]}[/dim]",
                    title=f"[bold #00e676]Banner: {target}:{port}[/bold #00e676]",
                    border_style="#00e676", box=box.DOUBLE_EDGE,
                ))
            else:
                c.print("  [dim]No banner received (service may not send one).[/dim]")
        except socket.timeout:
            c.print("  [bright_yellow]Connection timed out.[/bright_yellow]")
        except ConnectionRefusedError:
            c.print("  [bright_red]Connection refused (port closed).[/bright_red]")
        except Exception as e:
            c.print(f"  [bright_red]Error: {e}[/bright_red]")
