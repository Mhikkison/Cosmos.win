"""
Packet Sniffer — Capture and analyze network traffic using raw sockets,
display live connections, protocol distribution, and detect anomalies.
"""

import socket
import struct
import psutil
import time
import os
from collections import Counter
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

PROTOCOL_MAP = {1: "ICMP", 6: "TCP", 17: "UDP", 2: "IGMP", 47: "GRE", 50: "ESP"}
WELL_KNOWN_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}


class PacketSniffer:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold bright_green]PACKET SNIFFER[/bold bright_green]\n"
                         "[dim]Network traffic capture, protocol analysis & anomaly detection[/dim]"),
            border_style="bright_green", box=box.DOUBLE_EDGE,
        ))

        while True:
            c.print()
            table = Table(box=box.ROUNDED, border_style="bright_green", header_style="bold bright_cyan")
            table.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            table.add_column("ACTION", style="bold bright_green", width=50)
            table.add_row("1", "Live packet capture (raw socket)")
            table.add_row("2", "Connection statistics")
            table.add_row("3", "Protocol distribution analysis")
            table.add_row("4", "Top talkers (bandwidth hogs)")
            table.add_row("5", "Detect port scanning activity")
            table.add_row("0", "Return to main menu")
            c.print(Align.center(table))

            choice = Prompt.ask("  [bold bright_green]sniff[/bold bright_green][dim]>[/dim]", default="0")

            if choice == "1":
                self._live_capture()
            elif choice == "2":
                self._connection_stats()
            elif choice == "3":
                self._protocol_distribution()
            elif choice == "4":
                self._top_talkers()
            elif choice == "5":
                self._detect_portscan()
            elif choice == "0":
                break

    def _live_capture(self):
        c = self.console
        count = int(Prompt.ask("  [bright_cyan]Packets to capture[/bright_cyan]", default="50"))
        c.print(f"\n  [bold bright_cyan]Capturing {count} packets (Ctrl+C to stop early)...[/bold bright_cyan]\n")

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            hostname = socket.gethostname()
            host_ip = socket.gethostbyname(hostname)
            s.bind((host_ip, 0))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        except Exception as e:
            c.print(f"  [bright_red]Could not create raw socket: {e}[/bright_red]")
            c.print("  [dim]Raw socket requires Administrator privileges.[/dim]")
            return

        table = Table(
            title=f"[bold bright_green]Live Capture[/bold bright_green]",
            box=box.ROUNDED, border_style="bright_green", header_style="bold bright_cyan",
        )
        table.add_column("#", style="dim", width=5)
        table.add_column("PROTOCOL", style="bright_yellow", width=8)
        table.add_column("SOURCE", style="bright_cyan", width=22)
        table.add_column("DESTINATION", style="bright_white", width=22)
        table.add_column("SIZE", style="dim", width=8, justify="right")
        table.add_column("INFO", style="dim", width=25)

        captured = 0
        try:
            while captured < count:
                data, addr = s.recvfrom(65535)
                if len(data) < 20:
                    continue

                # Parse IP header
                iph = struct.unpack('!BBHHHBBH4s4s', data[:20])
                version_ihl = iph[0]
                ihl = (version_ihl & 0xF) * 4
                total_length = iph[2]
                protocol = iph[6]
                src_ip = socket.inet_ntoa(iph[8])
                dst_ip = socket.inet_ntoa(iph[9])

                proto_name = PROTOCOL_MAP.get(protocol, str(protocol))
                info = ""

                if protocol == 6 and len(data) >= ihl + 4:  # TCP
                    src_port = struct.unpack('!H', data[ihl:ihl+2])[0]
                    dst_port = struct.unpack('!H', data[ihl+2:ihl+4])[0]
                    src_svc = WELL_KNOWN_PORTS.get(src_port, "")
                    dst_svc = WELL_KNOWN_PORTS.get(dst_port, "")
                    info = f"{src_port}->{dst_port}"
                    if dst_svc:
                        info += f" ({dst_svc})"
                elif protocol == 17 and len(data) >= ihl + 4:  # UDP
                    src_port = struct.unpack('!H', data[ihl:ihl+2])[0]
                    dst_port = struct.unpack('!H', data[ihl+2:ihl+4])[0]
                    info = f"{src_port}->{dst_port}"

                captured += 1
                table.add_row(
                    str(captured),
                    proto_name,
                    src_ip,
                    dst_ip,
                    str(total_length),
                    info[:25],
                )

        except KeyboardInterrupt:
            c.print("\n  [dim]Capture stopped.[/dim]")
        finally:
            try:
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                s.close()
            except Exception:
                pass

        c.print()
        c.print(table)
        c.print(f"\n  [bright_green]Captured {captured} packets[/bright_green]")

    def _connection_stats(self):
        c = self.console
        connections = psutil.net_connections(kind="inet")
        stats = Counter()
        for conn in connections:
            stats[conn.status] += 1

        table = Table(
            title="[bold bright_green]Connection Statistics[/bold bright_green]",
            box=box.DOUBLE_EDGE, border_style="bright_green", header_style="bold bright_cyan",
        )
        table.add_column("STATUS", style="bold bright_white", width=20)
        table.add_column("COUNT", style="bright_cyan", width=10, justify="center")
        table.add_column("BAR", width=40)

        max_count = max(stats.values()) if stats else 1
        for status, count in sorted(stats.items(), key=lambda x: x[1], reverse=True):
            bar_len = int((count / max_count) * 30)
            bar = f"[bright_green]{'=' * bar_len}[/bright_green]{'.' * (30 - bar_len)}"
            table.add_row(status, str(count), bar)

        c.print()
        c.print(Align.center(table))
        c.print(f"\n  [dim]Total connections: {len(connections)}[/dim]")

    def _protocol_distribution(self):
        c = self.console
        connections = psutil.net_connections(kind="all")
        proto_count: Counter = Counter()
        for conn in connections:
            if conn.type == socket.SOCK_STREAM:
                proto_count["TCP"] += 1
            elif conn.type == socket.SOCK_DGRAM:
                proto_count["UDP"] += 1
            else:
                proto_count["Other"] += 1

        table = Table(
            title="[bold bright_green]Protocol Distribution[/bold bright_green]",
            box=box.DOUBLE_EDGE, border_style="bright_green", header_style="bold bright_cyan",
        )
        table.add_column("PROTOCOL", style="bold bright_white", width=15)
        table.add_column("COUNT", style="bright_cyan", width=10, justify="center")
        table.add_column("PERCENTAGE", style="bright_yellow", width=15, justify="center")

        total = sum(proto_count.values())
        for proto, count in proto_count.most_common():
            pct = (count / total * 100) if total else 0
            table.add_row(proto, str(count), f"{pct:.1f}%")

        c.print()
        c.print(Align.center(table))

    def _top_talkers(self):
        c = self.console
        connections = psutil.net_connections(kind="inet")
        ip_count: Counter = Counter()

        for conn in connections:
            if conn.raddr:
                ip_count[conn.raddr.ip] += 1
            if conn.laddr:
                ip_count[conn.laddr.ip] += 1

        table = Table(
            title="[bold bright_green]Top Talkers (Most Connections)[/bold bright_green]",
            box=box.DOUBLE_EDGE, border_style="bright_green", header_style="bold bright_cyan",
        )
        table.add_column("IP", style="bold bright_white", width=18)
        table.add_column("CONNECTIONS", style="bright_cyan", width=14, justify="center")
        table.add_column("HOSTNAME", style="dim", width=30)

        for ip, count in ip_count.most_common(20):
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = "N/A"
            table.add_row(ip, str(count), hostname[:30])

        c.print()
        c.print(Align.center(table))

    def _detect_portscan(self):
        c = self.console
        c.print("\n  [bold bright_cyan]Analyzing connections for port scanning patterns...[/bold bright_cyan]")

        connections = psutil.net_connections(kind="inet")
        # Group by remote IP and count distinct destination ports
        ip_ports: dict[str, set] = {}
        for conn in connections:
            if conn.laddr and conn.status in ("SYN_SENT", "SYN_RECV", "ESTABLISHED"):
                local_port = conn.laddr.port
                if conn.raddr:
                    remote_ip = conn.raddr.ip
                    if remote_ip not in ip_ports:
                        ip_ports[remote_ip] = set()
                    ip_ports[remote_ip].add(conn.raddr.port)

        suspects = [(ip, ports) for ip, ports in ip_ports.items() if len(ports) > 10]

        if not suspects:
            c.print("  [bold bright_green]No port scanning activity detected.[/bold bright_green]")
            return

        table = Table(
            title=f"[bold bright_red]Potential Port Scanning ({len(suspects)} sources)[/bold bright_red]",
            box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
        )
        table.add_column("IP", style="bold bright_red", width=18)
        table.add_column("UNIQUE PORTS", style="bright_yellow", width=14, justify="center")
        table.add_column("SAMPLE PORTS", style="dim", width=45)

        for ip, ports in sorted(suspects, key=lambda x: len(x[1]), reverse=True):
            sample = ", ".join(str(p) for p in sorted(ports)[:10])
            table.add_row(ip, str(len(ports)), sample)

        c.print()
        c.print(Align.center(table))
