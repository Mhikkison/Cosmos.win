"""
Bandwidth Monitor — Real-time network bandwidth monitoring per interface,
per-process network usage, traffic spike detection, and speed test.
"""

import time
import psutil
import socket
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.prompt import Prompt
from rich.live import Live
from rich import box

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


def format_bytes(b: float) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


def format_speed(bps: float) -> str:
    """Format bytes/sec as human-readable speed."""
    if bps < 1024:
        return f"{bps:.0f} B/s"
    elif bps < 1048576:
        return f"{bps/1024:.1f} KB/s"
    elif bps < 1073741824:
        return f"{bps/1048576:.2f} MB/s"
    else:
        return f"{bps/1073741824:.2f} GB/s"


class BandwidthMonitor:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold bright_blue]BANDWIDTH MONITOR[/bold bright_blue]\n"
                         "[dim]Real-time network bandwidth, per-process usage & speed test[/dim]"),
            border_style="bright_blue", box=box.DOUBLE_EDGE,
        ))

        while True:
            c.print()
            table = Table(box=box.ROUNDED, border_style="bright_blue", header_style="bold bright_cyan")
            table.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            table.add_column("ACTION", style="bold bright_blue", width=55)
            table.add_row("1", "Live bandwidth monitor (10 seconds)")
            table.add_row("2", "Per-interface statistics")
            table.add_row("3", "Top network-consuming processes")
            table.add_row("4", "Connection count by process")
            table.add_row("5", "Simple download speed test")
            table.add_row("0", "Return to main menu")
            c.print(Align.center(table))

            choice = Prompt.ask("  [bold bright_blue]bw[/bold bright_blue][dim]>[/dim]", default="0")

            if choice == "1":
                self._live_monitor()
            elif choice == "2":
                self._interface_stats()
            elif choice == "3":
                self._top_processes()
            elif choice == "4":
                self._connection_count()
            elif choice == "5":
                self._speed_test()
            elif choice == "0":
                break

    def _live_monitor(self):
        c = self.console
        c.print("\n  [dim]Monitoring bandwidth for 10 seconds (Ctrl+C to stop)...[/dim]\n")

        samples = []
        prev = psutil.net_io_counters()
        try:
            for i in range(10):
                time.sleep(1)
                current = psutil.net_io_counters()
                sent = current.bytes_sent - prev.bytes_sent
                recv = current.bytes_recv - prev.bytes_recv
                samples.append((sent, recv))
                prev = current

                # Live output
                sent_col = "bright_red" if sent > 1048576 else "bright_yellow" if sent > 102400 else "bright_green"
                recv_col = "bright_red" if recv > 1048576 else "bright_yellow" if recv > 102400 else "bright_green"
                c.print(
                    f"  [{sent_col}]UP: {format_speed(sent):>12}[/{sent_col}]  "
                    f"[{recv_col}]DOWN: {format_speed(recv):>12}[/{recv_col}]  "
                    f"[dim]({i+1}/10)[/dim]"
                )
        except KeyboardInterrupt:
            pass

        if samples:
            avg_up = sum(s for s, _ in samples) / len(samples)
            avg_down = sum(r for _, r in samples) / len(samples)
            max_up = max(s for s, _ in samples)
            max_down = max(r for _, r in samples)

            c.print(Panel(
                f"[bright_cyan]Avg Upload:[/bright_cyan] {format_speed(avg_up)}\n"
                f"[bright_cyan]Avg Download:[/bright_cyan] {format_speed(avg_down)}\n"
                f"[bright_cyan]Peak Upload:[/bright_cyan] {format_speed(max_up)}\n"
                f"[bright_cyan]Peak Download:[/bright_cyan] {format_speed(max_down)}\n"
                f"[bright_cyan]Total Sent:[/bright_cyan] {format_bytes(sum(s for s, _ in samples))}\n"
                f"[bright_cyan]Total Received:[/bright_cyan] {format_bytes(sum(r for _, r in samples))}",
                title="[bold bright_blue]Bandwidth Summary[/bold bright_blue]",
                border_style="bright_blue",
            ))

    def _interface_stats(self):
        c = self.console
        stats = psutil.net_io_counters(pernic=True)
        addrs = psutil.net_if_addrs()

        table = Table(
            title="[bold bright_blue]Network Interface Statistics[/bold bright_blue]",
            box=box.DOUBLE_EDGE, border_style="bright_blue", header_style="bold bright_cyan",
        )
        table.add_column("INTERFACE", style="bold bright_white", width=22)
        table.add_column("IP", style="bright_cyan", width=16)
        table.add_column("SENT", style="bright_yellow", width=14, justify="right")
        table.add_column("RECEIVED", style="bright_green", width=14, justify="right")
        table.add_column("PACKETS OUT", style="dim", width=12, justify="right")
        table.add_column("PACKETS IN", style="dim", width=12, justify="right")
        table.add_column("ERRORS", style="bright_red", width=10, justify="right")

        for iface, counters in stats.items():
            ip = ""
            if iface in addrs:
                for addr in addrs[iface]:
                    if addr.family == socket.AF_INET:
                        ip = addr.address
                        break

            errors = counters.errin + counters.errout
            err_col = "bright_red" if errors > 0 else "dim"
            table.add_row(
                iface[:22], ip,
                format_bytes(counters.bytes_sent),
                format_bytes(counters.bytes_recv),
                f"{counters.packets_sent:,}",
                f"{counters.packets_recv:,}",
                f"[{err_col}]{errors}[/{err_col}]",
            )

        c.print()
        c.print(Align.center(table))

    def _top_processes(self):
        c = self.console
        c.print("\n  [dim]Sampling network connections per process...[/dim]")

        proc_conns: dict[str, dict] = {}
        connections = psutil.net_connections(kind="inet")

        for conn in connections:
            if not conn.pid:
                continue
            try:
                proc = psutil.Process(conn.pid)
                name = proc.name()
                if name not in proc_conns:
                    proc_conns[name] = {"pid": conn.pid, "conns": 0, "established": 0}
                proc_conns[name]["conns"] += 1
                if conn.status == "ESTABLISHED":
                    proc_conns[name]["established"] += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        sorted_procs = sorted(proc_conns.items(), key=lambda x: x[1]["conns"], reverse=True)

        table = Table(
            title="[bold bright_blue]Top Network Processes[/bold bright_blue]",
            box=box.DOUBLE_EDGE, border_style="bright_blue", header_style="bold bright_cyan",
        )
        table.add_column("PROCESS", style="bold bright_white", width=25)
        table.add_column("PID", style="bright_yellow", width=8)
        table.add_column("TOTAL CONNS", style="bright_cyan", width=14, justify="center")
        table.add_column("ESTABLISHED", style="bright_green", width=14, justify="center")

        for name, info in sorted_procs[:25]:
            table.add_row(name[:25], str(info["pid"]), str(info["conns"]), str(info["established"]))

        c.print()
        c.print(Align.center(table))

    def _connection_count(self):
        c = self.console
        connections = psutil.net_connections(kind="inet")

        status_counts: dict[str, int] = {}
        for conn in connections:
            status_counts[conn.status] = status_counts.get(conn.status, 0) + 1

        table = Table(
            title="[bold bright_blue]Connection Summary[/bold bright_blue]",
            box=box.DOUBLE_EDGE, border_style="bright_blue", header_style="bold bright_cyan",
        )
        table.add_column("STATUS", style="bold bright_white", width=20)
        table.add_column("COUNT", style="bright_cyan", width=10, justify="center")
        table.add_column("BAR", style="bright_blue", width=40)

        max_count = max(status_counts.values()) if status_counts else 1
        for status, count in sorted(status_counts.items(), key=lambda x: x[1], reverse=True):
            bar_len = int((count / max_count) * 35)
            bar = "=" * bar_len
            col = "bright_green" if status == "ESTABLISHED" else "bright_yellow" if status == "LISTEN" else "dim"
            table.add_row(f"[{col}]{status}[/{col}]", str(count), f"[{col}]{bar}[/{col}]")

        c.print()
        c.print(Align.center(table))
        c.print(f"\n  [dim]Total connections: {len(connections)}[/dim]")

    def _speed_test(self):
        c = self.console
        if not HAS_REQUESTS:
            c.print("  [bright_red]requests library required for speed test.[/bright_red]")
            return

        c.print("\n  [bold bright_cyan]Running download speed test...[/bold bright_cyan]")
        c.print("  [dim]Downloading test file from Cloudflare...[/dim]")

        # Use Cloudflare's speed test endpoint (100MB)
        test_url = "https://speed.cloudflare.com/__down?bytes=10000000"  # 10MB
        try:
            start = time.time()
            resp = requests.get(test_url, timeout=30, stream=True)
            total = 0
            for chunk in resp.iter_content(chunk_size=8192):
                total += len(chunk)
            elapsed = time.time() - start

            speed_bps = total / elapsed
            speed_mbps = (speed_bps * 8) / 1_000_000

            col = "bright_green" if speed_mbps > 50 else "bright_yellow" if speed_mbps > 10 else "bright_red"
            c.print(Panel(
                f"[bright_cyan]Downloaded:[/bright_cyan] {format_bytes(total)}\n"
                f"[bright_cyan]Time:[/bright_cyan] {elapsed:.2f}s\n"
                f"[bright_cyan]Speed:[/bright_cyan] [{col}]{format_speed(speed_bps)} ({speed_mbps:.1f} Mbps)[/{col}]",
                title="[bold bright_blue]Speed Test Result[/bold bright_blue]",
                border_style=col, box=box.DOUBLE_EDGE,
            ))
        except Exception as e:
            c.print(f"  [bright_red]Error: {e}[/bright_red]")
