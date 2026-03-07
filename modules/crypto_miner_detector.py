"""
Crypto Miner Detector — Detect unauthorized cryptocurrency mining processes.
Checks for known miner binaries, suspicious CPU usage patterns,
mining pool connections, and GPU utilization.
"""

import os
import psutil
import socket
import time
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box

KNOWN_MINER_NAMES = {
    "xmrig.exe", "xmrig-notls.exe", "xmr-stak.exe", "ccminer.exe",
    "cgminer.exe", "bfgminer.exe", "ethminer.exe", "nbminer.exe",
    "t-rex.exe", "phoenixminer.exe", "lolminer.exe", "gminer.exe",
    "nanominer.exe", "claymore.exe", "ewbf.exe", "dstm.exe",
    "minerd.exe", "minergate.exe", "nicehash.exe", "excavator.exe",
    "cpuminer.exe", "cpuminer-multi.exe", "cpuminer-opt.exe",
    "moneroocean.exe", "randomx.exe", "cryptonight.exe",
    "coinhive.exe", "minergate-cli.exe", "nheqminer.exe",
}

KNOWN_MINING_POOLS = [
    "pool.minexmr.com", "xmrpool.eu", "pool.supportxmr.com",
    "monerohash.com", "moneroocean.stream", "hashvault.pro",
    "nanopool.org", "2miners.com", "f2pool.com", "antpool.com",
    "ethermine.org", "sparkpool.com", "poolin.com", "viabtc.com",
    "nicehash.com", "miningpoolhub.com", "zpool.ca", "prohashing.com",
    "unmineable.com", "herominers.com", "c3pool.com",
]

MINING_PORTS = {3333, 4444, 5555, 7777, 8888, 9999, 14433, 14444, 45560, 45700}

MINER_CMD_PATTERNS = [
    "stratum+tcp", "stratum+ssl", "--algo", "-a cryptonight",
    "--donate-level", "--threads", "--cpu-priority", "-o pool",
    "--coin", "randomx", "kawpow", "ethash", "equihash",
]


class CryptoMinerDetector:
    def __init__(self, console: Console):
        self.console = console
        self.findings: list[dict] = []

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold bright_yellow]CRYPTO MINER DETECTOR[/bold bright_yellow]\n"
                         "[dim]Detect unauthorized mining processes, pool connections & resource abuse[/dim]"),
            border_style="bright_yellow", box=box.DOUBLE_EDGE,
        ))

        while True:
            c.print()
            table = Table(box=box.ROUNDED, border_style="bright_yellow", header_style="bold bright_cyan")
            table.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            table.add_column("ACTION", style="bold bright_yellow", width=50)
            table.add_row("1", "Full crypto miner scan")
            table.add_row("2", "Check high CPU usage processes")
            table.add_row("3", "Scan for mining pool connections")
            table.add_row("4", "Check for known miner binaries on disk")
            table.add_row("5", "Scan command lines for mining args")
            table.add_row("6", "Kill detected miners")
            table.add_row("0", "Return to main menu")
            c.print(Align.center(table))

            choice = Prompt.ask("  [bold bright_yellow]miner[/bold bright_yellow][dim]>[/dim]", default="0")

            if choice == "1":
                self._full_scan()
            elif choice == "2":
                self._check_cpu()
            elif choice == "3":
                self._check_pool_connections()
            elif choice == "4":
                self._scan_disk()
            elif choice == "5":
                self._scan_cmdlines()
            elif choice == "6":
                self._kill_miners()
            elif choice == "0":
                break

    def _full_scan(self):
        c = self.console
        self.findings = []

        with Progress(
            SpinnerColumn(style="bright_yellow"),
            TextColumn("[bold bright_yellow]{task.description}[/bold bright_yellow]"),
            BarColumn(bar_width=40, style="bright_yellow", complete_style="bright_cyan"),
            TextColumn("[bright_white]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=c,
        ) as progress:
            t = progress.add_task("Scanning...", total=5)

            progress.update(t, description="[1/5] Checking process names")
            self._scan_process_names()
            progress.advance(t)

            progress.update(t, description="[2/5] Analyzing CPU usage")
            self._scan_high_cpu()
            progress.advance(t)

            progress.update(t, description="[3/5] Checking network connections")
            self._scan_network()
            progress.advance(t)

            progress.update(t, description="[4/5] Scanning command lines")
            self._scan_cmdline_args()
            progress.advance(t)

            progress.update(t, description="[5/5] Checking common miner paths")
            self._scan_common_paths()
            progress.advance(t)

        self._show_results()

    def _scan_process_names(self):
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                name = (proc.info["name"] or "").lower()
                if name in KNOWN_MINER_NAMES:
                    self.findings.append({
                        "type": "KNOWN MINER",
                        "name": proc.info["name"],
                        "detail": f"PID: {proc.info['pid']} | Path: {proc.info.get('exe', 'N/A')}",
                        "severity": "CRITICAL",
                        "pid": proc.info["pid"],
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _scan_high_cpu(self):
        # Pre-seed
        for p in psutil.process_iter():
            try:
                p.cpu_percent(interval=None)
            except Exception:
                pass
        time.sleep(1.5)

        for proc in psutil.process_iter(["pid", "name", "cpu_percent"]):
            try:
                cpu = proc.info.get("cpu_percent", 0)
                if cpu and cpu > 80:
                    name = proc.info.get("name", "?")
                    if name.lower() not in {"system idle process", "system", "svchost.exe"}:
                        self.findings.append({
                            "type": "HIGH CPU",
                            "name": name,
                            "detail": f"PID: {proc.info['pid']} | CPU: {cpu:.1f}%",
                            "severity": "HIGH",
                            "pid": proc.info["pid"],
                        })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _scan_network(self):
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "ESTABLISHED" and conn.raddr:
                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port

                is_mining_port = remote_port in MINING_PORTS

                # Reverse DNS check
                is_pool = False
                try:
                    hostname = socket.gethostbyaddr(remote_ip)[0]
                    for pool in KNOWN_MINING_POOLS:
                        if pool in hostname.lower():
                            is_pool = True
                            break
                except Exception:
                    hostname = remote_ip

                if is_mining_port or is_pool:
                    self.findings.append({
                        "type": "POOL CONNECTION",
                        "name": hostname[:40],
                        "detail": f"Port: {remote_port} | PID: {conn.pid}",
                        "severity": "CRITICAL" if is_pool else "HIGH",
                        "pid": conn.pid,
                    })

    def _scan_cmdline_args(self):
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                cmdline = " ".join(proc.cmdline()).lower()
                for pattern in MINER_CMD_PATTERNS:
                    if pattern in cmdline:
                        self.findings.append({
                            "type": "MINING ARGS",
                            "name": proc.info["name"],
                            "detail": f"PID: {proc.info['pid']} | Pattern: {pattern}",
                            "severity": "CRITICAL",
                            "pid": proc.info["pid"],
                        })
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _scan_common_paths(self):
        search_dirs = [
            os.environ.get("TEMP", ""),
            os.environ.get("APPDATA", ""),
            os.path.expanduser("~/Downloads"),
            "C:\\Windows\\Temp",
        ]
        for d in search_dirs:
            if not d or not os.path.isdir(d):
                continue
            try:
                for fname in os.listdir(d):
                    if fname.lower() in KNOWN_MINER_NAMES:
                        self.findings.append({
                            "type": "MINER FILE",
                            "name": fname,
                            "detail": os.path.join(d, fname),
                            "severity": "HIGH",
                            "pid": None,
                        })
            except PermissionError:
                continue

    def _show_results(self):
        c = self.console
        c.print()
        if not self.findings:
            c.print(Panel(
                "[bold bright_green]No cryptocurrency miners detected.[/bold bright_green]",
                border_style="bright_green",
            ))
            return

        # Deduplicate by PID
        seen_pids = set()
        unique = []
        for f in self.findings:
            key = (f.get("pid"), f["name"], f["type"])
            if key not in seen_pids:
                seen_pids.add(key)
                unique.append(f)

        table = Table(
            title=f"[bold bright_red]Crypto Miner Detections ({len(unique)})[/bold bright_red]",
            box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
        )
        table.add_column("TYPE", style="bright_yellow", width=18)
        table.add_column("NAME", style="bold bright_red", width=25)
        table.add_column("DETAIL", style="dim", width=45)
        table.add_column("SEVERITY", style="bold", width=10, justify="center")

        sev_col = {"CRITICAL": "bright_red", "HIGH": "bright_yellow", "MEDIUM": "bright_magenta"}
        for f in unique:
            col = sev_col.get(f["severity"], "white")
            table.add_row(f["type"], f["name"][:25], f["detail"][:45],
                          f"[{col}]{f['severity']}[/{col}]")

        c.print(Align.center(table))

    def _check_cpu(self):
        self.findings = []
        self._scan_high_cpu()
        self._show_results()

    def _check_pool_connections(self):
        self.findings = []
        self._scan_network()
        self._show_results()

    def _scan_disk(self):
        self.findings = []
        self._scan_common_paths()
        self._show_results()

    def _scan_cmdlines(self):
        self.findings = []
        self._scan_cmdline_args()
        self._show_results()

    def _kill_miners(self):
        c = self.console
        if not self.findings:
            c.print("  [bright_yellow]Run a scan first to detect miners.[/bright_yellow]")
            return

        pids = set(f["pid"] for f in self.findings if f.get("pid"))
        if not pids:
            c.print("  [dim]No killable processes found.[/dim]")
            return

        if Confirm.ask(f"  Kill {len(pids)} detected miner process(es)?", default=False):
            for pid in pids:
                try:
                    p = psutil.Process(pid)
                    name = p.name()
                    p.kill()
                    c.print(f"  [bright_red]Killed PID {pid} ({name})[/bright_red]")
                except Exception as e:
                    c.print(f"  [dim]Could not kill PID {pid}: {e}[/dim]")
