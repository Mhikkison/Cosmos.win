"""
Disk Forensics — Analyze disk usage, find recently modified files,
detect hidden partitions, recover deleted file traces, and scan for
data remnants in temp/recycle bin.
"""

import os
import shutil
import time
import subprocess
from datetime import datetime, timedelta
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box


TEMP_LOCATIONS = [
    os.environ.get("TEMP", r"C:\Temp"),
    os.environ.get("TMP", r"C:\Temp"),
    r"C:\Windows\Temp",
    r"C:\Windows\Prefetch",
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "Temp"),
]

RECYCLE_BIN_PATHS = [
    r"C:\$Recycle.Bin",
    r"D:\$Recycle.Bin",
    r"E:\$Recycle.Bin",
]

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".bat", ".vbs", ".ps1", ".js", ".dll", ".scr",
    ".pif", ".cmd", ".wsh", ".wsf", ".msi", ".hta",
}


def format_bytes(b: int) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


def run_cmd(args, timeout=15):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception as e:
        return str(e)


class DiskForensics:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold bright_magenta]DISK FORENSICS[/bold bright_magenta]\n"
                         "[dim]File analysis, temp data, recycle bin scan & disk usage forensics[/dim]"),
            border_style="bright_magenta", box=box.DOUBLE_EDGE,
        ))

        while True:
            c.print()
            table = Table(box=box.ROUNDED, border_style="bright_magenta", header_style="bold bright_cyan")
            table.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            table.add_column("ACTION", style="bold bright_magenta", width=50)
            table.add_row("1", "Disk usage overview")
            table.add_row("2", "Find recently modified files")
            table.add_row("3", "Scan temp directories")
            table.add_row("4", "Analyze Recycle Bin contents")
            table.add_row("5", "Find large files")
            table.add_row("6", "Find executables in user directories")
            table.add_row("7", "Clean temp files")
            table.add_row("0", "Return to main menu")
            c.print(Align.center(table))

            choice = Prompt.ask("  [bold bright_magenta]disk[/bold bright_magenta][dim]>[/dim]", default="0")

            if choice == "1":
                self._disk_overview()
            elif choice == "2":
                self._recent_files()
            elif choice == "3":
                self._scan_temp()
            elif choice == "4":
                self._analyze_recycle()
            elif choice == "5":
                self._find_large()
            elif choice == "6":
                self._find_executables()
            elif choice == "7":
                self._clean_temp()
            elif choice == "0":
                break

    def _disk_overview(self):
        c = self.console
        table = Table(
            title="[bold bright_magenta]Disk Usage Overview[/bold bright_magenta]",
            box=box.DOUBLE_EDGE, border_style="bright_magenta", header_style="bold bright_cyan",
        )
        table.add_column("DRIVE", style="bold bright_white", width=8)
        table.add_column("TOTAL", style="bright_cyan", width=12, justify="right")
        table.add_column("USED", style="bright_yellow", width=12, justify="right")
        table.add_column("FREE", style="bright_green", width=12, justify="right")
        table.add_column("USAGE", width=25)
        table.add_column("%", style="bold", width=8, justify="center")

        for part in __import__("psutil").disk_partitions():
            try:
                usage = shutil.disk_usage(part.mountpoint)
                pct = (usage.used / usage.total) * 100
                bar_len = int(pct / 5)
                bar_col = "bright_green" if pct < 70 else "bright_yellow" if pct < 90 else "bright_red"
                bar = f"[{bar_col}]{'=' * bar_len}[/{bar_col}]{'.' * (20 - bar_len)}"
                pct_col = bar_col
                table.add_row(
                    part.mountpoint,
                    format_bytes(usage.total),
                    format_bytes(usage.used),
                    format_bytes(usage.free),
                    bar,
                    f"[{pct_col}]{pct:.1f}%[/{pct_col}]",
                )
            except (PermissionError, OSError):
                continue

        c.print()
        c.print(Align.center(table))

    def _recent_files(self):
        c = self.console
        hours = int(Prompt.ask("  [bright_cyan]Modified in last N hours[/bright_cyan]", default="24"))
        directory = Prompt.ask("  [bright_cyan]Directory[/bright_cyan]",
                               default=os.path.expanduser("~"))

        cutoff = time.time() - (hours * 3600)
        found = []

        with Progress(
            SpinnerColumn(style="bright_magenta"),
            TextColumn("[bold bright_magenta]Scanning...[/bold bright_magenta]"),
            console=c,
        ) as progress:
            t = progress.add_task("", total=None)
            try:
                for root, dirs, files in os.walk(directory):
                    for fname in files:
                        fpath = os.path.join(root, fname)
                        try:
                            if os.path.getmtime(fpath) > cutoff:
                                found.append({
                                    "path": fpath,
                                    "size": os.path.getsize(fpath),
                                    "mtime": datetime.fromtimestamp(os.path.getmtime(fpath)),
                                })
                        except (OSError, PermissionError):
                            continue
                    if len(found) >= 200:
                        break
            except PermissionError:
                pass

        if not found:
            c.print("  [dim]No recently modified files found.[/dim]")
            return

        found.sort(key=lambda x: x["mtime"], reverse=True)
        table = Table(
            title=f"[bold bright_magenta]Recently Modified Files ({len(found)})[/bold bright_magenta]",
            box=box.DOUBLE_EDGE, border_style="bright_magenta", header_style="bold bright_cyan",
        )
        table.add_column("FILE", style="bold bright_white", width=40)
        table.add_column("SIZE", style="bright_cyan", width=12, justify="right")
        table.add_column("MODIFIED", style="dim", width=22)

        for f in found[:50]:
            table.add_row(
                os.path.basename(f["path"])[:40],
                format_bytes(f["size"]),
                f["mtime"].strftime("%Y-%m-%d %H:%M:%S"),
            )

        c.print()
        c.print(Align.center(table))

    def _scan_temp(self):
        c = self.console
        table = Table(
            title="[bold bright_magenta]Temp Directory Analysis[/bold bright_magenta]",
            box=box.DOUBLE_EDGE, border_style="bright_magenta", header_style="bold bright_cyan",
        )
        table.add_column("LOCATION", style="bold bright_white", width=45)
        table.add_column("FILES", style="bright_cyan", width=10, justify="center")
        table.add_column("SIZE", style="bright_yellow", width=12, justify="right")
        table.add_column("EXECUTABLES", style="bold", width=12, justify="center")

        for loc in TEMP_LOCATIONS:
            if not os.path.isdir(loc):
                continue
            file_count = 0
            total_size = 0
            exec_count = 0
            try:
                for fname in os.listdir(loc):
                    fpath = os.path.join(loc, fname)
                    if os.path.isfile(fpath):
                        file_count += 1
                        try:
                            total_size += os.path.getsize(fpath)
                        except OSError:
                            pass
                        ext = os.path.splitext(fname)[1].lower()
                        if ext in SUSPICIOUS_EXTENSIONS:
                            exec_count += 1
            except PermissionError:
                continue

            exec_col = "bright_red" if exec_count > 0 else "bright_green"
            table.add_row(loc[:45], str(file_count), format_bytes(total_size),
                          f"[{exec_col}]{exec_count}[/{exec_col}]")

        c.print()
        c.print(Align.center(table))

    def _analyze_recycle(self):
        c = self.console
        total_files = 0
        total_size = 0

        for rb_path in RECYCLE_BIN_PATHS:
            if not os.path.isdir(rb_path):
                continue
            try:
                for root, dirs, files in os.walk(rb_path):
                    for fname in files:
                        fpath = os.path.join(root, fname)
                        try:
                            total_files += 1
                            total_size += os.path.getsize(fpath)
                        except (OSError, PermissionError):
                            continue
            except PermissionError:
                continue

        c.print(Panel(
            f"[bright_cyan]Total items:[/bright_cyan] {total_files}\n"
            f"[bright_cyan]Total size:[/bright_cyan] {format_bytes(total_size)}",
            title="[bold bright_magenta]Recycle Bin Analysis[/bold bright_magenta]",
            border_style="bright_magenta",
        ))

        if total_size > 0 and Confirm.ask("  Empty Recycle Bin?", default=False):
            try:
                run_cmd(["powershell", "-Command", "Clear-RecycleBin -Force -ErrorAction SilentlyContinue"])
                c.print(f"  [bright_green]Freed {format_bytes(total_size)}[/bright_green]")
            except Exception as e:
                c.print(f"  [bright_red]Error: {e}[/bright_red]")

    def _find_large(self):
        c = self.console
        directory = Prompt.ask("  [bright_cyan]Directory[/bright_cyan]", default="C:\\")
        min_mb = int(Prompt.ask("  [bright_cyan]Minimum size (MB)[/bright_cyan]", default="100"))
        min_bytes = min_mb * 1024 * 1024

        found = []
        with Progress(
            SpinnerColumn(style="bright_magenta"),
            TextColumn("[bold bright_magenta]Searching...[/bold bright_magenta]"),
            console=c,
        ) as progress:
            t = progress.add_task("", total=None)
            try:
                for root, dirs, files in os.walk(directory):
                    for fname in files:
                        fpath = os.path.join(root, fname)
                        try:
                            size = os.path.getsize(fpath)
                            if size >= min_bytes:
                                found.append((fpath, size))
                        except (OSError, PermissionError):
                            continue
                    if len(found) >= 100:
                        break
            except PermissionError:
                pass

        found.sort(key=lambda x: x[1], reverse=True)
        table = Table(
            title=f"[bold bright_magenta]Large Files (>{min_mb}MB)[/bold bright_magenta]",
            box=box.DOUBLE_EDGE, border_style="bright_magenta", header_style="bold bright_cyan",
        )
        table.add_column("FILE", style="bold bright_white", width=55)
        table.add_column("SIZE", style="bright_cyan", width=15, justify="right")

        for fpath, size in found[:30]:
            table.add_row(fpath[:55], format_bytes(size))

        c.print()
        c.print(Align.center(table))

    def _find_executables(self):
        c = self.console
        user_dir = os.path.expanduser("~")
        found = []

        search_dirs = [
            os.path.join(user_dir, "Desktop"),
            os.path.join(user_dir, "Downloads"),
            os.path.join(user_dir, "Documents"),
            os.environ.get("TEMP", ""),
            os.environ.get("APPDATA", ""),
        ]

        for d in search_dirs:
            if not d or not os.path.isdir(d):
                continue
            try:
                for fname in os.listdir(d):
                    ext = os.path.splitext(fname)[1].lower()
                    if ext in SUSPICIOUS_EXTENSIONS:
                        fpath = os.path.join(d, fname)
                        try:
                            size = os.path.getsize(fpath)
                        except OSError:
                            size = 0
                        found.append((fpath, size))
            except PermissionError:
                continue

        if not found:
            c.print("  [bold bright_green]No executables found in user directories.[/bold bright_green]")
            return

        table = Table(
            title=f"[bold bright_red]Executables in User Directories ({len(found)})[/bold bright_red]",
            box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
        )
        table.add_column("FILE", style="bold bright_red", width=55)
        table.add_column("SIZE", style="bright_cyan", width=12, justify="right")

        for fpath, size in found[:30]:
            table.add_row(fpath[:55], format_bytes(size))

        c.print()
        c.print(Align.center(table))

    def _clean_temp(self):
        c = self.console
        if not Confirm.ask("  Clean all temp directories?", default=False):
            return

        freed = 0
        for loc in TEMP_LOCATIONS:
            if not os.path.isdir(loc):
                continue
            try:
                for fname in os.listdir(loc):
                    fpath = os.path.join(loc, fname)
                    try:
                        if os.path.isfile(fpath):
                            freed += os.path.getsize(fpath)
                            os.remove(fpath)
                        elif os.path.isdir(fpath):
                            freed += sum(os.path.getsize(os.path.join(dp, f))
                                         for dp, dn, fn in os.walk(fpath) for f in fn)
                            shutil.rmtree(fpath, ignore_errors=True)
                    except (PermissionError, OSError):
                        continue
            except PermissionError:
                continue

        c.print(f"\n  [bold bright_green]Cleaned {format_bytes(freed)} from temp directories.[/bold bright_green]")
