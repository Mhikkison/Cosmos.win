"""
File Integrity Monitor — Hash-based file change detection, baseline creation,
real-time directory watching, and tamper alerting for critical system files.
"""

import os
import hashlib
import json
import time
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box

CRITICAL_PATHS = [
    r"C:\Windows\System32\drivers\etc\hosts",
    r"C:\Windows\System32\config\SAM",
    r"C:\Windows\System32\config\SYSTEM",
    r"C:\Windows\System32\config\SOFTWARE",
    r"C:\Windows\System32\cmd.exe",
    r"C:\Windows\System32\powershell.exe",
    r"C:\Windows\System32\svchost.exe",
    r"C:\Windows\System32\lsass.exe",
    r"C:\Windows\System32\csrss.exe",
    r"C:\Windows\System32\winlogon.exe",
    r"C:\Windows\System32\ntoskrnl.exe",
    r"C:\Windows\System32\hal.dll",
    r"C:\Windows\System32\kernel32.dll",
    r"C:\Windows\System32\ntdll.dll",
    r"C:\Windows\System32\advapi32.dll",
]

BASELINE_FILE = os.path.join(os.environ.get("TEMP", "."), "cosmos_fim_baseline.json")


def sha256_file(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def file_metadata(path: str) -> dict:
    try:
        stat = os.stat(path)
        return {
            "size": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
        }
    except Exception:
        return {"size": 0, "modified": "?", "created": "?"}


class FileIntegrityMonitor:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold bright_green]FILE INTEGRITY MONITOR[/bold bright_green]\n"
                         "[dim]Hash-based change detection for critical system files[/dim]"),
            border_style="bright_green", box=box.DOUBLE_EDGE,
        ))

        while True:
            c.print()
            table = Table(box=box.ROUNDED, border_style="bright_green", header_style="bold bright_cyan")
            table.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            table.add_column("ACTION", style="bold bright_green", width=50)
            table.add_row("1", "Scan critical system files (hash check)")
            table.add_row("2", "Create baseline snapshot")
            table.add_row("3", "Compare current state vs baseline")
            table.add_row("4", "Scan a custom directory")
            table.add_row("5", "Monitor directory for changes (live)")
            table.add_row("6", "Verify single file integrity")
            table.add_row("0", "Return to main menu")
            c.print(Align.center(table))

            choice = Prompt.ask("  [bold bright_green]fim[/bold bright_green][dim]>[/dim]", default="0")

            if choice == "1":
                self._scan_critical()
            elif choice == "2":
                self._create_baseline()
            elif choice == "3":
                self._compare_baseline()
            elif choice == "4":
                self._scan_custom()
            elif choice == "5":
                self._monitor_live()
            elif choice == "6":
                self._verify_single()
            elif choice == "0":
                break

    def _scan_critical(self):
        c = self.console
        table = Table(
            title="[bold bright_green]Critical System File Integrity[/bold bright_green]",
            box=box.DOUBLE_EDGE, border_style="bright_green", header_style="bold bright_cyan",
        )
        table.add_column("FILE", style="bold bright_white", width=45)
        table.add_column("SHA-256", style="dim", width=18)
        table.add_column("SIZE", style="bright_cyan", width=12, justify="right")
        table.add_column("MODIFIED", style="dim", width=22)
        table.add_column("STATUS", style="bold", width=10)

        with Progress(
            SpinnerColumn(style="bright_green"),
            TextColumn("[bold bright_green]Hashing files...[/bold bright_green]"),
            BarColumn(bar_width=30, style="bright_green"),
            TextColumn("{task.completed}/{task.total}"),
            console=c,
        ) as progress:
            t = progress.add_task("Hashing...", total=len(CRITICAL_PATHS))
            for path in CRITICAL_PATHS:
                h = sha256_file(path)
                meta = file_metadata(path)
                exists = os.path.exists(path)
                if not exists:
                    status = "[bright_red]MISSING[/bright_red]"
                elif h:
                    status = "[bright_green]OK[/bright_green]"
                else:
                    status = "[bright_yellow]DENIED[/bright_yellow]"

                fname = os.path.basename(path)
                table.add_row(
                    fname,
                    (h[:16] + "...") if h else "N/A",
                    f"{meta['size']:,}" if meta["size"] else "?",
                    meta["modified"][:19],
                    status,
                )
                progress.advance(t)

        c.print()
        c.print(Align.center(table))

    def _create_baseline(self):
        c = self.console
        baseline = {"timestamp": datetime.now().isoformat(), "files": {}}

        paths = list(CRITICAL_PATHS)
        custom = c.input("  [dim]Add a custom directory? (leave empty to skip): [/dim]").strip()
        if custom and os.path.isdir(custom):
            try:
                for fname in os.listdir(custom):
                    fpath = os.path.join(custom, fname)
                    if os.path.isfile(fpath):
                        paths.append(fpath)
            except PermissionError:
                pass

        with Progress(
            SpinnerColumn(style="bright_green"),
            TextColumn("[bold bright_green]Creating baseline...[/bold bright_green]"),
            BarColumn(bar_width=30),
            console=c,
        ) as progress:
            t = progress.add_task("Hashing...", total=len(paths))
            for path in paths:
                h = sha256_file(path)
                meta = file_metadata(path)
                baseline["files"][path] = {"hash": h, **meta}
                progress.advance(t)

        try:
            with open(BASELINE_FILE, "w") as f:
                json.dump(baseline, f, indent=2)
            c.print(f"\n  [bold bright_green]Baseline saved ({len(paths)} files) to {BASELINE_FILE}[/bold bright_green]")
        except Exception as e:
            c.print(f"  [bright_red]Error: {e}[/bright_red]")

    def _compare_baseline(self):
        c = self.console
        if not os.path.isfile(BASELINE_FILE):
            c.print("  [bright_yellow]No baseline found. Create one first (option 2).[/bright_yellow]")
            return

        with open(BASELINE_FILE, "r") as f:
            baseline = json.load(f)

        c.print(f"\n  [dim]Comparing against baseline from {baseline.get('timestamp', '?')}[/dim]")

        changes = []
        for path, old_data in baseline.get("files", {}).items():
            if not os.path.exists(path):
                changes.append({"file": path, "change": "DELETED", "detail": "File no longer exists"})
                continue
            new_hash = sha256_file(path)
            if new_hash and old_data.get("hash") and new_hash != old_data["hash"]:
                changes.append({"file": path, "change": "MODIFIED", "detail": f"Hash changed"})
            new_meta = file_metadata(path)
            if new_meta["size"] != old_data.get("size", 0):
                changes.append({"file": path, "change": "SIZE CHANGED",
                                "detail": f"{old_data.get('size', '?')} -> {new_meta['size']}"})

        if not changes:
            c.print("  [bold bright_green]No changes detected since baseline.[/bold bright_green]")
            return

        table = Table(
            title=f"[bold bright_red]File Changes Detected ({len(changes)})[/bold bright_red]",
            box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
        )
        table.add_column("FILE", style="bold bright_white", width=45)
        table.add_column("CHANGE", style="bold", width=15)
        table.add_column("DETAIL", style="dim", width=35)

        change_col = {"DELETED": "bright_red", "MODIFIED": "bright_yellow", "SIZE CHANGED": "bright_magenta"}
        for ch in changes:
            col = change_col.get(ch["change"], "white")
            table.add_row(os.path.basename(ch["file"]), f"[{col}]{ch['change']}[/{col}]", ch["detail"])

        c.print()
        c.print(Align.center(table))

    def _scan_custom(self):
        c = self.console
        directory = Prompt.ask("  [bright_cyan]Directory path[/bright_cyan]")
        if not os.path.isdir(directory):
            c.print("  [bright_red]Invalid directory.[/bright_red]")
            return

        files = []
        try:
            for fname in os.listdir(directory):
                fpath = os.path.join(directory, fname)
                if os.path.isfile(fpath):
                    files.append(fpath)
        except PermissionError:
            c.print("  [bright_red]Permission denied.[/bright_red]")
            return

        table = Table(
            title=f"[bold bright_green]Directory Scan: {directory} ({len(files)} files)[/bold bright_green]",
            box=box.DOUBLE_EDGE, border_style="bright_green", header_style="bold bright_cyan",
        )
        table.add_column("FILE", style="bold bright_white", width=35)
        table.add_column("SHA-256", style="dim", width=18)
        table.add_column("SIZE", style="bright_cyan", width=12, justify="right")
        table.add_column("MODIFIED", style="dim", width=22)

        for fpath in files[:60]:
            h = sha256_file(fpath)
            meta = file_metadata(fpath)
            table.add_row(
                os.path.basename(fpath)[:35],
                (h[:16] + "...") if h else "denied",
                f"{meta['size']:,}",
                meta["modified"][:19],
            )

        c.print()
        c.print(Align.center(table))

    def _monitor_live(self):
        c = self.console
        directory = Prompt.ask("  [bright_cyan]Directory to monitor[/bright_cyan]")
        if not os.path.isdir(directory):
            c.print("  [bright_red]Invalid directory.[/bright_red]")
            return

        c.print(f"\n  [bold bright_cyan]Monitoring {directory} for changes (Ctrl+C to stop)...[/bold bright_cyan]\n")

        def snap():
            s = {}
            try:
                for fname in os.listdir(directory):
                    fpath = os.path.join(directory, fname)
                    if os.path.isfile(fpath):
                        s[fpath] = {"size": os.path.getsize(fpath), "mtime": os.path.getmtime(fpath)}
            except Exception:
                pass
            return s

        baseline = snap()
        try:
            while True:
                time.sleep(2)
                current = snap()
                for path in current:
                    if path not in baseline:
                        c.print(f"  [bold bright_yellow]NEW: {os.path.basename(path)}[/bold bright_yellow]")
                    elif current[path] != baseline[path]:
                        c.print(f"  [bold bright_magenta]CHANGED: {os.path.basename(path)}[/bold bright_magenta]")
                for path in baseline:
                    if path not in current:
                        c.print(f"  [bold bright_red]DELETED: {os.path.basename(path)}[/bold bright_red]")
                baseline = current
        except KeyboardInterrupt:
            c.print("\n  [dim]Monitoring stopped.[/dim]")

    def _verify_single(self):
        c = self.console
        path = Prompt.ask("  [bright_cyan]File path[/bright_cyan]")
        if not os.path.isfile(path):
            c.print("  [bright_red]File not found.[/bright_red]")
            return

        h = sha256_file(path)
        meta = file_metadata(path)

        c.print(Panel(
            f"[bold bright_white]{os.path.basename(path)}[/bold bright_white]\n\n"
            f"[bright_cyan]SHA-256:[/bright_cyan] {h or 'Could not hash'}\n"
            f"[bright_cyan]Size:[/bright_cyan] {meta['size']:,} bytes\n"
            f"[bright_cyan]Modified:[/bright_cyan] {meta['modified']}\n"
            f"[bright_cyan]Created:[/bright_cyan] {meta['created']}",
            title="[bold bright_green]File Integrity[/bold bright_green]",
            border_style="bright_green",
        ))

        expected = c.input("  [dim]Expected SHA-256 (leave empty to skip): [/dim]").strip()
        if expected:
            if expected.lower() == (h or "").lower():
                c.print("  [bold bright_green]MATCH - File integrity verified.[/bold bright_green]")
            else:
                c.print("  [bold bright_red]MISMATCH - File may have been tampered with![/bold bright_red]")
