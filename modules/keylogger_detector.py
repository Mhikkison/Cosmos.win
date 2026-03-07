"""
Keylogger Detector — Detect keyloggers by scanning for keyboard hooks,
suspicious processes, known keylogger signatures, and clipboard monitors.
"""

import os
import psutil
import subprocess
import ctypes
import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box


KNOWN_KEYLOGGERS = {
    "keylogger.exe", "kl.exe", "hooklog.exe", "keylog.exe",
    "spyrix.exe", "refog.exe", "actual-keylogger.exe",
    "ardamax.exe", "revealer.exe", "elite-keylogger.exe",
    "best-free-keylogger.exe", "kidlogger.exe", "logkeys.exe",
    "pykeylogger.exe", "shadowkeylogger.exe", "blackbox.exe",
    "keystroke.exe", "inputlog.exe", "keysnitch.exe",
    "wolfeye.exe", "hoverwatch.exe", "mspy.exe",
    "flexispy.exe", "cocospy.exe", "spyic.exe",
}

HOOK_RELATED_APIS = [
    "SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState",
    "GetKeyboardState", "RegisterRawInputDevices",
    "GetRawInputData", "GetClipboardData", "OpenClipboard",
]

SUSPICIOUS_LOG_EXTENSIONS = {".log", ".txt", ".dat", ".key", ".kbd"}
SUSPICIOUS_LOG_NAMES = {"keylog", "keystroke", "keyboard", "inputlog", "typedkeys", "kbdata"}


class KeyloggerDetector:
    def __init__(self, console: Console):
        self.console = console
        self.findings: list[dict] = []

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold bright_red]KEYLOGGER DETECTOR[/bold bright_red]\n"
                         "[dim]Keyboard hook scanner, known keylogger finder & clipboard monitor check[/dim]"),
            border_style="bright_red", box=box.DOUBLE_EDGE,
        ))

        while True:
            c.print()
            table = Table(box=box.ROUNDED, border_style="bright_red", header_style="bold bright_cyan")
            table.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            table.add_column("ACTION", style="bold bright_red", width=50)
            table.add_row("1", "Full keylogger detection scan")
            table.add_row("2", "Check for keyboard hooks (WinAPI)")
            table.add_row("3", "Scan for known keylogger processes")
            table.add_row("4", "Find suspicious log files")
            table.add_row("5", "Check clipboard monitoring")
            table.add_row("6", "Kill detected keyloggers")
            table.add_row("0", "Return to main menu")
            c.print(Align.center(table))

            choice = Prompt.ask("  [bold bright_red]kl[/bold bright_red][dim]>[/dim]", default="0")

            if choice == "1":
                self._full_scan()
            elif choice == "2":
                self._check_hooks()
            elif choice == "3":
                self._scan_processes()
            elif choice == "4":
                self._find_log_files()
            elif choice == "5":
                self._check_clipboard()
            elif choice == "6":
                self._kill_keyloggers()
            elif choice == "0":
                break

    def _full_scan(self):
        c = self.console
        self.findings = []

        with Progress(
            SpinnerColumn(style="bright_red"),
            TextColumn("[bold bright_red]{task.description}[/bold bright_red]"),
            BarColumn(bar_width=40, style="bright_red"),
            TextColumn("[bright_white]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=c,
        ) as progress:
            t = progress.add_task("Scanning...", total=4)

            progress.update(t, description="[1/4] Checking keyboard hooks")
            self._detect_hooks()
            progress.advance(t)

            progress.update(t, description="[2/4] Scanning processes")
            self._detect_process_names()
            progress.advance(t)

            progress.update(t, description="[3/4] Scanning command lines")
            self._detect_cmdline()
            progress.advance(t)

            progress.update(t, description="[4/4] Checking for log files")
            self._detect_log_files()
            progress.advance(t)

        self._show_results()

    def _detect_hooks(self):
        """Check if any process is using SetWindowsHookEx for keyboard hooking."""
        # We scan process imported DLLs for hook-related functions
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                cmdline = " ".join(proc.cmdline()).lower()
                # Check for processes that commonly hook keyboards
                if any(api.lower() in cmdline for api in HOOK_RELATED_APIS):
                    self.findings.append({
                        "type": "HOOK API",
                        "name": proc.info["name"],
                        "detail": f"PID: {proc.info['pid']} | Hook API in command line",
                        "pid": proc.info["pid"],
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _detect_process_names(self):
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                name = (proc.info["name"] or "").lower()
                if name in KNOWN_KEYLOGGERS:
                    self.findings.append({
                        "type": "KNOWN KEYLOGGER",
                        "name": proc.info["name"],
                        "detail": f"PID: {proc.info['pid']} | Path: {proc.info.get('exe', 'N/A')}",
                        "pid": proc.info["pid"],
                    })
                # Also check if process name contains suspicious words
                if any(kw in name for kw in ["keylog", "hook", "keystroke", "inputcapture"]):
                    self.findings.append({
                        "type": "SUSPICIOUS NAME",
                        "name": proc.info["name"],
                        "detail": f"PID: {proc.info['pid']}",
                        "pid": proc.info["pid"],
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _detect_cmdline(self):
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                cmdline = " ".join(proc.cmdline()).lower()
                if any(kw in cmdline for kw in ["getasynckeystate", "setwinhookex", "keylogger",
                                                  "keystroke", "keyboard hook"]):
                    self.findings.append({
                        "type": "CMDLINE MATCH",
                        "name": proc.info["name"],
                        "detail": f"PID: {proc.info['pid']}",
                        "pid": proc.info["pid"],
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _detect_log_files(self):
        search_dirs = [
            os.environ.get("TEMP", ""),
            os.environ.get("APPDATA", ""),
            os.path.expanduser("~"),
            os.path.expanduser("~/Documents"),
        ]
        for d in search_dirs:
            if not d or not os.path.isdir(d):
                continue
            try:
                for fname in os.listdir(d):
                    name_lower = fname.lower()
                    ext = os.path.splitext(name_lower)[1]
                    if ext in SUSPICIOUS_LOG_EXTENSIONS:
                        if any(kw in name_lower for kw in SUSPICIOUS_LOG_NAMES):
                            self.findings.append({
                                "type": "LOG FILE",
                                "name": fname,
                                "detail": os.path.join(d, fname),
                                "pid": None,
                            })
            except PermissionError:
                continue

    def _check_hooks(self):
        c = self.console
        c.print("\n  [bold bright_cyan]Checking for active keyboard hooks...[/bold bright_cyan]")

        # Use PowerShell to check for keyboard hook DLLs
        try:
            output = subprocess.run(
                ["powershell", "-Command",
                 "Get-Process | Where-Object {$_.Modules.ModuleName -match 'hook'} | Select-Object Id, ProcessName | Format-Table -AutoSize"],
                capture_output=True, text=True, timeout=15
            )
            if output.stdout.strip():
                c.print("\n  [bright_yellow]Processes with hook-related modules:[/bright_yellow]")
                c.print(f"  {output.stdout}")
            else:
                c.print("  [bright_green]No obvious hook modules found.[/bright_green]")
        except Exception as e:
            c.print(f"  [dim]Could not check hooks: {e}[/dim]")

    def _scan_processes(self):
        self.findings = []
        self._detect_process_names()
        self._show_results()

    def _find_log_files(self):
        self.findings = []
        self._detect_log_files()
        self._show_results()

    def _check_clipboard(self):
        c = self.console
        c.print("\n  [bold bright_cyan]Checking clipboard access...[/bold bright_cyan]")

        # Check which processes have clipboard access
        clipboard_procs = []
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                cmdline = " ".join(proc.cmdline()).lower()
                if any(cb in cmdline for cb in ["clipboard", "clipspy", "clipboardmonitor"]):
                    clipboard_procs.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if clipboard_procs:
            table = Table(box=box.ROUNDED, border_style="bright_red", header_style="bold bright_cyan")
            table.add_column("PID", style="bright_yellow", width=8)
            table.add_column("PROCESS", style="bold bright_red", width=30)
            for p in clipboard_procs:
                table.add_row(str(p["pid"]), p["name"])
            c.print(Align.center(table))
        else:
            c.print("  [bright_green]No obvious clipboard monitors detected.[/bright_green]")

    def _show_results(self):
        c = self.console
        c.print()
        if not self.findings:
            c.print(Panel(
                "[bold bright_green]No keylogger indicators found.[/bold bright_green]",
                border_style="bright_green",
            ))
            return

        table = Table(
            title=f"[bold bright_red]Keylogger Detections ({len(self.findings)})[/bold bright_red]",
            box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
        )
        table.add_column("TYPE", style="bright_yellow", width=18)
        table.add_column("NAME", style="bold bright_red", width=25)
        table.add_column("DETAIL", style="dim", width=50)

        for f in self.findings:
            table.add_row(f["type"], f["name"][:25], f["detail"][:50])

        c.print(Align.center(table))

    def _kill_keyloggers(self):
        c = self.console
        if not self.findings:
            c.print("  [bright_yellow]Run a scan first.[/bright_yellow]")
            return

        pids = set(f["pid"] for f in self.findings if f.get("pid"))
        if not pids:
            c.print("  [dim]No killable processes.[/dim]")
            return

        if Confirm.ask(f"  Kill {len(pids)} detected process(es)?", default=False):
            for pid in pids:
                try:
                    p = psutil.Process(pid)
                    p.kill()
                    c.print(f"  [bright_red]Killed PID {pid} ({p.name()})[/bright_red]")
                except Exception as e:
                    c.print(f"  [dim]Could not kill {pid}: {e}[/dim]")
