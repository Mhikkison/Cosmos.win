"""
DLL Hijack Scanner — Detect DLL hijacking vulnerabilities and phantom DLLs.
Checks for unsigned DLLs, DLLs loaded from suspicious paths,
and writable DLL directories.
"""

import os
import psutil
import subprocess
import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box


SAFE_DLL_DIRS = {
    os.environ.get("SYSTEMROOT", r"C:\Windows").lower(),
    os.path.join(os.environ.get("SYSTEMROOT", r"C:\Windows"), "System32").lower(),
    os.path.join(os.environ.get("SYSTEMROOT", r"C:\Windows"), "SysWOW64").lower(),
    os.path.join(os.environ.get("PROGRAMFILES", r"C:\Program Files")).lower(),
    os.path.join(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")).lower(),
}

SUSPICIOUS_DLL_DIRS = [
    os.environ.get("TEMP", "").lower(),
    os.environ.get("TMP", "").lower(),
    os.path.join(os.environ.get("APPDATA", ""), "Local", "Temp").lower(),
    "downloads",
]

KNOWN_HIJACK_DLLS = {
    "version.dll", "winmm.dll", "d3d9.dll", "d3d11.dll",
    "dxgi.dll", "dwmapi.dll", "uxtheme.dll", "wer.dll",
    "profapi.dll", "comctl32.dll", "msvcr100.dll", "msvcp140.dll",
    "vcruntime140.dll", "dbghelp.dll", "dbgcore.dll",
    "wintrust.dll", "crypt32.dll", "cryptsp.dll",
}


class DLLHijackScanner:
    def __init__(self, console: Console):
        self.console = console
        self.findings: list[dict] = []

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold bright_red]DLL HIJACK SCANNER[/bold bright_red]\n"
                         "[dim]Detect DLL hijacking, phantom DLLs & suspicious library loads[/dim]"),
            border_style="bright_red", box=box.DOUBLE_EDGE,
        ))

        while True:
            c.print()
            table = Table(box=box.ROUNDED, border_style="bright_red", header_style="bold bright_cyan")
            table.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            table.add_column("ACTION", style="bold bright_red", width=50)
            table.add_row("1", "Full DLL hijack scan (all running processes)")
            table.add_row("2", "Scan specific process by PID")
            table.add_row("3", "Check for unsigned DLLs in System32")
            table.add_row("4", "Find DLLs loaded from temp directories")
            table.add_row("5", "Check writable DLL search paths")
            table.add_row("0", "Return to main menu")
            c.print(Align.center(table))

            choice = Prompt.ask("  [bold bright_red]dll[/bold bright_red][dim]>[/dim]", default="0")

            if choice == "1":
                self._full_scan()
            elif choice == "2":
                self._scan_pid()
            elif choice == "3":
                self._check_unsigned()
            elif choice == "4":
                self._check_temp_dlls()
            elif choice == "5":
                self._check_writable_paths()
            elif choice == "0":
                break

    def _full_scan(self):
        c = self.console
        self.findings = []
        processes = list(psutil.process_iter(["pid", "name"]))

        with Progress(
            SpinnerColumn(style="bright_red"),
            TextColumn("[bold bright_red]{task.description}[/bold bright_red]"),
            BarColumn(bar_width=40, style="bright_red", complete_style="bright_cyan"),
            TextColumn("[bright_white]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=c,
        ) as progress:
            t = progress.add_task("Scanning DLLs...", total=len(processes))

            for proc in processes:
                try:
                    pid = proc.info["pid"]
                    name = proc.info["name"]
                    p = psutil.Process(pid)
                    try:
                        dlls = p.memory_maps()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        progress.advance(t)
                        continue

                    for dll in dlls:
                        path = dll.path.lower()
                        dll_name = os.path.basename(path)

                        # Check if DLL is from suspicious location
                        is_suspicious = False
                        reason = ""

                        dir_path = os.path.dirname(path)
                        if any(sus in dir_path for sus in SUSPICIOUS_DLL_DIRS if sus):
                            is_suspicious = True
                            reason = "Loaded from temp/suspicious directory"

                        if dll_name in KNOWN_HIJACK_DLLS:
                            # Check if it's NOT in a safe directory
                            if not any(dir_path.startswith(safe) for safe in SAFE_DLL_DIRS):
                                is_suspicious = True
                                reason = f"Known hijack target '{dll_name}' loaded from non-standard path"

                        if is_suspicious:
                            self.findings.append({
                                "process": name,
                                "pid": pid,
                                "dll": dll.path,
                                "reason": reason,
                            })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                progress.advance(t)

        self._show_results()

    def _scan_pid(self):
        c = self.console
        pid_str = Prompt.ask("  [bright_cyan]PID to scan[/bright_cyan]")
        try:
            pid = int(pid_str)
            proc = psutil.Process(pid)
        except (ValueError, psutil.NoSuchProcess):
            c.print("  [bright_red]Invalid PID[/bright_red]")
            return

        try:
            dlls = proc.memory_maps()
        except psutil.AccessDenied:
            c.print("  [bright_red]Access denied[/bright_red]")
            return

        table = Table(
            title=f"[bold bright_red]DLLs for {proc.name()} (PID {pid})[/bold bright_red]",
            box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
        )
        table.add_column("#", style="dim", width=5)
        table.add_column("DLL PATH", style="bright_white", width=70)
        table.add_column("STATUS", style="bold", width=15)

        for i, dll in enumerate(dlls[:60], 1):
            path = dll.path.lower()
            dir_path = os.path.dirname(path)
            is_safe = any(dir_path.startswith(safe) for safe in SAFE_DLL_DIRS)
            status = "[bright_green]SAFE[/bright_green]" if is_safe else "[bright_yellow]REVIEW[/bright_yellow]"
            if any(sus in dir_path for sus in SUSPICIOUS_DLL_DIRS if sus):
                status = "[bright_red]SUSPICIOUS[/bright_red]"
            table.add_row(str(i), dll.path[:70], status)

        c.print()
        c.print(table)

    def _check_unsigned(self):
        c = self.console
        c.print("\n  [bold bright_cyan]Checking for potentially unsigned DLLs in System32...[/bold bright_cyan]")
        c.print("  [dim]This uses signtool/PowerShell to verify signatures (may be slow).[/dim]")

        sys32 = os.path.join(os.environ.get("SYSTEMROOT", r"C:\Windows"), "System32")
        unsigned = []

        dlls = [f for f in os.listdir(sys32) if f.lower().endswith(".dll")][:100]

        with Progress(
            SpinnerColumn(style="bright_red"),
            TextColumn("[bold bright_red]Checking signatures...[/bold bright_red]"),
            BarColumn(bar_width=40),
            TextColumn("{task.completed}/{task.total}"),
            console=c,
        ) as progress:
            t = progress.add_task("Checking...", total=len(dlls))
            for dll in dlls:
                full_path = os.path.join(sys32, dll)
                try:
                    result = subprocess.run(
                        ["powershell", "-Command",
                         f"(Get-AuthenticodeSignature '{full_path}').Status"],
                        capture_output=True, text=True, timeout=5
                    )
                    status = result.stdout.strip()
                    if status not in ("Valid", ""):
                        unsigned.append((dll, status))
                except Exception:
                    pass
                progress.advance(t)

        if unsigned:
            table = Table(
                title=f"[bold bright_red]Non-Valid Signatures ({len(unsigned)})[/bold bright_red]",
                box=box.ROUNDED, border_style="bright_red", header_style="bold bright_cyan",
            )
            table.add_column("DLL", style="bold bright_white", width=35)
            table.add_column("SIGNATURE STATUS", style="bright_red", width=25)

            for dll, status in unsigned:
                table.add_row(dll, status)
            c.print()
            c.print(Align.center(table))
        else:
            c.print("  [bold bright_green]All checked DLLs have valid signatures.[/bold bright_green]")

    def _check_temp_dlls(self):
        c = self.console
        found = []
        temp_dirs = [
            os.environ.get("TEMP", ""),
            os.environ.get("TMP", ""),
            r"C:\Windows\Temp",
        ]

        for d in temp_dirs:
            if not d or not os.path.isdir(d):
                continue
            try:
                for fname in os.listdir(d):
                    if fname.lower().endswith(".dll"):
                        found.append(os.path.join(d, fname))
            except PermissionError:
                continue

        if not found:
            c.print("  [bold bright_green]No DLLs found in temp directories.[/bold bright_green]")
            return

        table = Table(
            title=f"[bold bright_red]DLLs in Temp Directories ({len(found)})[/bold bright_red]",
            box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
        )
        table.add_column("#", style="dim", width=5)
        table.add_column("FILE PATH", style="bright_red", width=80)

        for i, f in enumerate(found[:40], 1):
            table.add_row(str(i), f)

        c.print()
        c.print(Align.center(table))

    def _check_writable_paths(self):
        c = self.console
        c.print("\n  [bold bright_cyan]Checking PATH directories for write access...[/bold bright_cyan]")

        path_dirs = os.environ.get("PATH", "").split(";")
        writable = []

        for d in path_dirs:
            d = d.strip()
            if not d or not os.path.isdir(d):
                continue
            try:
                test_file = os.path.join(d, ".cosmos_test_write")
                with open(test_file, "w") as f:
                    f.write("test")
                os.remove(test_file)
                writable.append(d)
            except (PermissionError, OSError):
                continue

        if not writable:
            c.print("  [bold bright_green]No writable PATH directories found (good).[/bold bright_green]")
            return

        table = Table(
            title=f"[bold bright_red]Writable PATH Directories ({len(writable)})[/bold bright_red]",
            box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
        )
        table.add_column("#", style="dim", width=5)
        table.add_column("DIRECTORY", style="bright_red", width=70)

        for i, d in enumerate(writable, 1):
            table.add_row(str(i), d)

        c.print()
        c.print(Align.center(table))
        c.print("\n  [bright_yellow]Writable directories in PATH can be exploited for DLL hijacking.[/bright_yellow]")

    def _show_results(self):
        c = self.console
        c.print()
        if not self.findings:
            c.print(Panel(
                "[bold bright_green]No DLL hijacking indicators found.[/bold bright_green]",
                border_style="bright_green",
            ))
            return

        table = Table(
            title=f"[bold bright_red]DLL Hijack Findings ({len(self.findings)})[/bold bright_red]",
            box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
        )
        table.add_column("PROCESS", style="bold bright_white", width=20)
        table.add_column("PID", style="bright_yellow", width=8)
        table.add_column("DLL", style="bright_red", width=45)
        table.add_column("REASON", style="dim", width=35)

        for f in self.findings[:40]:
            table.add_row(f["process"][:20], str(f["pid"]), f["dll"][:45], f["reason"][:35])

        c.print(Align.center(table))
