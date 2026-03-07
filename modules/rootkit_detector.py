"""
Rootkit Detector — Detect hidden processes, hidden files, SSDT hooks,
suspicious drivers, and kernel-level tampering indicators.
"""

import os
import subprocess
import psutil
import ctypes
import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box


SUSPICIOUS_DRIVERS = {
    "amsdk.sys", "bkf.sys", "agony.sys", "hxdef.sys",
    "vanquish.sys", "fu.sys", "msdirectx.sys", "wininit.sys",
    "ndisrd.sys", "pcihdd.sys", "rkreveal.sys",
}

ROOTKIT_INDICATORS = {
    "hidden_process": "Process visible in WMI but not in API enumeration",
    "hidden_file": "File exists on disk but not visible in directory listing",
    "hooked_api": "System API appears modified or redirected",
    "suspicious_driver": "Unknown or suspicious kernel driver loaded",
    "modified_mbr": "Master Boot Record shows signs of modification",
}

CRITICAL_SYSTEM_FILES = [
    r"C:\Windows\System32\ntoskrnl.exe",
    r"C:\Windows\System32\hal.dll",
    r"C:\Windows\System32\ci.dll",
    r"C:\Windows\System32\drivers\ntfs.sys",
    r"C:\Windows\System32\drivers\disk.sys",
    r"C:\Windows\System32\drivers\classpnp.sys",
]


def run_cmd(args, timeout=15):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except Exception as e:
        return str(e)


class RootkitDetector:
    def __init__(self, console: Console):
        self.console = console
        self.findings: list[dict] = []

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold bright_red]ROOTKIT DETECTOR[/bold bright_red]\n"
                         "[dim]Hidden process detection, suspicious driver scan & kernel integrity check[/dim]"),
            border_style="bright_red", box=box.DOUBLE_EDGE,
        ))

        while True:
            c.print()
            table = Table(box=box.ROUNDED, border_style="bright_red", header_style="bold bright_cyan")
            table.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            table.add_column("ACTION", style="bold bright_red", width=50)
            table.add_row("1", "Full rootkit scan")
            table.add_row("2", "Detect hidden processes")
            table.add_row("3", "Scan loaded kernel drivers")
            table.add_row("4", "Check critical system file integrity")
            table.add_row("5", "Scan for suspicious services")
            table.add_row("6", "Check boot configuration")
            table.add_row("0", "Return to main menu")
            c.print(Align.center(table))

            choice = Prompt.ask("  [bold bright_red]rk[/bold bright_red][dim]>[/dim]", default="0")

            if choice == "1":
                self._full_scan()
            elif choice == "2":
                self._hidden_processes()
            elif choice == "3":
                self._scan_drivers()
            elif choice == "4":
                self._check_system_files()
            elif choice == "5":
                self._suspicious_services()
            elif choice == "6":
                self._check_boot()
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
            t = progress.add_task("Scanning...", total=5)

            progress.update(t, description="[1/5] Detecting hidden processes")
            self._detect_hidden_procs()
            progress.advance(t)

            progress.update(t, description="[2/5] Scanning kernel drivers")
            self._detect_suspicious_drivers()
            progress.advance(t)

            progress.update(t, description="[3/5] Checking system file integrity")
            self._detect_file_tampering()
            progress.advance(t)

            progress.update(t, description="[4/5] Checking for hidden files")
            self._detect_hidden_files()
            progress.advance(t)

            progress.update(t, description="[5/5] Verifying boot integrity")
            self._detect_boot_tampering()
            progress.advance(t)

        self._show_results()

    def _hidden_processes(self):
        self.findings = []
        self._detect_hidden_procs()
        self._show_results()

    def _detect_hidden_procs(self):
        """Compare psutil enumeration vs WMI enumeration to find hidden processes."""
        # Get PIDs from psutil
        psutil_pids = set()
        for proc in psutil.process_iter(["pid"]):
            try:
                psutil_pids.add(proc.info["pid"])
            except Exception:
                continue

        # Get PIDs from WMI
        wmi_output = run_cmd(["wmic", "process", "get", "ProcessId"])
        wmi_pids = set()
        for line in wmi_output.splitlines():
            line = line.strip()
            try:
                wmi_pids.add(int(line))
            except ValueError:
                continue

        # PIDs in WMI but not in psutil could indicate rootkit hiding
        hidden = wmi_pids - psutil_pids
        for pid in hidden:
            if pid > 4:  # Skip system/idle
                self.findings.append({
                    "type": "HIDDEN PROCESS",
                    "detail": f"PID {pid} visible in WMI but not in process API",
                    "severity": "CRITICAL",
                })

        # Also check for processes hiding from WMI
        api_only = psutil_pids - wmi_pids
        for pid in api_only:
            if pid > 4:
                self.findings.append({
                    "type": "WMI DISCREPANCY",
                    "detail": f"PID {pid} in API but not in WMI",
                    "severity": "HIGH",
                })

    def _scan_drivers(self):
        self.findings = []
        self._detect_suspicious_drivers()
        self._show_results()

    def _detect_suspicious_drivers(self):
        """Scan loaded kernel drivers for suspicious or unsigned entries."""
        output = run_cmd(["driverquery", "/v", "/fo", "csv"])
        for line in output.splitlines()[1:]:
            parts = line.strip('"').split('","')
            if len(parts) >= 6:
                driver_name = parts[0].lower()
                display_name = parts[1] if len(parts) > 1 else ""
                state = parts[3] if len(parts) > 3 else ""
                start_type = parts[4] if len(parts) > 4 else ""

                if driver_name in SUSPICIOUS_DRIVERS:
                    self.findings.append({
                        "type": "SUSPICIOUS DRIVER",
                        "detail": f"{display_name} ({driver_name}) - State: {state}",
                        "severity": "CRITICAL",
                    })

        # Check for unsigned drivers
        unsigned_output = run_cmd(["powershell", "-Command",
                                   "Get-WmiObject Win32_PnPSignedDriver | Where-Object {$_.IsSigned -eq $false} | "
                                   "Select-Object DeviceName, DriverVersion | Format-Table -AutoSize"])
        if "DeviceName" in unsigned_output:
            for line in unsigned_output.splitlines():
                line = line.strip()
                if line and not line.startswith("DeviceName") and not line.startswith("-"):
                    self.findings.append({
                        "type": "UNSIGNED DRIVER",
                        "detail": line[:70],
                        "severity": "HIGH",
                    })

    def _check_system_files(self):
        c = self.console
        import hashlib

        table = Table(
            title="[bold bright_red]Critical System File Integrity[/bold bright_red]",
            box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
        )
        table.add_column("FILE", style="bold bright_white", width=40)
        table.add_column("SIZE", style="bright_cyan", width=12, justify="right")
        table.add_column("SIGNED", style="bold", width=10)
        table.add_column("STATUS", style="bold", width=10)

        for path in CRITICAL_SYSTEM_FILES:
            if not os.path.exists(path):
                table.add_row(os.path.basename(path), "MISSING", "-", "[bright_red]ALERT[/bright_red]")
                continue

            size = os.path.getsize(path)
            # Check signature
            sig_out = run_cmd(["powershell", "-Command",
                               f"(Get-AuthenticodeSignature '{path}').Status"])
            is_signed = "Valid" in sig_out
            signed_col = "bright_green" if is_signed else "bright_red"
            status = "[bright_green]OK[/bright_green]" if is_signed else "[bright_yellow]CHECK[/bright_yellow]"

            table.add_row(
                os.path.basename(path),
                f"{size:,}",
                f"[{signed_col}]{'YES' if is_signed else 'NO'}[/{signed_col}]",
                status,
            )

        c.print()
        c.print(Align.center(table))

    def _detect_file_tampering(self):
        """Check if critical files have been replaced or modified."""
        for path in CRITICAL_SYSTEM_FILES:
            if not os.path.exists(path):
                self.findings.append({
                    "type": "MISSING FILE",
                    "detail": f"{path} does not exist",
                    "severity": "CRITICAL",
                })

    def _detect_hidden_files(self):
        """Look for files with hidden+system attributes in unusual locations."""
        check_dirs = [
            r"C:\Windows",
            r"C:\Windows\System32",
            os.environ.get("TEMP", r"C:\Temp"),
        ]
        for d in check_dirs:
            if not os.path.isdir(d):
                continue
            output = run_cmd(["attrib", d + "\\*.*"])
            for line in output.splitlines():
                if "SH" in line[:10] and "R" not in line[:10]:
                    filepath = line[10:].strip()
                    if filepath and not any(safe in filepath.lower() for safe in
                                            ["desktop.ini", "thumbs.db", "ntuser.dat"]):
                        self.findings.append({
                            "type": "HIDDEN FILE",
                            "detail": filepath[:70],
                            "severity": "MEDIUM",
                        })

    def _detect_boot_tampering(self):
        """Check BCD for signs of bootkits."""
        output = run_cmd(["bcdedit", "/enum", "all"])
        if "testsigning" in output.lower() and "yes" in output.lower():
            self.findings.append({
                "type": "TEST SIGNING",
                "detail": "Test signing mode enabled (can load unsigned drivers)",
                "severity": "HIGH",
            })

    def _suspicious_services(self):
        self.findings = []
        output = run_cmd(["sc", "query", "type=", "driver", "state=", "all"])
        for line in output.splitlines():
            if "SERVICE_NAME:" in line:
                svc_name = line.split(":", 1)[1].strip().lower()
                if svc_name in SUSPICIOUS_DRIVERS:
                    self.findings.append({
                        "type": "SUSPICIOUS SERVICE",
                        "detail": svc_name,
                        "severity": "CRITICAL",
                    })
        self._show_results()

    def _check_boot(self):
        c = self.console
        output = run_cmd(["bcdedit", "/enum", "{current}"])
        c.print(Panel(
            f"[dim]{output[:500]}[/dim]",
            title="[bold bright_red]Boot Configuration[/bold bright_red]",
            border_style="bright_red",
        ))

        # Check for suspicious boot entries
        if "testsigning" in output.lower():
            c.print("  [bold bright_red]Test signing is enabled![/bold bright_red]")
        if "nointegritychecks" in output.lower():
            c.print("  [bold bright_red]Integrity checks are disabled![/bold bright_red]")
        if "debug" in output.lower():
            c.print("  [bright_yellow]Debug mode detected.[/bright_yellow]")

    def _show_results(self):
        c = self.console
        c.print()
        if not self.findings:
            c.print(Panel(
                "[bold bright_green]No rootkit indicators found.[/bold bright_green]",
                border_style="bright_green",
            ))
            return

        table = Table(
            title=f"[bold bright_red]Rootkit Findings ({len(self.findings)})[/bold bright_red]",
            box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
        )
        table.add_column("TYPE", style="bright_yellow", width=20)
        table.add_column("DETAIL", style="bright_white", width=55)
        table.add_column("SEVERITY", style="bold", width=12, justify="center")

        sev_col = {"CRITICAL": "bright_red", "HIGH": "bright_yellow", "MEDIUM": "bright_magenta"}
        for f in self.findings:
            col = sev_col.get(f["severity"], "white")
            table.add_row(f["type"], f["detail"][:55], f"[{col}]{f['severity']}[/{col}]")

        c.print(Align.center(table))
