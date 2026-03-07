"""
Boot Guard — Monitor and protect boot configuration, detect bootkits,
verify Secure Boot status, analyze BCD entries, and check for MBR/UEFI tampering.
"""

import os
import subprocess
import hashlib
import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box


def run_cmd(args, timeout=15):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except Exception as e:
        return str(e)


def run_ps(command: str, timeout=20):
    try:
        r = subprocess.run(["powershell", "-Command", command],
                           capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception as e:
        return str(e)


CRITICAL_BOOT_FILES = [
    r"C:\Windows\System32\winload.exe",
    r"C:\Windows\System32\winload.efi",
    r"C:\Windows\System32\winresume.exe",
    r"C:\Windows\System32\winresume.efi",
    r"C:\Windows\System32\bootmgr.efi",
    r"C:\Windows\Boot\EFI\bootmgfw.efi",
    r"C:\Windows\System32\ci.dll",
    r"C:\Windows\System32\ntoskrnl.exe",
]


class BootGuard:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold bright_red]BOOT GUARD[/bold bright_red]\n"
                         "[dim]Boot integrity verification, Secure Boot audit & bootkit detection[/dim]"),
            border_style="bright_red", box=box.DOUBLE_EDGE,
        ))

        while True:
            c.print()
            table = Table(box=box.ROUNDED, border_style="bright_red", header_style="bold bright_cyan")
            table.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            table.add_column("ACTION", style="bold bright_red", width=55)
            table.add_row("1", "Full boot security audit")
            table.add_row("2", "Verify Secure Boot & UEFI status")
            table.add_row("3", "Analyze BCD configuration")
            table.add_row("4", "Check boot file integrity (signatures)")
            table.add_row("5", "Detect boot persistence mechanisms")
            table.add_row("6", "Check Early Launch Anti-Malware (ELAM)")
            table.add_row("0", "Return to main menu")
            c.print(Align.center(table))

            choice = Prompt.ask("  [bold bright_red]boot[/bold bright_red][dim]>[/dim]", default="0")

            if choice == "1":
                self._full_audit()
            elif choice == "2":
                self._secure_boot_status()
            elif choice == "3":
                self._analyze_bcd()
            elif choice == "4":
                self._check_boot_files()
            elif choice == "5":
                self._detect_persistence()
            elif choice == "6":
                self._check_elam()
            elif choice == "0":
                break

    def _full_audit(self):
        c = self.console
        findings = []

        with Progress(
            SpinnerColumn(style="bright_red"),
            TextColumn("[bold bright_red]{task.description}[/bold bright_red]"),
            BarColumn(bar_width=40),
            console=c,
        ) as progress:
            t = progress.add_task("Auditing boot security...", total=5)

            # Secure Boot
            progress.update(t, description="Checking Secure Boot")
            sb = run_ps("Confirm-SecureBootUEFI")
            if "True" in sb:
                findings.append(("Secure Boot", "PASS", "Enabled"))
            elif "False" in sb:
                findings.append(("Secure Boot", "FAIL", "Disabled - system vulnerable to bootkits"))
            else:
                findings.append(("Secure Boot", "WARN", "Could not determine (Legacy BIOS?)"))
            progress.advance(t)

            # Test signing
            progress.update(t, description="Checking test signing mode")
            bcd = run_cmd(["bcdedit", "/enum", "{current}"])
            if "testsigning" in bcd.lower() and "yes" in bcd.lower():
                findings.append(("Test Signing", "FAIL", "Enabled - unsigned drivers can load"))
            else:
                findings.append(("Test Signing", "PASS", "Disabled"))
            progress.advance(t)

            # Debug mode
            progress.update(t, description="Checking debug mode")
            if "debug" in bcd.lower() and "yes" in bcd.lower():
                findings.append(("Debug Mode", "FAIL", "Enabled - kernel debugging active"))
            else:
                findings.append(("Debug Mode", "PASS", "Disabled"))
            progress.advance(t)

            # Integrity checks
            progress.update(t, description="Checking integrity settings")
            if "nointegritychecks" in bcd.lower() and "yes" in bcd.lower():
                findings.append(("Integrity Checks", "FAIL", "Disabled - any driver can load"))
            else:
                findings.append(("Integrity Checks", "PASS", "Enforced"))
            progress.advance(t)

            # Boot file signatures
            progress.update(t, description="Verifying boot file signatures")
            unsigned = 0
            for path in CRITICAL_BOOT_FILES:
                if os.path.exists(path):
                    sig = run_ps(f"(Get-AuthenticodeSignature '{path}').Status")
                    if "Valid" not in sig:
                        unsigned += 1
            if unsigned > 0:
                findings.append(("Boot Files", "WARN", f"{unsigned} files with invalid signatures"))
            else:
                findings.append(("Boot Files", "PASS", "All boot files properly signed"))
            progress.advance(t)

        # Display
        table = Table(
            title="[bold bright_red]Boot Security Audit[/bold bright_red]",
            box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
        )
        table.add_column("CHECK", style="bold bright_white", width=22)
        table.add_column("STATUS", style="bold", width=10, justify="center")
        table.add_column("DETAIL", style="dim", width=55)

        status_col = {"PASS": "bright_green", "FAIL": "bright_red", "WARN": "bright_yellow"}
        for check, status, detail in findings:
            col = status_col.get(status, "white")
            table.add_row(check, f"[{col}]{status}[/{col}]", detail)

        c.print()
        c.print(Align.center(table))

        fails = sum(1 for _, s, _ in findings if s == "FAIL")
        if fails == 0:
            c.print("\n  [bold bright_green]Boot configuration looks secure.[/bold bright_green]")
        else:
            c.print(f"\n  [bold bright_red]{fails} security issue(s) found in boot configuration![/bold bright_red]")

    def _secure_boot_status(self):
        c = self.console
        sb = run_ps("Confirm-SecureBootUEFI")
        uefi = run_ps("$env:firmware_type")

        # Get UEFI variables
        sb_vars = run_ps(
            "Get-SecureBootUEFI -Name PK -ErrorAction SilentlyContinue | Select-Object Name, Bytes"
        )

        c.print(Panel(
            f"[bright_cyan]Secure Boot:[/bright_cyan] [bold {'bright_green]Enabled' if 'True' in sb else 'bright_red]Disabled'}[/bold]\n"
            f"[bright_cyan]Firmware Type:[/bright_cyan] {uefi.strip() or 'Unknown'}\n"
            f"[bright_cyan]Platform Key:[/bright_cyan] {'Present' if 'PK' in sb_vars else 'Not found'}",
            title="[bold bright_red]Secure Boot Status[/bold bright_red]",
            border_style="bright_red", box=box.DOUBLE_EDGE,
        ))

    def _analyze_bcd(self):
        c = self.console
        output = run_cmd(["bcdedit", "/enum", "all"])

        entries = []
        current = {}
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("---"):
                if current:
                    entries.append(current)
                current = {}
            elif line and "  " in line:
                parts = line.split(None, 1)
                if len(parts) == 2:
                    current[parts[0]] = parts[1]

        if current:
            entries.append(current)

        table = Table(
            title=f"[bold bright_red]BCD Entries ({len(entries)})[/bold bright_red]",
            box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
        )
        table.add_column("IDENTIFIER", style="bold bright_yellow", width=25)
        table.add_column("TYPE", style="bright_cyan", width=20)
        table.add_column("DESCRIPTION", style="bright_white", width=30)
        table.add_column("PATH", style="dim", width=35)

        for entry in entries:
            ident = entry.get("identifier", "?")
            bcd_type = entry.get("device", entry.get("type", "?"))[:20]
            desc = entry.get("description", "-")[:30]
            path = entry.get("path", "-")[:35]
            table.add_row(ident[:25], bcd_type, desc, path)

        c.print()
        c.print(Align.center(table))

        # Flag suspicious entries
        for entry in entries:
            path = entry.get("path", "").lower()
            if any(sus in path for sus in ["temp", "appdata", "users"]):
                c.print(f"  [bold bright_red]Suspicious boot entry path: {entry.get('path')}[/bold bright_red]")

    def _check_boot_files(self):
        c = self.console
        table = Table(
            title="[bold bright_red]Boot File Integrity[/bold bright_red]",
            box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
        )
        table.add_column("FILE", style="bold bright_white", width=35)
        table.add_column("EXISTS", style="bold", width=10)
        table.add_column("SIZE", style="dim", width=15, justify="right")
        table.add_column("SIGNED", style="bold", width=12)

        for path in CRITICAL_BOOT_FILES:
            exists = os.path.exists(path)
            if exists:
                size = f"{os.path.getsize(path):,}"
                sig = run_ps(f"(Get-AuthenticodeSignature '{path}').Status")
                is_signed = "Valid" in sig
                signed_col = "bright_green" if is_signed else "bright_red"
                table.add_row(
                    os.path.basename(path),
                    "[bright_green]YES[/bright_green]",
                    size,
                    f"[{signed_col}]{'VALID' if is_signed else 'INVALID'}[/{signed_col}]",
                )
            else:
                table.add_row(os.path.basename(path), "[dim]NO[/dim]", "-", "-")

        c.print()
        c.print(Align.center(table))

    def _detect_persistence(self):
        c = self.console
        c.print("\n  [bold bright_cyan]Checking for boot-level persistence mechanisms...[/bold bright_cyan]")

        checks = []

        # Check for bootkit-style entries
        bcd = run_cmd(["bcdedit", "/enum", "{bootmgr}"])
        if "custom" in bcd.lower():
            checks.append(("[bright_red]Custom bootmgr entry found[/bright_red]", "SUSPICIOUS"))
        else:
            checks.append(("[bright_green]No custom bootmgr modifications[/bright_green]", "OK"))

        # Check for boot-execute entries in registry
        import winreg
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\\CurrentControlSet\\Control\\Session Manager",
                0, winreg.KEY_READ)
            val, _ = winreg.QueryValueEx(key, "BootExecute")
            winreg.CloseKey(key)
            if val and val != ["autocheck autochk *"]:
                checks.append((f"[bright_red]Unusual BootExecute: {val}[/bright_red]", "SUSPICIOUS"))
            else:
                checks.append(("[bright_green]BootExecute is default[/bright_green]", "OK"))
        except Exception:
            checks.append(("[dim]Could not read BootExecute[/dim]", "UNKNOWN"))

        # Check boot drivers
        drivers_output = run_cmd(["sc", "query", "type=", "driver", "state=", "all"])
        boot_drivers = [l for l in drivers_output.splitlines() if "BOOT_START" in l]
        checks.append((f"[bright_cyan]Boot-start drivers: {len(boot_drivers)}[/bright_cyan]", "INFO"))

        for msg, status in checks:
            icon = "[bright_green]OK[/bright_green]" if status == "OK" else \
                   "[bright_red]!!![/bright_red]" if status == "SUSPICIOUS" else "[dim]--[/dim]"
            c.print(f"  {icon}  {msg}")

    def _check_elam(self):
        c = self.console
        c.print("\n  [bold bright_cyan]Checking Early Launch Anti-Malware (ELAM)...[/bold bright_cyan]")

        elam_output = run_ps(
            "Get-CimInstance -Namespace root/cimv2 -ClassName Win32_Tpm -ErrorAction SilentlyContinue"
        )

        # Check if Windows Defender ELAM is active
        defender = run_ps(
            "(Get-MpComputerStatus -ErrorAction SilentlyContinue).AMRunningMode"
        )

        # Check ELAM driver registration
        elam_reg = run_ps(
            "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\EarlyLaunch' -ErrorAction SilentlyContinue"
        )

        c.print(Panel(
            f"[bright_cyan]Defender Mode:[/bright_cyan] {defender.strip() or 'Unknown'}\n"
            f"[bright_cyan]ELAM Policy:[/bright_cyan] {'Configured' if elam_reg.strip() else 'Default'}\n"
            f"[bright_cyan]TPM:[/bright_cyan] {'Detected' if elam_output.strip() else 'Not found'}",
            title="[bold bright_red]ELAM Status[/bold bright_red]",
            border_style="bright_red",
        ))
