"""
BIOS/UEFI Security Checker — Check firmware security settings,
Secure Boot status, TPM status, and BIOS update information.
"""

import subprocess
import platform
import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box


def run_cmd(args, timeout=15):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except Exception as e:
        return str(e)


def run_ps(cmd, timeout=15):
    return run_cmd(["powershell", "-Command", cmd], timeout)


class BiosUefiChecker:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold bright_cyan]BIOS/UEFI SECURITY CHECKER[/bold bright_cyan]\n"
                         "[dim]Firmware security, Secure Boot, TPM & hardware security analysis[/dim]"),
            border_style="bright_cyan", box=box.DOUBLE_EDGE,
        ))

        while True:
            c.print()
            table = Table(box=box.ROUNDED, border_style="bright_cyan", header_style="bold bright_cyan")
            table.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            table.add_column("ACTION", style="bold bright_cyan", width=50)
            table.add_row("1", "Full firmware security audit")
            table.add_row("2", "Check Secure Boot status")
            table.add_row("3", "Check TPM status")
            table.add_row("4", "BIOS/UEFI information")
            table.add_row("5", "Check Virtualization Based Security")
            table.add_row("6", "Hardware security summary")
            table.add_row("0", "Return to main menu")
            c.print(Align.center(table))

            choice = Prompt.ask("  [bold bright_cyan]bios[/bold bright_cyan][dim]>[/dim]", default="0")

            if choice == "1":
                self._full_audit()
            elif choice == "2":
                self._check_secureboot()
            elif choice == "3":
                self._check_tpm()
            elif choice == "4":
                self._bios_info()
            elif choice == "5":
                self._check_vbs()
            elif choice == "6":
                self._hardware_summary()
            elif choice == "0":
                break

    def _full_audit(self):
        c = self.console
        checks = []

        audit_items = [
            ("Secure Boot", self._get_secureboot),
            ("TPM", self._get_tpm),
            ("UEFI Mode", self._get_uefi_mode),
            ("Virtualization Based Security", self._get_vbs),
            ("Credential Guard", self._get_credguard),
            ("Kernel DMA Protection", self._get_dma),
            ("Device Encryption", self._get_encryption),
        ]

        with Progress(
            SpinnerColumn(style="bright_cyan"),
            TextColumn("[bold bright_cyan]{task.description}[/bold bright_cyan]"),
            BarColumn(bar_width=30),
            console=c,
        ) as progress:
            t = progress.add_task("Auditing firmware...", total=len(audit_items))
            for name, func in audit_items:
                progress.update(t, description=f"Checking {name}...")
                status, detail = func()
                checks.append({"name": name, "status": status, "detail": detail})
                progress.advance(t)
                time.sleep(0.2)

        table = Table(
            title="[bold bright_cyan]Firmware Security Audit[/bold bright_cyan]",
            box=box.DOUBLE_EDGE, border_style="bright_cyan", header_style="bold bright_cyan",
        )
        table.add_column("CHECK", style="bold bright_white", width=30)
        table.add_column("STATUS", style="bold", width=12, justify="center")
        table.add_column("DETAIL", style="dim", width=40)

        passed = 0
        for ch in checks:
            if ch["status"] == "ENABLED":
                status_str = "[bright_green]ENABLED[/bright_green]"
                passed += 1
            elif ch["status"] == "PARTIAL":
                status_str = "[bright_yellow]PARTIAL[/bright_yellow]"
            else:
                status_str = "[bright_red]DISABLED[/bright_red]"
            table.add_row(ch["name"], status_str, ch["detail"][:40])

        c.print()
        c.print(Align.center(table))

        score = int((passed / len(checks)) * 100)
        col = "bright_green" if score >= 80 else "bright_yellow" if score >= 50 else "bright_red"
        c.print(f"\n  [bold {col}]Firmware Security Score: {score}% ({passed}/{len(checks)})[/bold {col}]")

    def _check_secureboot(self):
        c = self.console
        status, detail = self._get_secureboot()
        col = "bright_green" if status == "ENABLED" else "bright_red"
        c.print(Panel(
            f"[bright_cyan]Secure Boot:[/bright_cyan] [{col}]{status}[/{col}]\n"
            f"[dim]{detail}[/dim]",
            title="[bold bright_cyan]Secure Boot[/bold bright_cyan]",
            border_style=col,
        ))

    def _check_tpm(self):
        c = self.console
        status, detail = self._get_tpm()
        col = "bright_green" if status == "ENABLED" else "bright_red"

        tpm_detail = run_ps("Get-Tpm | Format-List")
        c.print(Panel(
            f"[bright_cyan]TPM Status:[/bright_cyan] [{col}]{status}[/{col}]\n"
            f"[dim]{detail}[/dim]\n\n"
            f"[dim]{tpm_detail[:300]}[/dim]",
            title="[bold bright_cyan]TPM Details[/bold bright_cyan]",
            border_style=col,
        ))

    def _bios_info(self):
        c = self.console
        output = run_cmd(["wmic", "bios", "get", "Manufacturer,Name,Version,ReleaseDate,SMBIOSBIOSVersion", "/format:list"])

        table = Table(
            title="[bold bright_cyan]BIOS/UEFI Information[/bold bright_cyan]",
            box=box.DOUBLE_EDGE, border_style="bright_cyan", header_style="bold bright_cyan",
        )
        table.add_column("PROPERTY", style="bold bright_white", width=25)
        table.add_column("VALUE", style="bright_cyan", width=50)

        for line in output.splitlines():
            if "=" in line:
                key, val = line.split("=", 1)
                if key.strip() and val.strip():
                    table.add_row(key.strip(), val.strip()[:50])

        # Additional system info
        table.add_row("OS Architecture", platform.machine())
        table.add_row("Processor", platform.processor()[:50])

        mb_output = run_cmd(["wmic", "baseboard", "get", "Manufacturer,Product,SerialNumber", "/format:list"])
        for line in mb_output.splitlines():
            if "=" in line:
                key, val = line.split("=", 1)
                if key.strip() and val.strip():
                    table.add_row(f"MB {key.strip()}", val.strip()[:50])

        c.print()
        c.print(Align.center(table))

    def _check_vbs(self):
        c = self.console
        status, detail = self._get_vbs()
        col = "bright_green" if status == "ENABLED" else "bright_red"
        c.print(Panel(
            f"[bright_cyan]VBS Status:[/bright_cyan] [{col}]{status}[/{col}]\n"
            f"[dim]{detail}[/dim]",
            title="[bold bright_cyan]Virtualization Based Security[/bold bright_cyan]",
            border_style=col,
        ))

    def _hardware_summary(self):
        c = self.console
        table = Table(
            title="[bold bright_cyan]Hardware Security Summary[/bold bright_cyan]",
            box=box.DOUBLE_EDGE, border_style="bright_cyan", header_style="bold bright_cyan",
        )
        table.add_column("FEATURE", style="bold bright_white", width=30)
        table.add_column("STATUS", style="bold", width=12)
        table.add_column("DETAIL", style="dim", width=35)

        items = [
            ("Secure Boot", self._get_secureboot()),
            ("TPM", self._get_tpm()),
            ("UEFI Mode", self._get_uefi_mode()),
            ("VBS", self._get_vbs()),
            ("Credential Guard", self._get_credguard()),
            ("Device Encryption", self._get_encryption()),
        ]

        for name, (status, detail) in items:
            col = "bright_green" if status == "ENABLED" else "bright_red"
            table.add_row(name, f"[{col}]{status}[/{col}]", detail[:35])

        c.print()
        c.print(Align.center(table))

    # ── Check functions ──────────────────────────────────────────────────────
    def _get_secureboot(self) -> tuple[str, str]:
        output = run_ps("Confirm-SecureBootUEFI")
        if "True" in output:
            return ("ENABLED", "Secure Boot is active")
        return ("DISABLED", "Secure Boot is off or unsupported")

    def _get_tpm(self) -> tuple[str, str]:
        output = run_ps("(Get-Tpm).TpmPresent")
        if "True" in output:
            ready = run_ps("(Get-Tpm).TpmReady")
            if "True" in ready:
                return ("ENABLED", "TPM present and ready")
            return ("PARTIAL", "TPM present but not ready")
        return ("DISABLED", "No TPM detected")

    def _get_uefi_mode(self) -> tuple[str, str]:
        output = run_ps("$env:firmware_type")
        if "UEFI" in output.upper():
            return ("ENABLED", "UEFI firmware mode")
        return ("DISABLED", "Legacy BIOS mode")

    def _get_vbs(self) -> tuple[str, str]:
        output = run_ps(
            "Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard "
            "| Select-Object VirtualizationBasedSecurityStatus | Format-List"
        )
        if "2" in output:
            return ("ENABLED", "VBS running")
        elif "1" in output:
            return ("PARTIAL", "VBS enabled but not running")
        return ("DISABLED", "VBS not configured")

    def _get_credguard(self) -> tuple[str, str]:
        output = run_ps(
            "Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard "
            "| Select-Object SecurityServicesRunning | Format-List"
        )
        if "1" in output or "2" in output:
            return ("ENABLED", "Credential Guard active")
        return ("DISABLED", "Credential Guard not running")

    def _get_dma(self) -> tuple[str, str]:
        output = run_ps(
            "Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DmaSecurity' -Name DmaGuardPolicyEnabled -ErrorAction SilentlyContinue"
        )
        if "1" in output:
            return ("ENABLED", "Kernel DMA protection active")
        return ("DISABLED", "Kernel DMA protection not configured")

    def _get_encryption(self) -> tuple[str, str]:
        output = run_cmd(["manage-bde", "-status", "C:"])
        if "Fully Encrypted" in output or "Percentage Encrypted: 100" in output:
            return ("ENABLED", "BitLocker fully encrypted")
        elif "Encryption in Progress" in output:
            return ("PARTIAL", "BitLocker encryption in progress")
        return ("DISABLED", "BitLocker not enabled on C:")
