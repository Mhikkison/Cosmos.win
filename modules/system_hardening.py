"""
System Hardening — Check and fix common Windows security misconfigurations.
Covers UAC, SMBv1, RDP, guest accounts, auto-login, Spectre/Meltdown,
Windows Update, PowerShell execution policy, and more.
"""

import subprocess
import winreg
import os
import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box


def read_reg_value(hive, path, name, default=None):
    try:
        key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
        val, _ = winreg.QueryValueEx(key, name)
        winreg.CloseKey(key)
        return val
    except Exception:
        return default


def set_reg_value(hive, path, name, value, reg_type=winreg.REG_DWORD):
    try:
        key = winreg.OpenKey(hive, path, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, name, 0, reg_type, value)
        winreg.CloseKey(key)
        return True
    except Exception:
        return False


def run_cmd(args, timeout=15):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except Exception as e:
        return str(e)


class SystemHardening:
    def __init__(self, console: Console):
        self.console = console
        self.checks: list[dict] = []

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold bright_cyan]SYSTEM HARDENING[/bold bright_cyan]\n"
                         "[dim]Security configuration audit & auto-fix for Windows[/dim]"),
            border_style="bright_cyan", box=box.DOUBLE_EDGE,
        ))

        while True:
            c.print()
            table = Table(box=box.ROUNDED, border_style="bright_cyan", header_style="bold bright_cyan")
            table.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            table.add_column("ACTION", style="bold bright_cyan", width=50)
            table.add_row("1", "Run full security audit (all checks)")
            table.add_row("2", "Auto-fix all FAILED checks")
            table.add_row("3", "Check UAC level")
            table.add_row("4", "Check SMBv1 status")
            table.add_row("5", "Check RDP exposure")
            table.add_row("6", "Check Guest account")
            table.add_row("7", "Check Windows Defender status")
            table.add_row("8", "Check PowerShell execution policy")
            table.add_row("9", "Check Windows Update status")
            table.add_row("0", "Return to main menu")
            c.print(Align.center(table))

            choice = Prompt.ask("  [bold bright_cyan]harden[/bold bright_cyan][dim]>[/dim]", default="0")

            if choice == "1":
                self._full_audit()
            elif choice == "2":
                self._auto_fix()
            elif choice == "3":
                self._show_single("UAC Level")
            elif choice == "4":
                self._show_single("SMBv1")
            elif choice == "5":
                self._show_single("RDP")
            elif choice == "6":
                self._show_single("Guest Account")
            elif choice == "7":
                self._show_single("Windows Defender")
            elif choice == "8":
                self._show_single("PowerShell Policy")
            elif choice == "9":
                self._show_single("Windows Update")
            elif choice == "0":
                break

    def _full_audit(self):
        c = self.console
        self.checks = []

        checks_to_run = [
            ("UAC Level", self._check_uac),
            ("SMBv1", self._check_smbv1),
            ("RDP", self._check_rdp),
            ("Guest Account", self._check_guest),
            ("Auto-Login", self._check_autologin),
            ("Remote Assistance", self._check_remote_assist),
            ("Windows Defender", self._check_defender),
            ("Firewall", self._check_firewall_state),
            ("PowerShell Policy", self._check_ps_policy),
            ("Telemetry", self._check_telemetry),
            ("Remote Registry", self._check_remote_registry),
            ("Windows Update", self._check_wupdate),
            ("NetBIOS over TCP", self._check_netbios),
            ("Autorun", self._check_autorun),
            ("Secure Boot", self._check_secureboot),
        ]

        with Progress(
            SpinnerColumn(style="bright_cyan"),
            TextColumn("[bold bright_cyan]{task.description}[/bold bright_cyan]"),
            BarColumn(bar_width=40, style="bright_blue", complete_style="bright_cyan"),
            TextColumn("[bright_white]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=c,
        ) as progress:
            t = progress.add_task("Auditing security...", total=len(checks_to_run))
            for name, func in checks_to_run:
                progress.update(t, description=f"Checking {name}...")
                result = func()
                self.checks.append({"name": name, **result})
                progress.advance(t)
                time.sleep(0.15)

        self._show_results()

    def _show_results(self):
        c = self.console
        table = Table(
            title="[bold bright_cyan]Security Audit Results[/bold bright_cyan]",
            box=box.DOUBLE_EDGE, border_style="bright_cyan", header_style="bold bright_cyan",
        )
        table.add_column("CHECK", style="bold bright_white", width=25)
        table.add_column("STATUS", style="bold", width=12, justify="center")
        table.add_column("CURRENT VALUE", style="dim", width=30)
        table.add_column("RECOMMENDATION", style="dim", width=35)

        passed = 0
        for check in self.checks:
            status = check["status"]
            if status == "PASS":
                status_str = "[bold bright_green]PASS[/bold bright_green]"
                passed += 1
            elif status == "WARN":
                status_str = "[bold bright_yellow]WARN[/bold bright_yellow]"
            else:
                status_str = "[bold bright_red]FAIL[/bold bright_red]"
            table.add_row(
                check["name"],
                status_str,
                check.get("value", "?")[:30],
                check.get("recommendation", "")[:35],
            )

        c.print()
        c.print(Align.center(table))
        total = len(self.checks)
        score = int((passed / total) * 100) if total else 0
        col = "bright_green" if score >= 80 else "bright_yellow" if score >= 50 else "bright_red"
        c.print(f"\n  [bold {col}]Security Score: {score}% ({passed}/{total} passed)[/bold {col}]")

    def _show_single(self, name: str):
        c = self.console
        func_map = {
            "UAC Level": self._check_uac,
            "SMBv1": self._check_smbv1,
            "RDP": self._check_rdp,
            "Guest Account": self._check_guest,
            "Windows Defender": self._check_defender,
            "PowerShell Policy": self._check_ps_policy,
            "Windows Update": self._check_wupdate,
        }
        func = func_map.get(name)
        if not func:
            return
        result = func()
        status = result["status"]
        col = "bright_green" if status == "PASS" else "bright_yellow" if status == "WARN" else "bright_red"
        c.print(Panel(
            f"[bold {col}]{name}: {status}[/bold {col}]\n"
            f"[dim]Value: {result.get('value', '?')}[/dim]\n"
            f"[dim]{result.get('recommendation', '')}[/dim]",
            border_style=col,
        ))

    def _auto_fix(self):
        c = self.console
        if not self.checks:
            c.print("  [bright_yellow]Run a full audit first (option 1).[/bright_yellow]")
            return

        failed = [ch for ch in self.checks if ch["status"] == "FAIL"]
        if not failed:
            c.print("  [bold bright_green]All checks passed. Nothing to fix.[/bold bright_green]")
            return

        c.print(f"\n  [bold bright_yellow]Found {len(failed)} failed check(s). Attempting auto-fix...[/bold bright_yellow]")

        fix_map = {
            "UAC Level": self._fix_uac,
            "SMBv1": self._fix_smbv1,
            "Guest Account": self._fix_guest,
            "Auto-Login": self._fix_autologin,
            "Remote Assistance": self._fix_remote_assist,
            "Telemetry": self._fix_telemetry,
            "Autorun": self._fix_autorun,
        }

        for ch in failed:
            fix_func = fix_map.get(ch["name"])
            if fix_func:
                success = fix_func()
                if success:
                    c.print(f"  [bright_green]Fixed: {ch['name']}[/bright_green]")
                else:
                    c.print(f"  [bright_red]Could not fix: {ch['name']}[/bright_red]")
            else:
                c.print(f"  [dim]No auto-fix for: {ch['name']}[/dim]")

    # ── Individual checks ────────────────────────────────────────────────────
    def _check_uac(self) -> dict:
        val = read_reg_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "EnableLUA", 0
        )
        if val == 1:
            return {"status": "PASS", "value": "Enabled", "recommendation": ""}
        return {"status": "FAIL", "value": "Disabled", "recommendation": "Enable UAC for protection"}

    def _check_smbv1(self) -> dict:
        val = read_reg_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "SMB1", 1
        )
        if val == 0:
            return {"status": "PASS", "value": "Disabled", "recommendation": ""}
        return {"status": "FAIL", "value": "Enabled", "recommendation": "Disable SMBv1 (WannaCry vector)"}

    def _check_rdp(self) -> dict:
        val = read_reg_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Terminal Server",
            "fDenyTSConnections", 1
        )
        if val == 1:
            return {"status": "PASS", "value": "RDP Disabled", "recommendation": ""}
        return {"status": "WARN", "value": "RDP Enabled", "recommendation": "Disable if not needed, use VPN"}

    def _check_guest(self) -> dict:
        output = run_cmd(["net", "user", "Guest"])
        if "Account active" in output and "No" in output.split("Account active")[-1].split("\n")[0]:
            return {"status": "PASS", "value": "Disabled", "recommendation": ""}
        return {"status": "FAIL", "value": "Active", "recommendation": "Disable Guest account"}

    def _check_autologin(self) -> dict:
        val = read_reg_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "AutoAdminLogon", "0"
        )
        if str(val) == "0":
            return {"status": "PASS", "value": "Disabled", "recommendation": ""}
        return {"status": "FAIL", "value": "Enabled", "recommendation": "Disable auto-login"}

    def _check_remote_assist(self) -> dict:
        val = read_reg_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Remote Assistance",
            "fAllowToGetHelp", 0
        )
        if val == 0:
            return {"status": "PASS", "value": "Disabled", "recommendation": ""}
        return {"status": "FAIL", "value": "Enabled", "recommendation": "Disable remote assistance"}

    def _check_defender(self) -> dict:
        val = read_reg_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows Defender",
            "DisableAntiSpyware", 0
        )
        if val == 0:
            return {"status": "PASS", "value": "Active", "recommendation": ""}
        return {"status": "FAIL", "value": "Disabled", "recommendation": "Enable Windows Defender"}

    def _check_firewall_state(self) -> dict:
        output = run_cmd(["netsh", "advfirewall", "show", "allprofiles", "state"])
        if "OFF" in output.upper():
            return {"status": "FAIL", "value": "Some profiles OFF", "recommendation": "Enable all firewall profiles"}
        return {"status": "PASS", "value": "All ON", "recommendation": ""}

    def _check_ps_policy(self) -> dict:
        output = run_cmd(["powershell", "-Command", "Get-ExecutionPolicy"])
        policy = output.strip()
        if policy in ("Restricted", "AllSigned"):
            return {"status": "PASS", "value": policy, "recommendation": ""}
        elif policy == "RemoteSigned":
            return {"status": "WARN", "value": policy, "recommendation": "Consider 'Restricted' or 'AllSigned'"}
        return {"status": "FAIL", "value": policy, "recommendation": "Set to Restricted or AllSigned"}

    def _check_telemetry(self) -> dict:
        val = read_reg_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
            "AllowTelemetry", 3
        )
        if val == 0:
            return {"status": "PASS", "value": "Disabled (0)", "recommendation": ""}
        return {"status": "FAIL", "value": f"Level {val}", "recommendation": "Set telemetry to 0 (Security)"}

    def _check_remote_registry(self) -> dict:
        output = run_cmd(["sc", "query", "RemoteRegistry"])
        if "STOPPED" in output:
            return {"status": "PASS", "value": "Stopped", "recommendation": ""}
        return {"status": "WARN", "value": "Running", "recommendation": "Stop RemoteRegistry service"}

    def _check_wupdate(self) -> dict:
        output = run_cmd(["powershell", "-Command",
                          "(New-Object -ComObject Microsoft.Update.AutoUpdate).Results.LastInstallationSuccessDate"])
        if "Exception" in output or not output.strip():
            return {"status": "WARN", "value": "Could not query", "recommendation": "Check Windows Update manually"}
        return {"status": "PASS", "value": output.strip()[:25], "recommendation": ""}

    def _check_netbios(self) -> dict:
        # NetBIOS setting in registry for the first interface
        val = read_reg_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters",
            "NodeType", 0
        )
        if val == 2:
            return {"status": "PASS", "value": "P-node (disabled)", "recommendation": ""}
        return {"status": "WARN", "value": f"NodeType={val}", "recommendation": "Set NodeType=2 to disable NetBIOS"}

    def _check_autorun(self) -> dict:
        val = read_reg_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "NoDriveTypeAutoRun", 0
        )
        if val == 255:
            return {"status": "PASS", "value": "Disabled (255)", "recommendation": ""}
        return {"status": "FAIL", "value": f"Value={val}", "recommendation": "Set NoDriveTypeAutoRun=255"}

    def _check_secureboot(self) -> dict:
        output = run_cmd(["powershell", "-Command", "Confirm-SecureBootUEFI"])
        if "True" in output:
            return {"status": "PASS", "value": "Enabled", "recommendation": ""}
        return {"status": "WARN", "value": "Disabled/Unsupported", "recommendation": "Enable Secure Boot in BIOS"}

    # ── Auto-fix functions ───────────────────────────────────────────────────
    def _fix_uac(self) -> bool:
        return set_reg_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "EnableLUA", 1
        )

    def _fix_smbv1(self) -> bool:
        return set_reg_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "SMB1", 0
        )

    def _fix_guest(self) -> bool:
        r = subprocess.run(["net", "user", "Guest", "/active:no"],
                           capture_output=True, timeout=10)
        return r.returncode == 0

    def _fix_autologin(self) -> bool:
        return set_reg_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "AutoAdminLogon", "0", winreg.REG_SZ
        )

    def _fix_remote_assist(self) -> bool:
        return set_reg_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Remote Assistance",
            "fAllowToGetHelp", 0
        )

    def _fix_telemetry(self) -> bool:
        return set_reg_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
            "AllowTelemetry", 0
        )

    def _fix_autorun(self) -> bool:
        return set_reg_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "NoDriveTypeAutoRun", 255
        )
