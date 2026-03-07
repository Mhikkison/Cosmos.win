"""
Privacy Hardener — Disable Windows telemetry, tracking, ad personalization,
activity history, and other privacy-invasive features with one-click hardening.
"""

import subprocess
import winreg
import os
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box


PRIVACY_CHECKS = [
    {
        "name": "Telemetry Level",
        "key": r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
        "value": "AllowTelemetry",
        "hive": winreg.HKEY_LOCAL_MACHINE,
        "good": 0, "desc": "Set telemetry to Security (minimal)",
    },
    {
        "name": "Advertising ID",
        "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
        "value": "Enabled",
        "hive": winreg.HKEY_CURRENT_USER,
        "good": 0, "desc": "Disable ad personalization tracking",
    },
    {
        "name": "Activity History",
        "key": r"SOFTWARE\Policies\Microsoft\Windows\System",
        "value": "EnableActivityFeed",
        "hive": winreg.HKEY_LOCAL_MACHINE,
        "good": 0, "desc": "Disable activity history collection",
    },
    {
        "name": "Activity Upload",
        "key": r"SOFTWARE\Policies\Microsoft\Windows\System",
        "value": "UploadUserActivities",
        "hive": winreg.HKEY_LOCAL_MACHINE,
        "good": 0, "desc": "Prevent activity upload to Microsoft",
    },
    {
        "name": "Location Tracking",
        "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location",
        "value": "Value",
        "hive": winreg.HKEY_CURRENT_USER,
        "good_str": "Deny", "desc": "Disable location access",
    },
    {
        "name": "Cortana",
        "key": r"SOFTWARE\Policies\Microsoft\Windows\Windows Search",
        "value": "AllowCortana",
        "hive": winreg.HKEY_LOCAL_MACHINE,
        "good": 0, "desc": "Disable Cortana",
    },
    {
        "name": "Web Search in Start",
        "key": r"SOFTWARE\Policies\Microsoft\Windows\Explorer",
        "value": "DisableSearchBoxSuggestions",
        "hive": winreg.HKEY_CURRENT_USER,
        "good": 1, "desc": "Disable web search suggestions in Start",
    },
    {
        "name": "Cloud Content (Tips)",
        "key": r"SOFTWARE\Policies\Microsoft\Windows\CloudContent",
        "value": "DisableSoftLanding",
        "hive": winreg.HKEY_LOCAL_MACHINE,
        "good": 1, "desc": "Disable Windows tips and suggestions",
    },
    {
        "name": "Tailored Experiences",
        "key": r"SOFTWARE\Policies\Microsoft\Windows\CloudContent",
        "value": "DisableTailoredExperiencesWithDiagnosticData",
        "hive": winreg.HKEY_CURRENT_USER,
        "good": 1, "desc": "Disable Microsoft tailored experiences",
    },
    {
        "name": "Camera Access",
        "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam",
        "value": "Value",
        "hive": winreg.HKEY_CURRENT_USER,
        "good_str": "Deny", "desc": "Disable global camera access",
    },
    {
        "name": "Microphone Access",
        "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone",
        "value": "Value",
        "hive": winreg.HKEY_CURRENT_USER,
        "good_str": "Deny", "desc": "Disable global microphone access",
    },
]

TELEMETRY_SERVICES = [
    "DiagTrack", "dmwappushservice", "WMPNetworkSvc",
    "WerSvc", "PcaSvc",
]

TELEMETRY_TASKS = [
    r"\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
    r"\Microsoft\Windows\Application Experience\ProgramDataUpdater",
    r"\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
    r"\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
    r"\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
]


def read_reg(hive, key_path, value_name):
    try:
        key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
        val, vtype = winreg.QueryValueEx(key, value_name)
        winreg.CloseKey(key)
        return val
    except Exception:
        return None


def write_reg(hive, key_path, value_name, value, vtype=winreg.REG_DWORD):
    try:
        key = winreg.CreateKeyEx(hive, key_path, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, value_name, 0, vtype, value)
        winreg.CloseKey(key)
        return True
    except Exception:
        return False


class PrivacyHardener:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold #00ffcc]PRIVACY HARDENER[/bold #00ffcc]\n"
                         "[dim]Disable telemetry, tracking, ads & privacy-invasive features[/dim]"),
            border_style="#00ffcc", box=box.DOUBLE_EDGE,
        ))

        while True:
            c.print()
            table = Table(box=box.ROUNDED, border_style="#00ffcc", header_style="bold bright_cyan")
            table.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            table.add_column("ACTION", style="bold #00ffcc", width=55)
            table.add_row("1", "Privacy status overview")
            table.add_row("2", "One-click privacy hardening (apply all fixes)")
            table.add_row("3", "Disable telemetry services")
            table.add_row("4", "Disable telemetry scheduled tasks")
            table.add_row("5", "Reset privacy settings to default")
            table.add_row("0", "Return to main menu")
            c.print(Align.center(table))

            choice = Prompt.ask("  [bold #00ffcc]privacy[/bold #00ffcc][dim]>[/dim]", default="0")

            if choice == "1":
                self._status_overview()
            elif choice == "2":
                self._harden_all()
            elif choice == "3":
                self._disable_services()
            elif choice == "4":
                self._disable_tasks()
            elif choice == "5":
                self._reset_defaults()
            elif choice == "0":
                break

    def _status_overview(self):
        c = self.console
        table = Table(
            title="[bold #00ffcc]Privacy Settings Status[/bold #00ffcc]",
            box=box.DOUBLE_EDGE, border_style="#00ffcc", header_style="bold bright_cyan",
        )
        table.add_column("SETTING", style="bold bright_white", width=25)
        table.add_column("STATUS", style="bold", width=12)
        table.add_column("DESCRIPTION", style="dim", width=45)

        hardened = 0
        for check in PRIVACY_CHECKS:
            current = read_reg(check["hive"], check["key"], check["value"])
            if "good_str" in check:
                is_good = current == check["good_str"]
            elif "good" in check:
                is_good = current == check["good"]
            else:
                is_good = False

            if is_good:
                status = "[bright_green]HARDENED[/bright_green]"
                hardened += 1
            elif current is None:
                status = "[bright_yellow]NOT SET[/bright_yellow]"
            else:
                status = "[bright_red]EXPOSED[/bright_red]"

            table.add_row(check["name"], status, check["desc"])

        c.print()
        c.print(Align.center(table))
        c.print(f"\n  [bold bright_cyan]{hardened}/{len(PRIVACY_CHECKS)} privacy protections active[/bold bright_cyan]")

    def _harden_all(self):
        c = self.console
        c.print("\n  [bold bright_yellow]This will apply all privacy hardening settings.[/bold bright_yellow]")
        if not Confirm.ask("  Proceed?", default=False):
            return

        success = 0
        with Progress(
            SpinnerColumn(style="#00ffcc"),
            TextColumn("[bold #00ffcc]{task.description}[/bold #00ffcc]"),
            BarColumn(bar_width=40),
            console=c,
        ) as progress:
            t = progress.add_task("Hardening...", total=len(PRIVACY_CHECKS))
            for check in PRIVACY_CHECKS:
                progress.update(t, description=f"Setting {check['name']}")
                if "good_str" in check:
                    ok = write_reg(check["hive"], check["key"], check["value"],
                                   check["good_str"], winreg.REG_SZ)
                else:
                    ok = write_reg(check["hive"], check["key"], check["value"],
                                   check["good"])
                if ok:
                    success += 1
                progress.advance(t)

        c.print(f"\n  [bold bright_green]{success}/{len(PRIVACY_CHECKS)} settings applied.[/bold bright_green]")
        if success < len(PRIVACY_CHECKS):
            c.print("  [bright_yellow]Some settings require Administrator privileges.[/bright_yellow]")

    def _disable_services(self):
        c = self.console
        if not Confirm.ask("  Disable telemetry services?", default=False):
            return

        for svc in TELEMETRY_SERVICES:
            try:
                subprocess.run(["sc", "config", svc, "start=", "disabled"],
                               capture_output=True, timeout=10)
                subprocess.run(["sc", "stop", svc],
                               capture_output=True, timeout=10)
                c.print(f"  [bright_green]Disabled: {svc}[/bright_green]")
            except Exception as e:
                c.print(f"  [bright_red]{svc}: {e}[/bright_red]")

    def _disable_tasks(self):
        c = self.console
        if not Confirm.ask("  Disable telemetry scheduled tasks?", default=False):
            return

        for task in TELEMETRY_TASKS:
            try:
                subprocess.run(
                    ["schtasks", "/change", "/tn", task, "/disable"],
                    capture_output=True, timeout=10)
                c.print(f"  [bright_green]Disabled: {task.split('/')[-1]}[/bright_green]")
            except Exception as e:
                c.print(f"  [bright_red]{task.split('/')[-1]}: {e}[/bright_red]")

    def _reset_defaults(self):
        c = self.console
        c.print("\n  [bold bright_yellow]This will reset privacy settings to Windows defaults.[/bold bright_yellow]")
        if not Confirm.ask("  Proceed?", default=False):
            return

        for check in PRIVACY_CHECKS:
            try:
                key = winreg.OpenKey(check["hive"], check["key"], 0, winreg.KEY_SET_VALUE)
                winreg.DeleteValue(key, check["value"])
                winreg.CloseKey(key)
            except Exception:
                pass

        c.print("  [bright_green]Privacy settings reset to defaults.[/bright_green]")
