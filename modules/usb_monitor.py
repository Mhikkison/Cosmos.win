"""
USB Monitor — Detect connected USB devices, monitor for new insertions,
check for BadUSB indicators, view USB history from registry, and block USB storage.
"""

import subprocess
import winreg
import time
import os
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box


USB_HISTORY_KEY = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
USB_STORAGE_KEY = r"SYSTEM\CurrentControlSet\Services\USBSTOR"

BADUSB_INDICATORS = {
    "rubber ducky", "bash bunny", "teensy", "digispark",
    "usb armory", "lan turtle", "hak5", "malduino",
    "arduino leonardo", "attiny85",
}


def run_cmd(args, timeout=15):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception as e:
        return str(e)


class USBMonitor:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold bright_yellow]USB MONITOR[/bold bright_yellow]\n"
                         "[dim]USB device detection, history, BadUSB check & storage control[/dim]"),
            border_style="bright_yellow", box=box.DOUBLE_EDGE,
        ))

        while True:
            c.print()
            table = Table(box=box.ROUNDED, border_style="bright_yellow", header_style="bold bright_cyan")
            table.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            table.add_column("ACTION", style="bold bright_yellow", width=45)
            table.add_row("1", "List currently connected USB devices")
            table.add_row("2", "View USB connection history (registry)")
            table.add_row("3", "Detect BadUSB / HID attack devices")
            table.add_row("4", "Monitor for new USB insertions (live)")
            table.add_row("5", "Block / Unblock USB storage")
            table.add_row("6", "Safely eject a USB drive")
            table.add_row("0", "Return to main menu")
            c.print(Align.center(table))

            choice = Prompt.ask("  [bold bright_yellow]usb[/bold bright_yellow][dim]>[/dim]", default="0")

            if choice == "1":
                self._list_connected()
            elif choice == "2":
                self._view_history()
            elif choice == "3":
                self._detect_badusb()
            elif choice == "4":
                self._monitor_live()
            elif choice == "5":
                self._toggle_storage()
            elif choice == "6":
                self._safe_eject()
            elif choice == "0":
                break

    def _list_connected(self):
        c = self.console
        output = run_cmd(["wmic", "path", "Win32_USBControllerDevice", "get", "Dependent"])

        # Also get PnP devices
        pnp_output = run_cmd(["powershell", "-Command",
                              "Get-PnpDevice -Class USB -Status OK | Select-Object FriendlyName, InstanceId, Status | Format-Table -AutoSize"])

        table = Table(
            title="[bold bright_yellow]Connected USB Devices[/bold bright_yellow]",
            box=box.DOUBLE_EDGE, border_style="bright_yellow", header_style="bold bright_cyan",
        )
        table.add_column("#", style="dim", width=5)
        table.add_column("DEVICE NAME", style="bold bright_white", width=45)
        table.add_column("INSTANCE ID", style="dim", width=50)
        table.add_column("STATUS", style="bright_green", width=10)

        devices = []
        for line in pnp_output.splitlines():
            line = line.strip()
            if line and not line.startswith("FriendlyName") and not line.startswith("-"):
                parts = line.rsplit(None, 1)
                if len(parts) >= 1:
                    devices.append(line)

        if not devices:
            c.print("  [dim]No USB devices found or access denied.[/dim]")
            return

        for i, dev in enumerate(devices[:30], 1):
            # Try to parse friendly name
            table.add_row(str(i), dev[:45], "", "OK")

        c.print()
        c.print(Align.center(table))

    def _view_history(self):
        c = self.console
        devices = []

        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, USB_HISTORY_KEY, 0, winreg.KEY_READ)
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    devices.append(subkey_name)
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception as e:
            c.print(f"  [bright_red]Cannot read USB history: {e}[/bright_red]")
            return

        if not devices:
            c.print("  [dim]No USB storage history found.[/dim]")
            return

        table = Table(
            title=f"[bold bright_yellow]USB Storage History ({len(devices)} devices)[/bold bright_yellow]",
            box=box.DOUBLE_EDGE, border_style="bright_yellow", header_style="bold bright_cyan",
        )
        table.add_column("#", style="dim", width=5)
        table.add_column("DEVICE ID", style="bold bright_white", width=60)
        table.add_column("THREAT LEVEL", style="bold", width=15)

        for i, dev in enumerate(devices, 1):
            dev_lower = dev.lower()
            is_suspicious = any(bad in dev_lower for bad in BADUSB_INDICATORS)
            threat = "[bright_red]SUSPICIOUS[/bright_red]" if is_suspicious else "[bright_green]NORMAL[/bright_green]"
            table.add_row(str(i), dev, threat)

        c.print()
        c.print(Align.center(table))

    def _detect_badusb(self):
        c = self.console
        c.print("\n  [bold bright_cyan]Checking for HID attack devices...[/bold bright_cyan]")

        # Check for HID devices with keyboard emulation
        output = run_cmd(["powershell", "-Command",
                          "Get-PnpDevice -Class HIDClass -Status OK | Select-Object FriendlyName, InstanceId | Format-List"])

        hid_devices = []
        current = {}
        for line in output.splitlines():
            if "FriendlyName" in line and ":" in line:
                current["name"] = line.split(":", 1)[1].strip()
            elif "InstanceId" in line and ":" in line:
                current["id"] = line.split(":", 1)[1].strip()
                if current.get("name"):
                    hid_devices.append(current)
                current = {}

        # Check for USB devices presenting as keyboards suspiciously
        usb_keyboards = [d for d in hid_devices if "USB" in d.get("id", "").upper()
                         and "keyboard" in d.get("name", "").lower()]

        suspicious = []
        for dev in hid_devices:
            name_lower = dev.get("name", "").lower()
            id_lower = dev.get("id", "").lower()
            for bad in BADUSB_INDICATORS:
                if bad in name_lower or bad in id_lower:
                    suspicious.append(dev)
                    break

        table = Table(
            title="[bold bright_yellow]HID Device Analysis[/bold bright_yellow]",
            box=box.DOUBLE_EDGE, border_style="bright_yellow", header_style="bold bright_cyan",
        )
        table.add_column("DEVICE", style="bold bright_white", width=40)
        table.add_column("ID", style="dim", width=45)
        table.add_column("ASSESSMENT", style="bold", width=18)

        for dev in hid_devices[:30]:
            if dev in suspicious:
                assess = "[bright_red]SUSPICIOUS[/bright_red]"
            elif dev in usb_keyboards:
                assess = "[bright_yellow]USB KEYBOARD[/bright_yellow]"
            else:
                assess = "[bright_green]NORMAL[/bright_green]"
            table.add_row(dev.get("name", "?")[:40], dev.get("id", "?")[:45], assess)

        c.print()
        c.print(Align.center(table))

        if suspicious:
            c.print(f"\n  [bold bright_red]Found {len(suspicious)} suspicious HID device(s)![/bold bright_red]")
        else:
            c.print("\n  [bold bright_green]No known BadUSB indicators detected.[/bold bright_green]")

        if usb_keyboards:
            c.print(f"  [bright_yellow]Note: {len(usb_keyboards)} USB keyboard(s) detected — verify they are legitimate.[/bright_yellow]")

    def _monitor_live(self):
        c = self.console
        c.print("\n  [bold bright_cyan]Monitoring for USB insertions (press Ctrl+C to stop)...[/bold bright_cyan]\n")

        def get_usb_set():
            out = run_cmd(["wmic", "path", "Win32_USBHub", "get", "DeviceID"])
            return set(line.strip() for line in out.splitlines() if line.strip() and "DeviceID" not in line)

        baseline = get_usb_set()
        c.print(f"  [dim]Baseline: {len(baseline)} USB device(s)[/dim]")

        try:
            while True:
                time.sleep(2)
                current = get_usb_set()
                new_devices = current - baseline
                removed = baseline - current

                for dev in new_devices:
                    c.print(f"  [bold bright_red]NEW USB: {dev}[/bold bright_red]")
                for dev in removed:
                    c.print(f"  [bright_yellow]REMOVED: {dev}[/bright_yellow]")

                baseline = current
        except KeyboardInterrupt:
            c.print("\n  [dim]Monitoring stopped.[/dim]")

    def _toggle_storage(self):
        c = self.console
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, USB_STORAGE_KEY, 0, winreg.KEY_READ)
            val, _ = winreg.QueryValueEx(key, "Start")
            winreg.CloseKey(key)
        except Exception:
            val = 3

        current = "ENABLED" if val == 3 else "BLOCKED"
        col = "bright_green" if val == 3 else "bright_red"
        c.print(f"\n  USB Storage is currently: [{col}]{current}[/{col}]")

        if val == 3:
            if Confirm.ask("  Block USB storage?", default=False):
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, USB_STORAGE_KEY, 0, winreg.KEY_SET_VALUE)
                    winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, 4)
                    winreg.CloseKey(key)
                    c.print("  [bold bright_green]USB storage blocked.[/bold bright_green]")
                except Exception as e:
                    c.print(f"  [bright_red]Error: {e}[/bright_red]")
        else:
            if Confirm.ask("  Unblock USB storage?", default=False):
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, USB_STORAGE_KEY, 0, winreg.KEY_SET_VALUE)
                    winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, 3)
                    winreg.CloseKey(key)
                    c.print("  [bold bright_green]USB storage unblocked.[/bold bright_green]")
                except Exception as e:
                    c.print(f"  [bright_red]Error: {e}[/bright_red]")

    def _safe_eject(self):
        c = self.console
        # List removable drives
        output = run_cmd(["wmic", "logicaldisk", "where", "DriveType=2", "get", "DeviceID,VolumeName,Size"])
        c.print()
        c.print(output)
        drive = Prompt.ask("  [bright_cyan]Drive letter to eject (e.g., E:)[/bright_cyan]")
        if drive.strip():
            run_cmd(["powershell", "-Command", f"$eject = New-Object -comObject Shell.Application; $eject.NameSpace(17).ParseName('{drive}').InvokeVerb('Eject')"])
            c.print(f"  [bright_green]Eject command sent for {drive}[/bright_green]")
