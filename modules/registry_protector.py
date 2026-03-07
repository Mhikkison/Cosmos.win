"""
Registry Protector — Monitor and protect critical Windows registry keys.
Detects unauthorized changes, backs up and restores registry hives,
and scans for persistence mechanisms.
"""

import winreg
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

CRITICAL_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Winlogon"),
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services", "Services"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "UAC Policies"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows Defender", "Defender Config"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "Windows Update Policy"),
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL", "TLS/SSL Config"),
]

PERSISTENCE_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Active Setup\Installed Components"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad"),
]

SNAPSHOT_FILE = os.path.join(os.environ.get("TEMP", "."), "cosmos_registry_snapshot.json")

SUSPICIOUS_PATTERNS = [
    "powershell", "cmd.exe /c", "wscript", "cscript", "regsvr32",
    "mshta", "rundll32", "certutil", "bitsadmin", "msiexec /q",
    "%temp%", "%appdata%", "download", "pastebin", "bit.ly",
]


def read_key_values(hive, path) -> dict:
    values = {}
    try:
        key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
        i = 0
        while True:
            try:
                name, val, _ = winreg.EnumValue(key, i)
                values[name] = str(val)
                i += 1
            except OSError:
                break
        winreg.CloseKey(key)
    except Exception:
        pass
    return values


def hash_dict(d: dict) -> str:
    s = json.dumps(d, sort_keys=True)
    return hashlib.sha256(s.encode()).hexdigest()


class RegistryProtector:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold bright_magenta]REGISTRY PROTECTOR[/bold bright_magenta]\n"
                         "[dim]Monitor, snapshot, compare & protect critical registry keys[/dim]"),
            border_style="bright_magenta", box=box.DOUBLE_EDGE,
        ))

        while True:
            c.print()
            table = Table(box=box.ROUNDED, border_style="bright_magenta", header_style="bold bright_cyan")
            table.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            table.add_column("ACTION", style="bold bright_magenta", width=50)
            table.add_row("1", "Scan critical registry keys")
            table.add_row("2", "Scan for persistence mechanisms")
            table.add_row("3", "Take registry snapshot (baseline)")
            table.add_row("4", "Compare current state vs snapshot")
            table.add_row("5", "Export registry key to file")
            table.add_row("6", "View startup entries (all sources)")
            table.add_row("0", "Return to main menu")
            c.print(Align.center(table))

            choice = Prompt.ask("  [bold bright_magenta]reg[/bold bright_magenta][dim]>[/dim]", default="0")

            if choice == "1":
                self._scan_critical()
            elif choice == "2":
                self._scan_persistence()
            elif choice == "3":
                self._take_snapshot()
            elif choice == "4":
                self._compare_snapshot()
            elif choice == "5":
                self._export_key()
            elif choice == "6":
                self._view_startups()
            elif choice == "0":
                break

    def _scan_critical(self):
        c = self.console
        table = Table(
            title="[bold bright_magenta]Critical Registry Keys[/bold bright_magenta]",
            box=box.DOUBLE_EDGE, border_style="bright_magenta", header_style="bold bright_cyan",
        )
        table.add_column("KEY", style="bold bright_white", width=25)
        table.add_column("ENTRIES", style="bright_cyan", width=10, justify="center")
        table.add_column("HASH", style="dim", width=18)
        table.add_column("STATUS", style="bold", width=12)

        with Progress(
            SpinnerColumn(style="bright_magenta"),
            TextColumn("[bold bright_magenta]{task.description}[/bold bright_magenta]"),
            BarColumn(bar_width=30),
            console=c,
        ) as progress:
            t = progress.add_task("Scanning...", total=len(CRITICAL_KEYS))

            for hive, path, label in CRITICAL_KEYS:
                values = read_key_values(hive, path)
                h = hash_dict(values)[:16]
                # Check for suspicious values
                suspicious = False
                for name, val in values.items():
                    for pattern in SUSPICIOUS_PATTERNS:
                        if pattern.lower() in val.lower():
                            suspicious = True
                            break

                status = "[bright_red]SUSPICIOUS[/bright_red]" if suspicious else "[bright_green]CLEAN[/bright_green]"
                table.add_row(label, str(len(values)), h, status)
                progress.advance(t)

        c.print()
        c.print(Align.center(table))

    def _scan_persistence(self):
        c = self.console
        findings = []

        with Progress(
            SpinnerColumn(style="bright_magenta"),
            TextColumn("[bold bright_magenta]Scanning persistence keys...[/bold bright_magenta]"),
            BarColumn(bar_width=30),
            console=c,
        ) as progress:
            t = progress.add_task("Scanning...", total=len(PERSISTENCE_KEYS))

            for hive, path in PERSISTENCE_KEYS:
                values = read_key_values(hive, path)
                hive_name = "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"
                for name, val in values.items():
                    is_suspicious = any(p.lower() in val.lower() for p in SUSPICIOUS_PATTERNS)
                    findings.append({
                        "key": f"{hive_name}\\{path}",
                        "name": name,
                        "value": val[:60],
                        "suspicious": is_suspicious,
                    })
                progress.advance(t)

        if not findings:
            c.print("  [bright_green]No persistence entries found.[/bright_green]")
            return

        table = Table(
            title=f"[bold bright_magenta]Persistence Entries ({len(findings)})[/bold bright_magenta]",
            box=box.DOUBLE_EDGE, border_style="bright_magenta", header_style="bold bright_cyan",
        )
        table.add_column("NAME", style="bold bright_white", width=25)
        table.add_column("VALUE", style="dim", width=55)
        table.add_column("THREAT", style="bold", width=14)

        for f in findings[:50]:
            threat = "[bright_red]SUSPICIOUS[/bright_red]" if f["suspicious"] else "[bright_green]NORMAL[/bright_green]"
            table.add_row(f["name"][:25], f["value"], threat)

        c.print()
        c.print(Align.center(table))

        sus_count = sum(1 for f in findings if f["suspicious"])
        if sus_count:
            c.print(f"\n  [bold bright_red]Found {sus_count} suspicious persistence entries![/bold bright_red]")

    def _take_snapshot(self):
        c = self.console
        snapshot = {}
        for hive, path, label in CRITICAL_KEYS:
            values = read_key_values(hive, path)
            snapshot[label] = values

        try:
            with open(SNAPSHOT_FILE, "w") as f:
                json.dump({"timestamp": datetime.now().isoformat(), "data": snapshot}, f, indent=2)
            c.print(f"\n  [bold bright_green]Snapshot saved to {SNAPSHOT_FILE}[/bold bright_green]")
        except Exception as e:
            c.print(f"  [bright_red]Error: {e}[/bright_red]")

    def _compare_snapshot(self):
        c = self.console
        if not os.path.isfile(SNAPSHOT_FILE):
            c.print("  [bright_yellow]No snapshot found. Take a snapshot first (option 3).[/bright_yellow]")
            return

        try:
            with open(SNAPSHOT_FILE, "r") as f:
                snap = json.load(f)
        except Exception as e:
            c.print(f"  [bright_red]Error reading snapshot: {e}[/bright_red]")
            return

        c.print(f"\n  [dim]Comparing against snapshot from {snap.get('timestamp', '?')}[/dim]")

        changes = []
        for hive, path, label in CRITICAL_KEYS:
            current = read_key_values(hive, path)
            old = snap.get("data", {}).get(label, {})

            for name in set(list(current.keys()) + list(old.keys())):
                if name not in old:
                    changes.append({"key": label, "name": name, "change": "ADDED", "value": current[name][:40]})
                elif name not in current:
                    changes.append({"key": label, "name": name, "change": "REMOVED", "value": old[name][:40]})
                elif current[name] != old[name]:
                    changes.append({"key": label, "name": name, "change": "MODIFIED", "value": current[name][:40]})

        if not changes:
            c.print("  [bold bright_green]No changes detected since last snapshot.[/bold bright_green]")
            return

        table = Table(
            title=f"[bold bright_red]Registry Changes Detected ({len(changes)})[/bold bright_red]",
            box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
        )
        table.add_column("KEY", style="bright_white", width=20)
        table.add_column("NAME", style="bold bright_white", width=25)
        table.add_column("CHANGE", style="bold", width=12)
        table.add_column("VALUE", style="dim", width=40)

        change_col = {"ADDED": "bright_yellow", "REMOVED": "bright_red", "MODIFIED": "bright_magenta"}
        for ch in changes:
            col = change_col.get(ch["change"], "white")
            table.add_row(ch["key"], ch["name"], f"[{col}]{ch['change']}[/{col}]", ch["value"])

        c.print()
        c.print(Align.center(table))

    def _export_key(self):
        c = self.console
        c.print("\n  Available keys:")
        for i, (_, _, label) in enumerate(CRITICAL_KEYS, 1):
            c.print(f"  [bright_yellow]{i}[/bright_yellow]) {label}")

        idx = Prompt.ask("  Select key to export", default="1")
        try:
            hive, path, label = CRITICAL_KEYS[int(idx) - 1]
        except (ValueError, IndexError):
            c.print("  [bright_red]Invalid selection.[/bright_red]")
            return

        values = read_key_values(hive, path)
        export_path = os.path.join(os.path.expanduser("~"), "Desktop",
                                   f"cosmos_reg_{label.replace(' ', '_')}.txt")
        try:
            with open(export_path, "w") as f:
                f.write(f"=== COSMOS.WIN Registry Export: {label} ===\n")
                f.write(f"Timestamp: {datetime.now().isoformat()}\n\n")
                for name, val in values.items():
                    f.write(f"{name} = {val}\n")
            c.print(f"  [bright_green]Exported to {export_path}[/bright_green]")
        except Exception as e:
            c.print(f"  [bright_red]Error: {e}[/bright_red]")

    def _view_startups(self):
        c = self.console
        all_entries = []

        startup_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\RunOnce"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run (32-bit)"),
        ]

        for hive, path, label in startup_keys:
            values = read_key_values(hive, path)
            for name, val in values.items():
                all_entries.append({"source": label, "name": name, "command": val})

        # Also check Startup folder
        startup_folders = [
            os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"),
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        ]
        for folder in startup_folders:
            if os.path.isdir(folder):
                for fname in os.listdir(folder):
                    all_entries.append({"source": "Startup Folder", "name": fname, "command": os.path.join(folder, fname)})

        table = Table(
            title=f"[bold bright_magenta]All Startup Entries ({len(all_entries)})[/bold bright_magenta]",
            box=box.DOUBLE_EDGE, border_style="bright_magenta", header_style="bold bright_cyan",
        )
        table.add_column("SOURCE", style="bright_yellow", width=22)
        table.add_column("NAME", style="bold bright_white", width=25)
        table.add_column("COMMAND", style="dim", width=55)

        for entry in all_entries:
            table.add_row(entry["source"], entry["name"][:25], entry["command"][:55])

        c.print()
        c.print(Align.center(table))
