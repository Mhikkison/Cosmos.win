"""
Startup Optimizer — Analyze and manage Windows startup programs, scheduled tasks,
services that auto-start, and browser extensions to optimize boot time and security.
"""

import os
import subprocess
import winreg
import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box


KNOWN_SAFE_STARTUP = {
    "securityhealthsystray": "Windows Security",
    "windows defender notification": "Windows Defender",
    "onedrive": "Microsoft OneDrive",
    "realtek": "Realtek Audio",
    "igfxtray": "Intel Graphics",
    "hkcmd": "Intel Hotkey",
    "teams": "Microsoft Teams",
}

KNOWN_SUSPICIOUS_STARTUP = {
    "wscript": "Windows Script Host (malware vector)",
    "cscript": "Console Script Host (malware vector)",
    "powershell -e": "Encoded PowerShell (malware vector)",
    "cmd /c": "Command chain (suspicious)",
    "regsvr32 /s": "Silent DLL registration (living-off-the-land)",
    "mshta": "HTML Application Host (malware vector)",
    "rundll32": "DLL execution (check path carefully)",
}

STARTUP_REG_KEYS = [
    (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "User Run"),
    (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "User RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Machine Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "Machine RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "Machine Run (x86)"),
]

STARTUP_FOLDERS = [
    os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"),
    r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
]


def run_cmd(args, timeout=15):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception as e:
        return str(e)


class StartupOptimizer:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold bright_magenta]STARTUP OPTIMIZER[/bold bright_magenta]\n"
                         "[dim]Manage startup programs, services & scheduled tasks for speed + security[/dim]"),
            border_style="bright_magenta", box=box.DOUBLE_EDGE,
        ))

        while True:
            c.print()
            table = Table(box=box.ROUNDED, border_style="bright_magenta", header_style="bold bright_cyan")
            table.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            table.add_column("ACTION", style="bold bright_magenta", width=55)
            table.add_row("1", "Full startup security audit")
            table.add_row("2", "List all registry startup entries")
            table.add_row("3", "List startup folder contents")
            table.add_row("4", "Audit auto-start services")
            table.add_row("5", "Disable a startup entry")
            table.add_row("6", "View boot time estimate")
            table.add_row("0", "Return to main menu")
            c.print(Align.center(table))

            choice = Prompt.ask("  [bold bright_magenta]start[/bold bright_magenta][dim]>[/dim]", default="0")

            if choice == "1":
                self._full_audit()
            elif choice == "2":
                self._list_registry()
            elif choice == "3":
                self._list_folders()
            elif choice == "4":
                self._audit_services()
            elif choice == "5":
                self._disable_entry()
            elif choice == "6":
                self._boot_time()
            elif choice == "0":
                break

    def _full_audit(self):
        c = self.console
        entries = []

        with Progress(
            SpinnerColumn(style="bright_magenta"),
            TextColumn("[bold bright_magenta]{task.description}[/bold bright_magenta]"),
            BarColumn(bar_width=40),
            console=c,
        ) as progress:
            t = progress.add_task("Auditing startup...", total=3)

            # Registry entries
            progress.update(t, description="Scanning registry keys")
            for hive, path, location in STARTUP_REG_KEYS:
                try:
                    key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                    i = 0
                    while True:
                        try:
                            name, val, _ = winreg.EnumValue(key, i)
                            risk = self._assess_risk(name, val)
                            entries.append({
                                "name": name, "value": val[:80], "location": location,
                                "type": "REGISTRY", "risk": risk,
                            })
                            i += 1
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except Exception:
                    continue
            progress.advance(t)

            # Startup folders
            progress.update(t, description="Scanning startup folders")
            for folder in STARTUP_FOLDERS:
                if os.path.isdir(folder):
                    for f in os.listdir(folder):
                        fp = os.path.join(folder, f)
                        if f.lower().endswith(".ini") or f.lower() == "desktop.ini":
                            continue
                        risk = "LOW"
                        if f.endswith((".bat", ".cmd", ".vbs", ".ps1")):
                            risk = "HIGH"
                        entries.append({
                            "name": f, "value": fp[:80],
                            "location": "Startup Folder", "type": "FILE", "risk": risk,
                        })
            progress.advance(t)

            # Auto-start services
            progress.update(t, description="Checking auto-start services")
            svc_output = run_cmd(["sc", "query", "type=", "service", "state=", "all"])
            auto_services = run_cmd(["wmic", "service", "where", "StartMode='Auto'",
                                     "get", "Name,DisplayName,PathName", "/format:csv"])
            progress.advance(t)

        # Display
        table = Table(
            title=f"[bold bright_magenta]Startup Audit ({len(entries)} entries)[/bold bright_magenta]",
            box=box.DOUBLE_EDGE, border_style="bright_magenta", header_style="bold bright_cyan",
        )
        table.add_column("NAME", style="bold bright_white", width=25)
        table.add_column("TYPE", style="bright_cyan", width=10)
        table.add_column("LOCATION", style="dim", width=18)
        table.add_column("COMMAND/PATH", style="dim", width=45)
        table.add_column("RISK", style="bold", width=8)

        risk_col = {"HIGH": "bright_red", "MED": "bright_yellow", "LOW": "bright_green", "SAFE": "dim"}
        for e in entries:
            col = risk_col.get(e["risk"], "white")
            table.add_row(
                e["name"][:25], e["type"], e["location"],
                e["value"][:45], f"[{col}]{e['risk']}[/{col}]",
            )

        c.print()
        c.print(Align.center(table))

        high = sum(1 for e in entries if e["risk"] == "HIGH")
        if high:
            c.print(f"\n  [bold bright_red]{high} high-risk startup entries found![/bold bright_red]")

    def _assess_risk(self, name: str, value: str) -> str:
        name_lower = name.lower()
        val_lower = value.lower()

        for pattern, _ in KNOWN_SUSPICIOUS_STARTUP.items():
            if pattern in val_lower:
                return "HIGH"

        if any(d in val_lower for d in ["temp", "%tmp%", "appdata\\roaming"]):
            return "HIGH"

        for safe_key in KNOWN_SAFE_STARTUP:
            if safe_key in name_lower or safe_key in val_lower:
                return "SAFE"

        if not os.path.isfile(value.strip('"').split()[0] if value else ""):
            return "MED"

        return "LOW"

    def _list_registry(self):
        c = self.console
        table = Table(
            title="[bold bright_magenta]Registry Startup Entries[/bold bright_magenta]",
            box=box.DOUBLE_EDGE, border_style="bright_magenta", header_style="bold bright_cyan",
        )
        table.add_column("KEY", style="bright_yellow", width=20)
        table.add_column("NAME", style="bold bright_white", width=25)
        table.add_column("VALUE", style="dim", width=55)

        for hive, path, location in STARTUP_REG_KEYS:
            try:
                key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        name, val, _ = winreg.EnumValue(key, i)
                        table.add_row(location, name[:25], str(val)[:55])
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except Exception:
                continue

        c.print()
        c.print(Align.center(table))

    def _list_folders(self):
        c = self.console
        for folder in STARTUP_FOLDERS:
            c.print(f"\n  [bold bright_cyan]{folder}[/bold bright_cyan]")
            if not os.path.isdir(folder):
                c.print("    [dim]Not found[/dim]")
                continue
            files = os.listdir(folder)
            if not files:
                c.print("    [dim]Empty[/dim]")
            for f in files:
                fp = os.path.join(folder, f)
                size = os.path.getsize(fp) if os.path.isfile(fp) else 0
                c.print(f"    [bright_white]{f}[/bright_white] [dim]({size:,} bytes)[/dim]")

    def _audit_services(self):
        c = self.console
        output = run_cmd(["wmic", "service", "where", "StartMode='Auto'",
                          "get", "Name,DisplayName,State,PathName", "/format:csv"])

        table = Table(
            title="[bold bright_magenta]Auto-Start Services[/bold bright_magenta]",
            box=box.DOUBLE_EDGE, border_style="bright_magenta", header_style="bold bright_cyan",
        )
        table.add_column("SERVICE", style="bold bright_white", width=25)
        table.add_column("DISPLAY NAME", style="dim", width=30)
        table.add_column("STATE", style="bold", width=10)
        table.add_column("PATH", style="dim", width=40)

        for line in output.splitlines():
            parts = line.strip().split(",")
            if len(parts) >= 5 and parts[1]:
                display = parts[1][:30]
                name = parts[2][:25]
                path = parts[3][:40]
                state = parts[4] if len(parts) > 4 else "?"
                state_col = "bright_green" if state == "Running" else "bright_yellow"
                table.add_row(name, display, f"[{state_col}]{state}[/{state_col}]", path)

        c.print()
        c.print(Align.center(table))

    def _disable_entry(self):
        c = self.console
        c.print("\n  [bold bright_yellow]Available registry startup entries:[/bold bright_yellow]")

        all_entries = []
        for hive, path, location in STARTUP_REG_KEYS:
            try:
                key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        name, val, _ = winreg.EnumValue(key, i)
                        all_entries.append((hive, path, name, val, location))
                        c.print(f"    [bright_yellow]{len(all_entries)}[/bright_yellow]) {name} [dim]({location})[/dim]")
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except Exception:
                continue

        if not all_entries:
            c.print("    [dim]No entries found.[/dim]")
            return

        pick = Prompt.ask("  [bright_red]Entry # to disable[/bright_red]", default="")
        try:
            idx = int(pick) - 1
            hive, path, name, val, location = all_entries[idx]
            if Confirm.ask(f"  Disable '{name}' from {location}?", default=False):
                try:
                    key = winreg.OpenKey(hive, path, 0, winreg.KEY_SET_VALUE)
                    winreg.DeleteValue(key, name)
                    winreg.CloseKey(key)
                    c.print(f"  [bold bright_green]Disabled '{name}'[/bold bright_green]")
                except Exception as e:
                    c.print(f"  [bright_red]Error: {e}[/bright_red]")
        except (ValueError, IndexError):
            c.print("  [bright_red]Invalid selection.[/bright_red]")

    def _boot_time(self):
        c = self.console
        output = run_cmd(["powershell", "-Command",
            "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime"])

        import psutil
        boot_time = psutil.boot_time()
        from datetime import datetime
        boot_dt = datetime.fromtimestamp(boot_time)
        uptime = datetime.now() - boot_dt

        c.print(Panel(
            f"[bright_cyan]Last Boot:[/bright_cyan] {boot_dt.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"[bright_cyan]Uptime:[/bright_cyan] {uptime.days}d {uptime.seconds//3600}h {(uptime.seconds%3600)//60}m\n"
            f"[bright_cyan]Boot Time (PS):[/bright_cyan] {output.strip()[:40]}",
            title="[bold bright_magenta]Boot Time[/bold bright_magenta]",
            border_style="bright_magenta",
        ))
