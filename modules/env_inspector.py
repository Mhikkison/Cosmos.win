"""
Environment Inspector — Deep inspection of environment variables, PATH entries,
detection of suspicious PATH hijacking, sensitive data leaks in env vars,
and comparison against known-safe configurations.
"""

import os
import subprocess
import winreg
import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box


SENSITIVE_ENV_PATTERNS = [
    "password", "secret", "token", "api_key", "apikey", "private_key",
    "access_key", "auth", "credential", "passwd", "pwd",
    "connection_string", "db_pass", "database_password",
]

SUSPICIOUS_PATH_PATTERNS = [
    "temp", "tmp", "appdata\\local\\temp", "downloads",
    "desktop", "users\\public", "%tmp%",
]

KNOWN_SAFE_PATH_DIRS = {
    "c:\\windows", "c:\\windows\\system32", "c:\\windows\\system32\\wbem",
    "c:\\windows\\system32\\windowspowershell\\v1.0",
    "c:\\program files", "c:\\program files (x86)",
}


class EnvInspector:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold bright_magenta]ENVIRONMENT INSPECTOR[/bold bright_magenta]\n"
                         "[dim]Environment variables, PATH audit, hijack detection & leak scan[/dim]"),
            border_style="bright_magenta", box=box.DOUBLE_EDGE,
        ))

        while True:
            c.print()
            table = Table(box=box.ROUNDED, border_style="bright_magenta", header_style="bold bright_cyan")
            table.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            table.add_column("ACTION", style="bold bright_magenta", width=55)
            table.add_row("1", "Full environment security audit")
            table.add_row("2", "PATH hijack detection")
            table.add_row("3", "Scan for sensitive data in env vars")
            table.add_row("4", "List all environment variables")
            table.add_row("5", "Compare user vs system PATH entries")
            table.add_row("6", "Check for DLL search order issues")
            table.add_row("0", "Return to main menu")
            c.print(Align.center(table))

            choice = Prompt.ask("  [bold bright_magenta]env[/bold bright_magenta][dim]>[/dim]", default="0")

            if choice == "1":
                self._full_audit()
            elif choice == "2":
                self._path_hijack()
            elif choice == "3":
                self._sensitive_scan()
            elif choice == "4":
                self._list_all()
            elif choice == "5":
                self._compare_paths()
            elif choice == "6":
                self._dll_search_order()
            elif choice == "0":
                break

    def _full_audit(self):
        c = self.console
        findings = []

        with Progress(
            SpinnerColumn(style="bright_magenta"),
            TextColumn("[bold bright_magenta]{task.description}[/bold bright_magenta]"),
            BarColumn(bar_width=40),
            console=c,
        ) as progress:
            t = progress.add_task("Auditing environment...", total=4)

            # Check PATH
            progress.update(t, description="Analyzing PATH entries")
            path_dirs = os.environ.get("PATH", "").split(";")
            for d in path_dirs:
                d_lower = d.lower().strip()
                if not d_lower:
                    continue
                if not os.path.isdir(d):
                    findings.append(("PATH", "WARN", f"Non-existent directory: {d[:60]}"))
                for pattern in SUSPICIOUS_PATH_PATTERNS:
                    if pattern in d_lower:
                        findings.append(("PATH", "RISK", f"Suspicious writable path: {d[:60]}"))
                        break
            progress.advance(t)

            # Check sensitive vars
            progress.update(t, description="Scanning for sensitive data")
            for key, val in os.environ.items():
                for pattern in SENSITIVE_ENV_PATTERNS:
                    if pattern in key.lower() and val.strip():
                        findings.append(("LEAK", "RISK",
                            f"{key}={val[:8]}{'*' * max(0, len(val)-8)} (sensitive data exposed)"))
                        break
            progress.advance(t)

            # Check writable paths before system paths
            progress.update(t, description="Checking PATH order")
            found_system = False
            for d in path_dirs:
                d_lower = d.lower().strip().rstrip("\\")
                if d_lower in KNOWN_SAFE_PATH_DIRS:
                    found_system = True
                elif found_system is False and os.path.isdir(d):
                    # User path before system path
                    is_writable = os.access(d, os.W_OK)
                    if is_writable and d_lower not in KNOWN_SAFE_PATH_DIRS:
                        findings.append(("HIJACK", "RISK",
                            f"Writable dir before system PATH: {d[:60]}"))
            progress.advance(t)

            # Check temp vars
            progress.update(t, description="Checking temp directories")
            for var in ["TEMP", "TMP"]:
                val = os.environ.get(var, "")
                if val and os.path.isdir(val):
                    files = [f for f in os.listdir(val) if f.endswith((".exe", ".dll", ".bat"))]
                    if files:
                        findings.append(("TEMP", "WARN",
                            f"{len(files)} executables in {var} ({val[:40]})"))
            progress.advance(t)

        # Display
        if not findings:
            c.print(Panel("[bold bright_green]No environment security issues found.[/bold bright_green]",
                          border_style="bright_green"))
            return

        table = Table(
            title=f"[bold bright_magenta]Environment Audit ({len(findings)} findings)[/bold bright_magenta]",
            box=box.DOUBLE_EDGE, border_style="bright_magenta", header_style="bold bright_cyan",
        )
        table.add_column("TYPE", style="bright_yellow", width=10)
        table.add_column("LEVEL", style="bold", width=8)
        table.add_column("DETAIL", style="bright_white", width=70)

        level_col = {"RISK": "bright_red", "WARN": "bright_yellow", "INFO": "dim"}
        for cat, level, detail in findings:
            col = level_col.get(level, "white")
            table.add_row(cat, f"[{col}]{level}[/{col}]", detail[:70])

        c.print()
        c.print(Align.center(table))

    def _path_hijack(self):
        c = self.console
        path_dirs = os.environ.get("PATH", "").split(";")

        table = Table(
            title="[bold bright_red]PATH Hijack Analysis[/bold bright_red]",
            box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
        )
        table.add_column("#", style="dim", width=4)
        table.add_column("DIRECTORY", style="bold bright_white", width=55)
        table.add_column("EXISTS", style="bold", width=8)
        table.add_column("WRITABLE", style="bold", width=10)
        table.add_column("RISK", style="bold", width=10)

        for i, d in enumerate(path_dirs, 1):
            d = d.strip()
            if not d:
                continue
            exists = os.path.isdir(d)
            writable = os.access(d, os.W_OK) if exists else False
            is_system = d.lower().rstrip("\\") in KNOWN_SAFE_PATH_DIRS

            if not exists:
                risk = "[bright_yellow]PHANTOM[/bright_yellow]"
            elif writable and not is_system:
                risk = "[bright_red]HIGH[/bright_red]"
            elif writable:
                risk = "[bright_yellow]MED[/bright_yellow]"
            else:
                risk = "[bright_green]LOW[/bright_green]"

            table.add_row(
                str(i), d[:55],
                "[bright_green]YES[/bright_green]" if exists else "[bright_red]NO[/bright_red]",
                "[bright_red]YES[/bright_red]" if writable else "[bright_green]NO[/bright_green]",
                risk,
            )

        c.print()
        c.print(Align.center(table))

    def _sensitive_scan(self):
        c = self.console
        found = []
        for key, val in sorted(os.environ.items()):
            for pattern in SENSITIVE_ENV_PATTERNS:
                if pattern in key.lower() and val.strip():
                    masked = val[:4] + "*" * max(0, len(val) - 4)
                    found.append((key, masked, pattern))
                    break

        if not found:
            c.print("\n  [bold bright_green]No sensitive data detected in environment variables.[/bold bright_green]")
            return

        table = Table(
            title=f"[bold bright_red]Sensitive Environment Variables ({len(found)})[/bold bright_red]",
            box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
        )
        table.add_column("VARIABLE", style="bold bright_red", width=30)
        table.add_column("VALUE (masked)", style="dim", width=40)
        table.add_column("PATTERN", style="bright_yellow", width=15)

        for key, val, pattern in found:
            table.add_row(key, val[:40], pattern)

        c.print()
        c.print(Align.center(table))

    def _list_all(self):
        c = self.console
        table = Table(
            title=f"[bold bright_magenta]All Environment Variables ({len(os.environ)})[/bold bright_magenta]",
            box=box.ROUNDED, border_style="bright_magenta", header_style="bold bright_cyan",
        )
        table.add_column("VARIABLE", style="bold bright_white", width=30)
        table.add_column("VALUE", style="dim", width=65)

        for key, val in sorted(os.environ.items()):
            table.add_row(key, val[:65])

        c.print()
        c.print(table)

    def _compare_paths(self):
        c = self.console
        # Get system PATH from registry
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                0, winreg.KEY_READ)
            sys_path, _ = winreg.QueryValueEx(key, "Path")
            winreg.CloseKey(key)
        except Exception:
            sys_path = ""

        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_READ)
            user_path, _ = winreg.QueryValueEx(key, "Path")
            winreg.CloseKey(key)
        except Exception:
            user_path = ""

        sys_dirs = [d.strip() for d in sys_path.split(";") if d.strip()]
        user_dirs = [d.strip() for d in user_path.split(";") if d.strip()]

        c.print(Panel(
            f"[bright_cyan]System PATH entries:[/bright_cyan] {len(sys_dirs)}\n"
            f"[bright_cyan]User PATH entries:[/bright_cyan] {len(user_dirs)}",
            title="[bold bright_magenta]PATH Comparison[/bold bright_magenta]",
            border_style="bright_magenta",
        ))

        c.print("\n  [bold bright_cyan]System PATH:[/bold bright_cyan]")
        for d in sys_dirs:
            exists = os.path.isdir(d)
            col = "bright_green" if exists else "bright_red"
            c.print(f"    [{col}]{d}[/{col}]")

        c.print("\n  [bold bright_yellow]User PATH:[/bold bright_yellow]")
        for d in user_dirs:
            exists = os.path.isdir(d)
            col = "bright_green" if exists else "bright_red"
            in_system = d.lower() in [s.lower() for s in sys_dirs]
            dupe = " [dim](also in system)[/dim]" if in_system else ""
            c.print(f"    [{col}]{d}[/{col}]{dupe}")

    def _dll_search_order(self):
        c = self.console
        c.print("\n  [bold bright_cyan]Checking DLL Search Order safety...[/bold bright_cyan]")

        # Check SafeDllSearchMode
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Session Manager",
                0, winreg.KEY_READ)
            val, _ = winreg.QueryValueEx(key, "SafeDllSearchMode")
            winreg.CloseKey(key)
            safe_mode = val == 1
        except Exception:
            safe_mode = True  # Default is enabled

        # Check CWDIllegalInDllSearch
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Session Manager",
                0, winreg.KEY_READ)
            val, _ = winreg.QueryValueEx(key, "CWDIllegalInDllSearch")
            winreg.CloseKey(key)
            cwd_blocked = val > 0
        except Exception:
            cwd_blocked = False

        c.print(Panel(
            f"[bright_cyan]SafeDllSearchMode:[/bright_cyan] [bold {'bright_green]Enabled' if safe_mode else 'bright_red]Disabled'}[/bold]\n"
            f"[bright_cyan]CWD in DLL Search:[/bright_cyan] [bold {'bright_green]Blocked' if cwd_blocked else 'bright_yellow]Allowed (default)'}[/bold]\n\n"
            f"[dim]SafeDllSearchMode moves CWD to later in search order.\n"
            f"CWDIllegalInDllSearch blocks CWD entirely from DLL search.[/dim]",
            title="[bold bright_magenta]DLL Search Order[/bold bright_magenta]",
            border_style="bright_magenta",
        ))
