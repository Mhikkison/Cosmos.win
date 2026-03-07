"""
Permissions Auditor — Audit file/folder NTFS permissions, find world-writable
directories, check sensitive file ACLs, and detect permission misconfigurations.
"""

import os
import subprocess
import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box


SENSITIVE_PATHS = [
    r"C:\Windows\System32\config\SAM",
    r"C:\Windows\System32\config\SYSTEM",
    r"C:\Windows\System32\config\SOFTWARE",
    r"C:\Windows\System32\config\SECURITY",
    r"C:\Windows\System32\drivers\etc\hosts",
    r"C:\Windows\System32\cmd.exe",
    r"C:\Windows\System32\powershell.exe",
    r"C:\Windows\System32\svchost.exe",
    r"C:\Windows\repair",
    r"C:\inetpub",
]

WRITABLE_CHECK_DIRS = [
    r"C:\Windows",
    r"C:\Windows\System32",
    r"C:\Windows\Temp",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
]

RISKY_PERMISSIONS = {"Everyone", "BUILTIN\\Users", "Authenticated Users"}


def run_cmd(args, timeout=15):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception as e:
        return str(e)


def get_acl(path: str) -> str:
    return run_cmd(["icacls", path])


class PermissionsAuditor:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold bright_cyan]PERMISSIONS AUDITOR[/bold bright_cyan]\n"
                         "[dim]NTFS permission audit, world-writable detection & ACL analysis[/dim]"),
            border_style="bright_cyan", box=box.DOUBLE_EDGE,
        ))

        while True:
            c.print()
            table = Table(box=box.ROUNDED, border_style="bright_cyan", header_style="bold bright_cyan")
            table.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            table.add_column("ACTION", style="bold bright_cyan", width=50)
            table.add_row("1", "Audit sensitive file permissions")
            table.add_row("2", "Find world-writable directories")
            table.add_row("3", "Check PATH directory permissions")
            table.add_row("4", "Audit custom path permissions")
            table.add_row("5", "Check service binary permissions")
            table.add_row("6", "Find files with Everyone:Full access")
            table.add_row("0", "Return to main menu")
            c.print(Align.center(table))

            choice = Prompt.ask("  [bold bright_cyan]perm[/bold bright_cyan][dim]>[/dim]", default="0")

            if choice == "1":
                self._audit_sensitive()
            elif choice == "2":
                self._find_world_writable()
            elif choice == "3":
                self._check_path_perms()
            elif choice == "4":
                self._audit_custom()
            elif choice == "5":
                self._check_service_perms()
            elif choice == "6":
                self._find_everyone_full()
            elif choice == "0":
                break

    def _audit_sensitive(self):
        c = self.console
        table = Table(
            title="[bold bright_cyan]Sensitive File Permissions[/bold bright_cyan]",
            box=box.DOUBLE_EDGE, border_style="bright_cyan", header_style="bold bright_cyan",
        )
        table.add_column("FILE", style="bold bright_white", width=40)
        table.add_column("EXISTS", style="bold", width=8)
        table.add_column("ACL SUMMARY", style="dim", width=40)
        table.add_column("RISK", style="bold", width=12)

        with Progress(
            SpinnerColumn(style="bright_cyan"),
            TextColumn("[bold bright_cyan]Auditing permissions...[/bold bright_cyan]"),
            BarColumn(bar_width=30),
            console=c,
        ) as progress:
            t = progress.add_task("Scanning...", total=len(SENSITIVE_PATHS))
            for path in SENSITIVE_PATHS:
                exists = os.path.exists(path)
                if not exists:
                    table.add_row(path, "[dim]NO[/dim]", "-", "[dim]N/A[/dim]")
                    progress.advance(t)
                    continue

                acl = get_acl(path)
                has_risky = any(rp in acl for rp in RISKY_PERMISSIONS)
                has_full = "(F)" in acl and any(rp in acl for rp in RISKY_PERMISSIONS)

                if has_full:
                    risk = "[bright_red]HIGH[/bright_red]"
                elif has_risky:
                    risk = "[bright_yellow]MEDIUM[/bright_yellow]"
                else:
                    risk = "[bright_green]LOW[/bright_green]"

                # Extract first meaningful ACL line
                acl_summary = ""
                for line in acl.splitlines():
                    line = line.strip()
                    if line and ":" in line and "Successfully" not in line and path not in line:
                        acl_summary = line[:40]
                        break

                table.add_row(path, "[bright_green]YES[/bright_green]", acl_summary, risk)
                progress.advance(t)

        c.print()
        c.print(Align.center(table))

    def _find_world_writable(self):
        c = self.console
        writable = []

        with Progress(
            SpinnerColumn(style="bright_cyan"),
            TextColumn("[bold bright_cyan]Checking directories...[/bold bright_cyan]"),
            BarColumn(bar_width=30),
            console=c,
        ) as progress:
            t = progress.add_task("Scanning...", total=len(WRITABLE_CHECK_DIRS))
            for d in WRITABLE_CHECK_DIRS:
                if not os.path.isdir(d):
                    progress.advance(t)
                    continue
                acl = get_acl(d)
                if "Everyone" in acl and any(p in acl for p in ["(F)", "(W)", "(M)"]):
                    writable.append((d, acl.split("\n")[1].strip() if len(acl.split("\n")) > 1 else ""))
                progress.advance(t)

        if not writable:
            c.print("  [bold bright_green]No world-writable system directories found.[/bold bright_green]")
            return

        table = Table(
            title=f"[bold bright_red]World-Writable Directories ({len(writable)})[/bold bright_red]",
            box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
        )
        table.add_column("DIRECTORY", style="bold bright_red", width=40)
        table.add_column("ACL", style="dim", width=50)

        for d, acl in writable:
            table.add_row(d, acl[:50])

        c.print()
        c.print(Align.center(table))

    def _check_path_perms(self):
        c = self.console
        path_dirs = os.environ.get("PATH", "").split(";")

        table = Table(
            title="[bold bright_cyan]PATH Directory Permissions[/bold bright_cyan]",
            box=box.DOUBLE_EDGE, border_style="bright_cyan", header_style="bold bright_cyan",
        )
        table.add_column("DIRECTORY", style="bold bright_white", width=50)
        table.add_column("WRITABLE", style="bold", width=12)
        table.add_column("RISK", style="bold", width=10)

        for d in path_dirs:
            d = d.strip()
            if not d or not os.path.isdir(d):
                continue

            # Test write access
            writable = False
            try:
                test_file = os.path.join(d, ".cosmos_perm_test")
                with open(test_file, "w") as f:
                    f.write("test")
                os.remove(test_file)
                writable = True
            except (PermissionError, OSError):
                pass

            w_col = "bright_red" if writable else "bright_green"
            risk = "[bright_red]HIGH[/bright_red]" if writable else "[bright_green]LOW[/bright_green]"
            table.add_row(d[:50], f"[{w_col}]{'YES' if writable else 'NO'}[/{w_col}]", risk)

        c.print()
        c.print(Align.center(table))

    def _audit_custom(self):
        c = self.console
        path = Prompt.ask("  [bright_cyan]Path to audit[/bright_cyan]")
        if not os.path.exists(path):
            c.print("  [bright_red]Path not found.[/bright_red]")
            return

        acl = get_acl(path)
        c.print(Panel(
            f"[dim]{acl}[/dim]",
            title=f"[bold bright_cyan]ACL: {path}[/bold bright_cyan]",
            border_style="bright_cyan",
        ))

    def _check_service_perms(self):
        c = self.console
        c.print("\n  [bold bright_cyan]Checking service binary permissions...[/bold bright_cyan]")

        output = run_cmd(["wmic", "service", "get", "name,pathname"])
        findings = []

        for line in output.splitlines():
            line = line.strip()
            if not line or "PathName" in line:
                continue
            # Extract path
            parts = line.split(None, 1)
            if len(parts) < 2:
                continue
            svc_name = parts[0]
            path = parts[1].strip().strip('"')

            if not os.path.isfile(path):
                continue

            # Check if non-admin can write to the binary
            acl = get_acl(path)
            if any(rp in acl for rp in RISKY_PERMISSIONS) and any(p in acl for p in ["(F)", "(W)", "(M)"]):
                findings.append((svc_name, path))

        if not findings:
            c.print("  [bold bright_green]No service binaries with risky permissions found.[/bold bright_green]")
            return

        table = Table(
            title=f"[bold bright_red]Vulnerable Service Binaries ({len(findings)})[/bold bright_red]",
            box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
        )
        table.add_column("SERVICE", style="bold bright_red", width=25)
        table.add_column("PATH", style="dim", width=60)

        for name, path in findings[:20]:
            table.add_row(name, path[:60])

        c.print()
        c.print(Align.center(table))

    def _find_everyone_full(self):
        c = self.console
        target = Prompt.ask("  [bright_cyan]Directory to scan[/bright_cyan]", default=r"C:\Windows\Temp")
        if not os.path.isdir(target):
            c.print("  [bright_red]Invalid directory.[/bright_red]")
            return

        found = []
        try:
            for fname in os.listdir(target)[:200]:
                fpath = os.path.join(target, fname)
                acl = get_acl(fpath)
                if "Everyone" in acl and "(F)" in acl:
                    found.append(fpath)
        except PermissionError:
            c.print("  [bright_red]Permission denied.[/bright_red]")
            return

        if not found:
            c.print("  [bold bright_green]No files with Everyone:Full found.[/bold bright_green]")
            return

        table = Table(
            title=f"[bold bright_red]Everyone:Full Access ({len(found)})[/bold bright_red]",
            box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
        )
        table.add_column("#", style="dim", width=5)
        table.add_column("FILE", style="bright_red", width=75)

        for i, f in enumerate(found[:30], 1):
            table.add_row(str(i), f[:75])

        c.print()
        c.print(Align.center(table))
