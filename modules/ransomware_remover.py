"""
Ransomware Remover — detects ransomware behavior & processes,
attempts to kill them, and provides shadow copy restoration advice.
"""

import os
import psutil
import subprocess
import time
import winreg
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich import box

# Known ransomware process names (public threat intelligence)
RANSOMWARE_PROCESSES = {
    "wannacry.exe", "wncry.exe", "wcry.exe", "mssecsvc.exe", "tasksche.exe",
    "locky.exe", "cryptolocker.exe", "teslacrypt.exe", "cerber.exe",
    "darkside.exe", "revil.exe", "ryuk.exe", "conti.exe", "lockbit.exe",
    "avoslocker.exe", "blackcat.exe", "alphv.exe", "hive.exe",
    "petya.exe", "notpetya.exe", "badrabbit.exe", "gandcrab.exe",
    "maze.exe", "ragnar.exe", "sodinokibi.exe", "dharma.exe", "phobos.exe",
    "stop.exe", "djvu.exe", "makop.exe", "medusa.exe",
}

# Ransomware extensions (files with these extensions = encrypted)
RANSOM_EXTENSIONS = {
    ".wcry", ".wncry", ".wnry", ".locky", ".crypt", ".enc",
    ".cerber", ".zepto", ".odin", ".sage", ".zzz", ".micro",
    ".aaa", ".abc", ".xyz", ".ttt", ".bbb", ".vvv",
    ".locked", ".crypto", ".encrypted", ".crinf", ".r5a",
    ".xrtn", ".zzzs", ".lol!", ".killedXXX", ".darkness",
}

# Known ransom note filenames
RANSOM_NOTES = {
    "readme.txt", "how_to_decrypt.txt", "decrypt_instructions.txt",
    "!decrypt.txt", "@please_read_me@.txt", "!!!_read_me_!!!.txt",
    "restore_files.txt", "how_to_restore_files.txt", "_readme.txt",
    "@restore@.txt", "read_me.html", "ransom.html",
}

SCAN_DIRS = [
    os.path.expanduser("~/Desktop"),
    os.path.expanduser("~/Documents"),
    os.path.expanduser("~/Downloads"),
    "C:\\Windows\\Temp",
    os.environ.get("TEMP", ""),
]


class RansomwareRemover:
    def __init__(self, console: Console):
        self.console = console
        self.findings: list[dict] = []

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold bright_red]☣️  RANSOMWARE REMOVER[/bold bright_red]\n"
                         "[dim]Behavioral detection, process termination, and recovery guidance[/dim]"),
            border_style="bright_red", box=box.DOUBLE_EDGE,
        ))
        c.print()

        with Progress(
            SpinnerColumn(style="bright_red"),
            TextColumn("[bold bright_red]{task.description}[/bold bright_red]"),
            BarColumn(bar_width=40, style="bright_yellow", complete_style="bright_red"),
            TextColumn("[bright_white]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=c,
        ) as progress:
            t = progress.add_task("Analyzing...", total=4)

            progress.update(t, description="[1/4] Scanning active processes")
            self._scan_processes()
            progress.advance(t)
            time.sleep(0.4)

            progress.update(t, description="[2/4] Detecting encrypted files")
            self._scan_encrypted_files()
            progress.advance(t)
            time.sleep(0.4)

            progress.update(t, description="[3/4] Locating ransom notes")
            self._scan_ransom_notes()
            progress.advance(t)
            time.sleep(0.3)

            progress.update(t, description="[4/4] Checking Volume Shadow Copies")
            vss_alive = self._check_shadow_copies()
            progress.advance(t)
            time.sleep(0.2)

        self._show_results(vss_alive)
        self._prompt_action()

    def _scan_processes(self):
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                name = (proc.info["name"] or "").lower()
                if name in RANSOMWARE_PROCESSES:
                    self.findings.append({
                        "category": "PROCESS",
                        "detail": proc.info["name"],
                        "extra": f"PID: {proc.info['pid']}",
                        "action": "KILL",
                        "pid": proc.info["pid"],
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _scan_encrypted_files(self):
        for folder in SCAN_DIRS:
            if not folder or not os.path.isdir(folder):
                continue
            try:
                for fname in os.listdir(folder):
                    ext = os.path.splitext(fname)[1].lower()
                    if ext in RANSOM_EXTENSIONS:
                        self.findings.append({
                            "category": "ENCRYPTED FILE",
                            "detail": fname,
                            "extra": folder,
                            "action": "REVIEW",
                            "pid": None,
                        })
            except PermissionError:
                continue

    def _scan_ransom_notes(self):
        for folder in SCAN_DIRS:
            if not folder or not os.path.isdir(folder):
                continue
            try:
                for fname in os.listdir(folder):
                    if fname.lower() in RANSOM_NOTES:
                        self.findings.append({
                            "category": "RANSOM NOTE",
                            "detail": fname,
                            "extra": folder,
                            "action": "INSPECT",
                            "pid": None,
                        })
            except PermissionError:
                continue

    def _check_shadow_copies(self) -> bool:
        """Returns True if VSS copies exist (can potentially recover files)."""
        try:
            result = subprocess.run(
                ["vssadmin", "list", "shadows"],
                capture_output=True, text=True, timeout=10
            )
            return "Shadow Copy" in result.stdout
        except Exception:
            return False

    def _show_results(self, vss_alive: bool):
        c = self.console
        c.print()

        if not self.findings:
            c.print(Panel(
                "[bold bright_green]✓  No ransomware detected.\n"
                "[dim]Your files and processes appear safe.[/dim][/bold bright_green]",
                border_style="bright_green",
            ))
        else:
            table = Table(
                title="[bold bright_red]☣  RANSOMWARE INDICATORS[/bold bright_red]",
                box=box.DOUBLE_EDGE, border_style="bright_red",
                header_style="bold bright_cyan",
            )
            table.add_column("CATEGORY", style="bright_yellow", width=18)
            table.add_column("ITEM",     style="bold bright_red", width=30)
            table.add_column("LOCATION", style="dim", width=40)
            table.add_column("ACTION",   justify="center", width=10)

            cat_col = {
                "PROCESS":        "bright_red",
                "ENCRYPTED FILE": "bright_magenta",
                "RANSOM NOTE":    "bright_yellow",
            }
            for f in self.findings:
                col = cat_col.get(f["category"], "white")
                table.add_row(
                    f"[{col}]{f['category']}[/{col}]",
                    f["detail"][:30],
                    f["extra"][:40],
                    f"[bold {col}]{f['action']}[/bold {col}]",
                )
            c.print(Align.center(table))

        c.print()
        if vss_alive:
            c.print("[bold bright_green]✓ Volume Shadow Copies exist — file recovery may be possible![/bold bright_green]")
        else:
            c.print("[bold bright_red]✗ No Volume Shadow Copies found — ransomware may have deleted them.[/bold bright_red]")

        c.print()
        c.print(Panel(
            "[bold bright_cyan]💡 Recovery Tips:[/bold bright_cyan]\n"
            "[dim]1. Disconnect infected machine from network immediately\n"
            "2. Boot from clean USB, run offline AV scan\n"
            "3. Check backup solutions (Windows Backup, cloud sync)\n"
            "4. Use ID-Ransomware (id-ransomware.malwarehunterteam.com) to identify strain\n"
            "5. Check No More Ransom project (nomoreransom.org) for free decryptors[/dim]",
            border_style="bright_cyan", box=box.ROUNDED,
        ))

    def _prompt_action(self):
        c = self.console
        c.print()
        procs = [f for f in self.findings if f["category"] == "PROCESS" and f.get("pid")]
        if procs:
            ans = c.input("[bold bright_red]Kill detected ransomware processes? [y/N]: [/bold bright_red]")
            if ans.strip().lower() == "y":
                for f in procs:
                    try:
                        psutil.Process(f["pid"]).kill()
                        c.print(f"  [bright_red]✗ Killed PID {f['pid']} ({f['detail']})[/bright_red]")
                    except Exception as e:
                        c.print(f"  [dim]Could not kill: {e}[/dim]")

        shadow_ans = c.input("\n[bold bright_yellow]Create a new Volume Shadow Copy now (VSS backup)? [y/N]: [/bold bright_yellow]")
        if shadow_ans.strip().lower() == "y":
            try:
                subprocess.run(["wmic", "shadowcopy", "call", "create", "Volume=C:\\"], timeout=30)
                c.print("[bright_green]✓ Shadow copy creation initiated.[/bright_green]")
            except Exception as e:
                c.print(f"[dim]Could not create shadow copy: {e}[/dim]")

        c.input("\n[dim]Press Enter to return to menu...[/dim]")
