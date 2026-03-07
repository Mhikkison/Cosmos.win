"""
Process Manager — Advanced live process viewer with resource monitoring,
tree view, kill, suspend/resume, priority change, and DLL inspection.
"""

import os
import time
import psutil
import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.tree import Tree
from rich import box


SYSTEM_PROCESSES = {"system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
                    "services.exe", "lsass.exe", "svchost.exe", "winlogon.exe",
                    "explorer.exe", "dwm.exe", "fontdrvhost.exe", "sihost.exe"}

SUSPICIOUS_FLAGS = {
    "no_path": "Executable path is hidden or inaccessible",
    "high_cpu": "Consuming > 50% CPU",
    "high_mem": "Using > 1 GB RAM",
    "many_connections": "Has > 20 open network connections",
    "hidden_window": "No visible window for non-service process",
}


def format_bytes(b: int) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


def get_process_info(proc: psutil.Process) -> dict | None:
    try:
        with proc.oneshot():
            info = proc.as_dict(attrs=[
                "pid", "name", "exe", "username", "status",
                "cpu_percent", "memory_info", "create_time",
                "ppid", "num_threads", "nice",
            ])
            info["memory_rss"] = info["memory_info"].rss if info["memory_info"] else 0
            info["cpu_percent"] = info.get("cpu_percent", 0) or 0
            try:
                info["connections"] = len(proc.net_connections())
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                info["connections"] = 0
            return info
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


class ProcessManager:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold bright_magenta]PROCESS MANAGER[/bold bright_magenta]\n"
                         "[dim]Live process viewer with kill, suspend, priority & DLL inspection[/dim]"),
            border_style="bright_magenta", box=box.DOUBLE_EDGE,
        ))

        while True:
            c.print()
            table = Table(box=box.ROUNDED, border_style="bright_magenta", header_style="bold bright_cyan")
            table.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            table.add_column("ACTION", style="bold bright_magenta", width=45)
            table.add_row("1", "View all processes (sorted by CPU)")
            table.add_row("2", "View all processes (sorted by Memory)")
            table.add_row("3", "Search process by name")
            table.add_row("4", "Process tree view")
            table.add_row("5", "Kill a process by PID")
            table.add_row("6", "Suspend / Resume a process")
            table.add_row("7", "Change process priority")
            table.add_row("8", "Inspect loaded DLLs for a process")
            table.add_row("9", "Detect suspicious processes")
            table.add_row("0", "Return to main menu")
            c.print(Align.center(table))

            choice = Prompt.ask("  [bold bright_magenta]proc[/bold bright_magenta][dim]>[/dim]", default="0")

            if choice == "1":
                self._list_processes("cpu")
            elif choice == "2":
                self._list_processes("mem")
            elif choice == "3":
                self._search_process()
            elif choice == "4":
                self._process_tree()
            elif choice == "5":
                self._kill_process()
            elif choice == "6":
                self._suspend_resume()
            elif choice == "7":
                self._change_priority()
            elif choice == "8":
                self._inspect_dlls()
            elif choice == "9":
                self._detect_suspicious()
            elif choice == "0":
                break

    def _list_processes(self, sort_by: str = "cpu"):
        c = self.console
        # Pre-seed CPU measurement
        for p in psutil.process_iter():
            try:
                p.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        time.sleep(0.5)

        procs = []
        for proc in psutil.process_iter():
            info = get_process_info(proc)
            if info:
                procs.append(info)

        if sort_by == "cpu":
            procs.sort(key=lambda x: x["cpu_percent"], reverse=True)
            title = "Processes by CPU Usage"
        else:
            procs.sort(key=lambda x: x["memory_rss"], reverse=True)
            title = "Processes by Memory Usage"

        table = Table(
            title=f"[bold bright_magenta]{title}[/bold bright_magenta]",
            box=box.DOUBLE_EDGE, border_style="bright_magenta",
            header_style="bold bright_cyan",
        )
        table.add_column("PID", style="bright_yellow", width=8, justify="right")
        table.add_column("NAME", style="bold bright_white", width=28)
        table.add_column("CPU %", style="bright_cyan", width=8, justify="right")
        table.add_column("MEMORY", style="bright_green", width=12, justify="right")
        table.add_column("THREADS", style="dim", width=8, justify="right")
        table.add_column("STATUS", style="dim", width=12)
        table.add_column("USER", style="dim", width=22)

        for p in procs[:50]:
            cpu_col = "bright_red" if p["cpu_percent"] > 50 else "bright_cyan"
            mem_col = "bright_red" if p["memory_rss"] > 1_073_741_824 else "bright_green"
            table.add_row(
                str(p["pid"]),
                (p["name"] or "?")[:28],
                f"[{cpu_col}]{p['cpu_percent']:.1f}[/{cpu_col}]",
                f"[{mem_col}]{format_bytes(p['memory_rss'])}[/{mem_col}]",
                str(p.get("num_threads", 0)),
                p.get("status", "?"),
                (p.get("username") or "?")[:22],
            )

        c.print()
        c.print(Align.center(table))
        c.print(f"\n  [dim]Showing top 50 of {len(procs)} processes[/dim]")

    def _search_process(self):
        c = self.console
        name = Prompt.ask("  [bright_cyan]Search term[/bright_cyan]")
        if not name.strip():
            return

        results = []
        for proc in psutil.process_iter(["pid", "name", "exe", "status"]):
            try:
                if name.lower() in (proc.info["name"] or "").lower():
                    results.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if not results:
            c.print(f"  [bright_yellow]No processes matching '{name}'[/bright_yellow]")
            return

        table = Table(box=box.ROUNDED, border_style="bright_magenta", header_style="bold bright_cyan")
        table.add_column("PID", style="bright_yellow", width=8)
        table.add_column("NAME", style="bold bright_white", width=28)
        table.add_column("PATH", style="dim", width=60)
        table.add_column("STATUS", style="dim", width=12)

        for p in results:
            table.add_row(str(p["pid"]), p["name"], (p.get("exe") or "N/A")[:60], p.get("status", "?"))

        c.print()
        c.print(Align.center(table))

    def _process_tree(self):
        c = self.console
        procs = {}
        for proc in psutil.process_iter(["pid", "name", "ppid"]):
            try:
                procs[proc.info["pid"]] = proc.info
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        tree = Tree("[bold bright_magenta]Process Tree[/bold bright_magenta]")
        roots = [p for p in procs.values() if p["ppid"] == 0 or p["ppid"] not in procs]

        def add_children(parent_tree, ppid, depth=0):
            if depth > 5:
                return
            children = [p for p in procs.values() if p["ppid"] == ppid and p["pid"] != ppid]
            for child in sorted(children, key=lambda x: x["name"] or ""):
                label = f"[bright_yellow]{child['pid']}[/bright_yellow] {child['name']}"
                branch = parent_tree.add(label)
                add_children(branch, child["pid"], depth + 1)

        for root in sorted(roots, key=lambda x: x["name"] or "")[:20]:
            label = f"[bold bright_cyan]{root['pid']}[/bold bright_cyan] [bold]{root['name']}[/bold]"
            branch = tree.add(label)
            add_children(branch, root["pid"])

        c.print()
        c.print(tree)

    def _kill_process(self):
        c = self.console
        pid_str = Prompt.ask("  [bright_red]PID to kill[/bright_red]")
        try:
            pid = int(pid_str)
            proc = psutil.Process(pid)
            name = proc.name()
            if Confirm.ask(f"  Kill {name} (PID {pid})?", default=False):
                proc.kill()
                c.print(f"  [bright_red]Killed {name} (PID {pid})[/bright_red]")
        except ValueError:
            c.print("  [bright_red]Invalid PID[/bright_red]")
        except psutil.NoSuchProcess:
            c.print(f"  [bright_yellow]Process {pid_str} not found[/bright_yellow]")
        except psutil.AccessDenied:
            c.print(f"  [bright_red]Access denied for PID {pid_str}[/bright_red]")

    def _suspend_resume(self):
        c = self.console
        pid_str = Prompt.ask("  [bright_yellow]PID to suspend/resume[/bright_yellow]")
        try:
            pid = int(pid_str)
            proc = psutil.Process(pid)
            status = proc.status()
            if status == "stopped":
                proc.resume()
                c.print(f"  [bright_green]Resumed {proc.name()} (PID {pid})[/bright_green]")
            else:
                proc.suspend()
                c.print(f"  [bright_yellow]Suspended {proc.name()} (PID {pid})[/bright_yellow]")
        except ValueError:
            c.print("  [bright_red]Invalid PID[/bright_red]")
        except psutil.NoSuchProcess:
            c.print(f"  [bright_yellow]Process not found[/bright_yellow]")
        except psutil.AccessDenied:
            c.print(f"  [bright_red]Access denied[/bright_red]")

    def _change_priority(self):
        c = self.console
        pid_str = Prompt.ask("  [bright_cyan]PID[/bright_cyan]")
        try:
            pid = int(pid_str)
            proc = psutil.Process(pid)
        except (ValueError, psutil.NoSuchProcess):
            c.print("  [bright_red]Invalid or missing PID[/bright_red]")
            return

        priorities = {
            "1": ("Idle", psutil.IDLE_PRIORITY_CLASS),
            "2": ("Below Normal", psutil.BELOW_NORMAL_PRIORITY_CLASS),
            "3": ("Normal", psutil.NORMAL_PRIORITY_CLASS),
            "4": ("Above Normal", psutil.ABOVE_NORMAL_PRIORITY_CLASS),
            "5": ("High", psutil.HIGH_PRIORITY_CLASS),
            "6": ("Realtime", psutil.REALTIME_PRIORITY_CLASS),
        }
        for k, (name, _) in priorities.items():
            c.print(f"  [bright_yellow]{k}[/bright_yellow]) {name}")

        choice = Prompt.ask("  Priority", default="3")
        if choice in priorities:
            name, val = priorities[choice]
            try:
                proc.nice(val)
                c.print(f"  [bright_green]Set {proc.name()} to {name} priority[/bright_green]")
            except psutil.AccessDenied:
                c.print("  [bright_red]Access denied[/bright_red]")

    def _inspect_dlls(self):
        c = self.console
        pid_str = Prompt.ask("  [bright_cyan]PID to inspect DLLs[/bright_cyan]")
        try:
            pid = int(pid_str)
            proc = psutil.Process(pid)
            name = proc.name()
        except (ValueError, psutil.NoSuchProcess):
            c.print("  [bright_red]Invalid or missing PID[/bright_red]")
            return

        try:
            dlls = proc.memory_maps()
        except psutil.AccessDenied:
            c.print("  [bright_red]Access denied reading memory maps[/bright_red]")
            return

        table = Table(
            title=f"[bold bright_magenta]Loaded DLLs for {name} (PID {pid})[/bold bright_magenta]",
            box=box.ROUNDED, border_style="bright_magenta", header_style="bold bright_cyan",
        )
        table.add_column("#", style="dim", width=5)
        table.add_column("PATH", style="bright_white", width=80)
        table.add_column("RSS", style="bright_cyan", width=12, justify="right")

        for i, mmap in enumerate(dlls[:60], 1):
            path = mmap.path
            rss = format_bytes(mmap.rss) if hasattr(mmap, "rss") else "?"
            col = "bright_red" if "temp" in path.lower() or "appdata" in path.lower() else "bright_white"
            table.add_row(str(i), f"[{col}]{path}[/{col}]", rss)

        c.print()
        c.print(table)
        if len(dlls) > 60:
            c.print(f"[dim]  ... and {len(dlls) - 60} more[/dim]")

    def _detect_suspicious(self):
        c = self.console
        c.print()

        # Pre-seed CPU
        for p in psutil.process_iter():
            try:
                p.cpu_percent(interval=None)
            except Exception:
                pass
        time.sleep(1)

        suspicious = []
        for proc in psutil.process_iter():
            info = get_process_info(proc)
            if not info:
                continue
            name_lower = (info["name"] or "").lower()
            if name_lower in SYSTEM_PROCESSES:
                continue

            flags = []
            if not info.get("exe"):
                flags.append("no_path")
            if info["cpu_percent"] > 50:
                flags.append("high_cpu")
            if info["memory_rss"] > 1_073_741_824:
                flags.append("high_mem")
            if info.get("connections", 0) > 20:
                flags.append("many_connections")

            if flags:
                suspicious.append((info, flags))

        if not suspicious:
            c.print(Panel(
                "[bold bright_green]No suspicious processes detected.[/bold bright_green]",
                border_style="bright_green",
            ))
            return

        table = Table(
            title="[bold bright_red]Suspicious Processes[/bold bright_red]",
            box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
        )
        table.add_column("PID", style="bright_yellow", width=8)
        table.add_column("NAME", style="bold bright_red", width=24)
        table.add_column("CPU", style="bright_cyan", width=8)
        table.add_column("MEM", style="bright_green", width=12)
        table.add_column("FLAGS", style="bright_yellow", width=50)

        for info, flags in suspicious[:30]:
            flag_str = ", ".join(SUSPICIOUS_FLAGS.get(f, f) for f in flags)
            table.add_row(
                str(info["pid"]),
                (info["name"] or "?")[:24],
                f"{info['cpu_percent']:.1f}%",
                format_bytes(info["memory_rss"]),
                flag_str[:50],
            )

        c.print(Align.center(table))
