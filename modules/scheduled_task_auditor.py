"""
Scheduled Task Auditor — Enumerate Windows scheduled tasks, detect persistence
via task scheduler, find suspicious tasks, and manage task cleanup.
"""

import subprocess
import re
import os
import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box


SUSPICIOUS_TASK_PATTERNS = [
    "powershell", "cmd.exe /c", "wscript", "cscript", "mshta",
    "regsvr32", "rundll32", "certutil", "bitsadmin",
    "%temp%", "%appdata%", "download", "update.exe",
    "base64", "-enc", "-e ", "iex(", "invoke-expression",
    "pastebin", "bit.ly", "tinyurl", "raw.githubusercontent",
]

KNOWN_LEGIT_AUTHORS = {
    "Microsoft", "Microsoft Corporation", "Intel", "NVIDIA",
    "Adobe", "Google", "Apple", "Mozilla",
}


def run_cmd(args, timeout=20):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception as e:
        return str(e)


class ScheduledTaskAuditor:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold bright_yellow]SCHEDULED TASK AUDITOR[/bold bright_yellow]\n"
                         "[dim]Task enumeration, persistence detection & suspicious task finder[/dim]"),
            border_style="bright_yellow", box=box.DOUBLE_EDGE,
        ))

        while True:
            c.print()
            table = Table(box=box.ROUNDED, border_style="bright_yellow", header_style="bold bright_cyan")
            table.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            table.add_column("ACTION", style="bold bright_yellow", width=50)
            table.add_row("1", "List all scheduled tasks")
            table.add_row("2", "Detect suspicious scheduled tasks")
            table.add_row("3", "View task details")
            table.add_row("4", "Find recently created tasks")
            table.add_row("5", "Disable a task")
            table.add_row("6", "Delete a task")
            table.add_row("0", "Return to main menu")
            c.print(Align.center(table))

            choice = Prompt.ask("  [bold bright_yellow]task[/bold bright_yellow][dim]>[/dim]", default="0")

            if choice == "1":
                self._list_tasks()
            elif choice == "2":
                self._detect_suspicious()
            elif choice == "3":
                self._task_detail()
            elif choice == "4":
                self._recent_tasks()
            elif choice == "5":
                self._disable_task()
            elif choice == "6":
                self._delete_task()
            elif choice == "0":
                break

    def _list_tasks(self):
        c = self.console
        output = run_cmd(["schtasks", "/query", "/fo", "csv", "/v"])
        tasks = self._parse_csv(output)

        if not tasks:
            c.print("  [dim]No scheduled tasks found or access denied.[/dim]")
            return

        table = Table(
            title=f"[bold bright_yellow]Scheduled Tasks ({len(tasks)})[/bold bright_yellow]",
            box=box.DOUBLE_EDGE, border_style="bright_yellow", header_style="bold bright_cyan",
        )
        table.add_column("#", style="dim", width=5)
        table.add_column("TASK NAME", style="bold bright_white", width=35)
        table.add_column("STATUS", style="bold", width=12)
        table.add_column("NEXT RUN", style="dim", width=20)
        table.add_column("AUTHOR", style="dim", width=20)

        for i, task in enumerate(tasks[:80], 1):
            status = task.get("Status", "?")
            status_col = "bright_green" if status == "Ready" else "bright_yellow" if status == "Running" else "dim"
            table.add_row(
                str(i),
                task.get("TaskName", "?")[:35],
                f"[{status_col}]{status}[/{status_col}]",
                task.get("Next Run Time", "?")[:20],
                task.get("Author", "?")[:20],
            )

        c.print()
        c.print(table)

    def _detect_suspicious(self):
        c = self.console
        output = run_cmd(["schtasks", "/query", "/fo", "csv", "/v"])
        tasks = self._parse_csv(output)
        suspicious = []

        with Progress(
            SpinnerColumn(style="bright_yellow"),
            TextColumn("[bold bright_yellow]Analyzing tasks...[/bold bright_yellow]"),
            BarColumn(bar_width=30),
            console=c,
        ) as progress:
            t = progress.add_task("Scanning...", total=len(tasks))
            for task in tasks:
                reasons = []
                action = task.get("Task To Run", "").lower()
                name = task.get("TaskName", "").lower()
                author = task.get("Author", "")

                for pattern in SUSPICIOUS_TASK_PATTERNS:
                    if pattern.lower() in action:
                        reasons.append(f"Suspicious pattern: {pattern}")
                        break

                if author and not any(legit in author for legit in KNOWN_LEGIT_AUTHORS):
                    if "\\users\\" in action or "%temp%" in action or "%appdata%" in action:
                        reasons.append("Non-standard author with user-path action")

                if "\\microsoft\\" not in name and "\\windows\\" not in name:
                    if any(ext in action for ext in [".bat", ".vbs", ".ps1", ".js"]):
                        reasons.append("Script execution from non-system task")

                if reasons:
                    suspicious.append({"task": task, "reasons": reasons})
                progress.advance(t)

        if not suspicious:
            c.print("  [bold bright_green]No suspicious scheduled tasks detected.[/bold bright_green]")
            return

        table = Table(
            title=f"[bold bright_red]Suspicious Tasks ({len(suspicious)})[/bold bright_red]",
            box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
        )
        table.add_column("TASK", style="bold bright_red", width=30)
        table.add_column("ACTION", style="dim", width=35)
        table.add_column("REASON", style="bright_yellow", width=35)

        for s in suspicious[:30]:
            table.add_row(
                s["task"].get("TaskName", "?")[:30],
                s["task"].get("Task To Run", "?")[:35],
                "; ".join(s["reasons"])[:35],
            )

        c.print()
        c.print(Align.center(table))

    def _task_detail(self):
        c = self.console
        name = Prompt.ask("  [bright_cyan]Task name (full path)[/bright_cyan]")
        output = run_cmd(["schtasks", "/query", "/tn", name, "/fo", "list", "/v"])
        if "ERROR" in output:
            c.print(f"  [bright_red]Task not found: {name}[/bright_red]")
            return

        table = Table(
            title=f"[bold bright_yellow]Task: {name}[/bold bright_yellow]",
            box=box.DOUBLE_EDGE, border_style="bright_yellow", header_style="bold bright_cyan",
        )
        table.add_column("PROPERTY", style="bold bright_white", width=25)
        table.add_column("VALUE", style="bright_cyan", width=60)

        for line in output.splitlines():
            if ":" in line:
                parts = line.split(":", 1)
                key = parts[0].strip()
                val = parts[1].strip()
                if key and val:
                    table.add_row(key, val[:60])

        c.print()
        c.print(Align.center(table))

    def _recent_tasks(self):
        c = self.console
        output = run_cmd(["schtasks", "/query", "/fo", "csv", "/v"])
        tasks = self._parse_csv(output)

        # Filter for non-Microsoft tasks
        custom = [t for t in tasks if not any(legit in t.get("Author", "")
                                               for legit in KNOWN_LEGIT_AUTHORS)]

        if not custom:
            c.print("  [dim]No custom/non-Microsoft tasks found.[/dim]")
            return

        table = Table(
            title=f"[bold bright_yellow]Custom Scheduled Tasks ({len(custom)})[/bold bright_yellow]",
            box=box.DOUBLE_EDGE, border_style="bright_yellow", header_style="bold bright_cyan",
        )
        table.add_column("TASK", style="bold bright_white", width=30)
        table.add_column("AUTHOR", style="bright_yellow", width=20)
        table.add_column("ACTION", style="dim", width=40)

        for task in custom[:40]:
            table.add_row(
                task.get("TaskName", "?")[:30],
                task.get("Author", "?")[:20],
                task.get("Task To Run", "?")[:40],
            )

        c.print()
        c.print(Align.center(table))

    def _disable_task(self):
        c = self.console
        name = Prompt.ask("  [bright_yellow]Task name to disable[/bright_yellow]")
        if Confirm.ask(f"  Disable '{name}'?", default=False):
            output = run_cmd(["schtasks", "/change", "/tn", name, "/disable"])
            if "SUCCESS" in output.upper() or "ERROR" not in output.upper():
                c.print(f"  [bright_green]Task '{name}' disabled.[/bright_green]")
            else:
                c.print(f"  [bright_red]Failed: {output[:100]}[/bright_red]")

    def _delete_task(self):
        c = self.console
        name = Prompt.ask("  [bright_red]Task name to delete[/bright_red]")
        if Confirm.ask(f"  DELETE '{name}'? This cannot be undone.", default=False):
            output = run_cmd(["schtasks", "/delete", "/tn", name, "/f"])
            if "SUCCESS" in output.upper():
                c.print(f"  [bright_green]Task '{name}' deleted.[/bright_green]")
            else:
                c.print(f"  [bright_red]Failed: {output[:100]}[/bright_red]")

    def _parse_csv(self, output: str) -> list[dict]:
        lines = output.strip().splitlines()
        if len(lines) < 2:
            return []

        headers = [h.strip('"') for h in lines[0].split('","')]
        tasks = []
        for line in lines[1:]:
            vals = [v.strip('"') for v in line.split('","')]
            if len(vals) == len(headers):
                tasks.append(dict(zip(headers, vals)))
        return tasks
