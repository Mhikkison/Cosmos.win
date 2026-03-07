"""
Browser Privacy Cleaner — Detect and clean browser data, cookies, cache,
history, saved passwords locations, and tracking data across major browsers.
"""

import os
import shutil
import sqlite3
import json
import glob
import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box


BROWSER_PATHS = {
    "Chrome": {
        "base": os.path.join(os.environ.get("LOCALAPPDATA", ""), "Google", "Chrome", "User Data"),
        "cache": "Default/Cache",
        "cookies": "Default/Network/Cookies",
        "history": "Default/History",
        "login_data": "Default/Login Data",
        "local_state": "Local State",
        "sessions": "Default/Sessions",
        "preferences": "Default/Preferences",
    },
    "Edge": {
        "base": os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "Edge", "User Data"),
        "cache": "Default/Cache",
        "cookies": "Default/Network/Cookies",
        "history": "Default/History",
        "login_data": "Default/Login Data",
    },
    "Firefox": {
        "base": os.path.join(os.environ.get("APPDATA", ""), "Mozilla", "Firefox", "Profiles"),
        "cookies": "cookies.sqlite",
        "history": "places.sqlite",
        "login_data": "logins.json",
        "cache": "cache2",
    },
    "Brave": {
        "base": os.path.join(os.environ.get("LOCALAPPDATA", ""), "BraveSoftware", "Brave-Browser", "User Data"),
        "cache": "Default/Cache",
        "cookies": "Default/Network/Cookies",
        "history": "Default/History",
    },
    "Opera": {
        "base": os.path.join(os.environ.get("APPDATA", ""), "Opera Software", "Opera Stable"),
        "cache": "Cache",
        "cookies": "Network/Cookies",
        "history": "History",
    },
}


def dir_size(path: str) -> int:
    total = 0
    try:
        for dirpath, dirnames, filenames in os.walk(path):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                try:
                    total += os.path.getsize(fp)
                except (OSError, PermissionError):
                    pass
    except (OSError, PermissionError):
        pass
    return total


def format_bytes(b: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"


class BrowserPrivacyCleaner:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold bright_magenta]BROWSER PRIVACY CLEANER[/bold bright_magenta]\n"
                         "[dim]Detect & clean cookies, cache, history, and tracking data[/dim]"),
            border_style="bright_magenta", box=box.DOUBLE_EDGE,
        ))

        while True:
            c.print()
            table = Table(box=box.ROUNDED, border_style="bright_magenta", header_style="bold bright_cyan")
            table.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            table.add_column("ACTION", style="bold bright_magenta", width=50)
            table.add_row("1", "Scan installed browsers & data sizes")
            table.add_row("2", "View browser data breakdown")
            table.add_row("3", "Clean all browser caches")
            table.add_row("4", "Clean all cookies")
            table.add_row("5", "Clean browsing history")
            table.add_row("6", "Full privacy cleanup (everything)")
            table.add_row("7", "Check tracking protection status")
            table.add_row("0", "Return to main menu")
            c.print(Align.center(table))

            choice = Prompt.ask("  [bold bright_magenta]priv[/bold bright_magenta][dim]>[/dim]", default="0")

            if choice == "1":
                self._scan_browsers()
            elif choice == "2":
                self._data_breakdown()
            elif choice == "3":
                self._clean_cache()
            elif choice == "4":
                self._clean_cookies()
            elif choice == "5":
                self._clean_history()
            elif choice == "6":
                self._full_cleanup()
            elif choice == "7":
                self._tracking_status()
            elif choice == "0":
                break

    def _scan_browsers(self):
        c = self.console
        table = Table(
            title="[bold bright_magenta]Installed Browsers & Data[/bold bright_magenta]",
            box=box.DOUBLE_EDGE, border_style="bright_magenta", header_style="bold bright_cyan",
        )
        table.add_column("BROWSER", style="bold bright_white", width=15)
        table.add_column("INSTALLED", style="bold", width=12)
        table.add_column("DATA SIZE", style="bright_cyan", width=15, justify="right")
        table.add_column("PROFILES", style="dim", width=10, justify="center")
        table.add_column("PATH", style="dim", width=40)

        for browser, paths in BROWSER_PATHS.items():
            base = paths["base"]
            installed = os.path.isdir(base)
            if installed:
                size = dir_size(base)
                profiles = len([d for d in os.listdir(base) if d.startswith("Profile") or d == "Default"]) if browser != "Firefox" else len(glob.glob(os.path.join(base, "*.default*")))
                table.add_row(
                    browser,
                    "[bright_green]YES[/bright_green]",
                    format_bytes(size),
                    str(max(profiles, 1)),
                    base[:40],
                )
            else:
                table.add_row(browser, "[dim]NO[/dim]", "-", "-", "-")

        c.print()
        c.print(Align.center(table))

    def _data_breakdown(self):
        c = self.console
        for browser, paths in BROWSER_PATHS.items():
            base = paths["base"]
            if not os.path.isdir(base):
                continue

            c.print(f"\n  [bold bright_magenta]{browser}[/bold bright_magenta]")
            items = {
                "Cache": os.path.join(base, paths.get("cache", "")),
                "Cookies": os.path.join(base, paths.get("cookies", "")),
                "History": os.path.join(base, paths.get("history", "")),
                "Login Data": os.path.join(base, paths.get("login_data", "")),
            }

            for name, path in items.items():
                if os.path.exists(path):
                    if os.path.isdir(path):
                        size = dir_size(path)
                    else:
                        size = os.path.getsize(path)
                    c.print(f"    {name}: [bright_cyan]{format_bytes(size)}[/bright_cyan]")
                else:
                    c.print(f"    {name}: [dim]not found[/dim]")

    def _clean_cache(self):
        c = self.console
        if not Confirm.ask("  Clean all browser caches?", default=False):
            return

        total_freed = 0
        for browser, paths in BROWSER_PATHS.items():
            base = paths["base"]
            cache_path = os.path.join(base, paths.get("cache", ""))
            if os.path.isdir(cache_path):
                size = dir_size(cache_path)
                try:
                    shutil.rmtree(cache_path, ignore_errors=True)
                    total_freed += size
                    c.print(f"  [bright_green]Cleaned {browser} cache ({format_bytes(size)})[/bright_green]")
                except Exception as e:
                    c.print(f"  [bright_red]{browser} cache: {e}[/bright_red]")

        c.print(f"\n  [bold bright_green]Total freed: {format_bytes(total_freed)}[/bold bright_green]")

    def _clean_cookies(self):
        c = self.console
        if not Confirm.ask("  Delete all browser cookies?", default=False):
            return

        for browser, paths in BROWSER_PATHS.items():
            base = paths["base"]
            cookie_path = os.path.join(base, paths.get("cookies", ""))
            if os.path.isfile(cookie_path):
                try:
                    os.remove(cookie_path)
                    c.print(f"  [bright_green]Deleted {browser} cookies[/bright_green]")
                except Exception as e:
                    c.print(f"  [bright_red]{browser}: {e}[/bright_red]")

    def _clean_history(self):
        c = self.console
        if not Confirm.ask("  Delete all browsing history?", default=False):
            return

        for browser, paths in BROWSER_PATHS.items():
            base = paths["base"]
            hist_path = os.path.join(base, paths.get("history", ""))
            if os.path.isfile(hist_path):
                try:
                    os.remove(hist_path)
                    c.print(f"  [bright_green]Deleted {browser} history[/bright_green]")
                except Exception as e:
                    c.print(f"  [bright_red]{browser}: {e}[/bright_red]")

    def _full_cleanup(self):
        c = self.console
        c.print("\n  [bold bright_red]This will delete ALL browser data (cache, cookies, history).[/bold bright_red]")
        if not Confirm.ask("  Proceed with full cleanup?", default=False):
            return

        self._clean_cache()
        self._clean_cookies()
        self._clean_history()
        c.print("\n  [bold bright_green]Full privacy cleanup complete.[/bold bright_green]")

    def _tracking_status(self):
        c = self.console
        table = Table(
            title="[bold bright_magenta]Tracking Protection Status[/bold bright_magenta]",
            box=box.DOUBLE_EDGE, border_style="bright_magenta", header_style="bold bright_cyan",
        )
        table.add_column("BROWSER", style="bold bright_white", width=15)
        table.add_column("3RD PARTY COOKIES", style="bold", width=20)
        table.add_column("DO NOT TRACK", style="bold", width=15)

        for browser, paths in BROWSER_PATHS.items():
            base = paths["base"]
            if not os.path.isdir(base):
                continue

            # Try to read preferences
            prefs_path = os.path.join(base, "Default", "Preferences")
            third_party = "UNKNOWN"
            dnt = "UNKNOWN"

            if os.path.isfile(prefs_path):
                try:
                    with open(prefs_path, "r", encoding="utf-8", errors="ignore") as f:
                        prefs = json.load(f)
                    block_3p = prefs.get("profile", {}).get("block_third_party_cookies", None)
                    if block_3p is True:
                        third_party = "[bright_green]BLOCKED[/bright_green]"
                    elif block_3p is False:
                        third_party = "[bright_red]ALLOWED[/bright_red]"

                    dnt_val = prefs.get("enable_do_not_track", None)
                    if dnt_val is True:
                        dnt = "[bright_green]ON[/bright_green]"
                    elif dnt_val is False:
                        dnt = "[bright_red]OFF[/bright_red]"
                except Exception:
                    pass

            table.add_row(browser, third_party, dnt)

        c.print()
        c.print(Align.center(table))
