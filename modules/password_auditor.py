"""
Password Auditor — Audit local Windows user accounts, check password policies,
detect weak configurations, check credential exposure via Have I Been Pwned API,
and test password strength.
"""

import subprocess
import hashlib
import re
import math
import time
import string
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "monkey",
    "1234567", "letmein", "trustno1", "dragon", "baseball", "iloveyou",
    "master", "sunshine", "ashley", "bailey", "shadow", "123123",
    "654321", "superman", "qazwsx", "michael", "football", "password1",
    "password123", "admin", "admin123", "root", "toor", "welcome",
    "welcome1", "p@ssw0rd", "changeme", "test", "guest", "default",
}


def password_entropy(pw: str) -> float:
    charset = 0
    if any(c in string.ascii_lowercase for c in pw):
        charset += 26
    if any(c in string.ascii_uppercase for c in pw):
        charset += 26
    if any(c in string.digits for c in pw):
        charset += 10
    if any(c in string.punctuation for c in pw):
        charset += 33
    if charset == 0:
        return 0
    return len(pw) * math.log2(charset)


def password_strength(pw: str) -> tuple[str, str, float]:
    """Returns (rating, color, entropy)."""
    entropy = password_entropy(pw)
    if pw.lower() in COMMON_PASSWORDS:
        return "COMPROMISED", "bright_red", entropy
    if entropy < 28:
        return "VERY WEAK", "bright_red", entropy
    elif entropy < 36:
        return "WEAK", "bright_red", entropy
    elif entropy < 50:
        return "MODERATE", "bright_yellow", entropy
    elif entropy < 70:
        return "STRONG", "bright_green", entropy
    else:
        return "VERY STRONG", "bright_cyan", entropy


def check_hibp(password: str) -> int | None:
    """Check if a password has been exposed using the k-anonymity HIBP API.
    Returns the number of times seen, or None on error."""
    if not HAS_REQUESTS:
        return None
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        resp = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                h, count = line.split(":")
                if h == suffix:
                    return int(count)
            return 0
    except Exception:
        return None


class PasswordAuditor:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold bright_yellow]PASSWORD AUDITOR[/bold bright_yellow]\n"
                         "[dim]Account audit, policy check, password strength & breach detection[/dim]"),
            border_style="bright_yellow", box=box.DOUBLE_EDGE,
        ))

        while True:
            c.print()
            table = Table(box=box.ROUNDED, border_style="bright_yellow", header_style="bold bright_cyan")
            table.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            table.add_column("ACTION", style="bold bright_yellow", width=45)
            table.add_row("1", "Audit local Windows user accounts")
            table.add_row("2", "Check password policy (net accounts)")
            table.add_row("3", "Test password strength (offline)")
            table.add_row("4", "Check password against Have I Been Pwned")
            table.add_row("5", "Detect accounts with empty/no password")
            table.add_row("6", "List admin group members")
            table.add_row("0", "Return to main menu")
            c.print(Align.center(table))

            choice = Prompt.ask("  [bold bright_yellow]pwd[/bold bright_yellow][dim]>[/dim]", default="0")

            if choice == "1":
                self._audit_users()
            elif choice == "2":
                self._check_policy()
            elif choice == "3":
                self._test_strength()
            elif choice == "4":
                self._check_hibp_interactive()
            elif choice == "5":
                self._detect_empty_passwords()
            elif choice == "6":
                self._list_admins()
            elif choice == "0":
                break

    def _audit_users(self):
        c = self.console
        try:
            result = subprocess.run(["net", "user"], capture_output=True, text=True, timeout=10)
            output = result.stdout
        except Exception as e:
            c.print(f"  [bright_red]Error: {e}[/bright_red]")
            return

        # Parse user list
        users = []
        capture = False
        for line in output.splitlines():
            if "---" in line:
                capture = True
                continue
            if capture and line.strip():
                if "The command" in line:
                    break
                users.extend(line.split())

        table = Table(
            title="[bold bright_yellow]Local User Accounts[/bold bright_yellow]",
            box=box.DOUBLE_EDGE, border_style="bright_yellow", header_style="bold bright_cyan",
        )
        table.add_column("USER", style="bold bright_white", width=25)
        table.add_column("FULL NAME", style="dim", width=30)
        table.add_column("ACTIVE", style="bold", width=10)
        table.add_column("LAST LOGON", style="dim", width=25)
        table.add_column("PWD EXPIRES", style="dim", width=15)

        with Progress(
            SpinnerColumn(style="bright_yellow"),
            TextColumn("[bold bright_yellow]{task.description}[/bold bright_yellow]"),
            BarColumn(bar_width=30, style="bright_yellow"),
            console=c,
        ) as progress:
            t = progress.add_task("Auditing users...", total=len(users))
            for user in users:
                detail = self._get_user_detail(user)
                active_col = "bright_green" if detail["active"] == "Yes" else "bright_red"
                table.add_row(
                    user,
                    detail["fullname"],
                    f"[{active_col}]{detail['active']}[/{active_col}]",
                    detail["last_logon"],
                    detail["pwd_expires"],
                )
                progress.advance(t)

        c.print()
        c.print(Align.center(table))

    def _get_user_detail(self, username: str) -> dict:
        info = {"fullname": "", "active": "?", "last_logon": "?", "pwd_expires": "?"}
        try:
            result = subprocess.run(["net", "user", username],
                                    capture_output=True, text=True, timeout=10)
            for line in result.stdout.splitlines():
                if "Full Name" in line:
                    info["fullname"] = line.split("Full Name")[-1].strip()
                elif "Account active" in line:
                    info["active"] = line.split("Account active")[-1].strip()
                elif "Last logon" in line:
                    info["last_logon"] = line.split("Last logon")[-1].strip()
                elif "Password expires" in line:
                    info["pwd_expires"] = line.split("Password expires")[-1].strip()
        except Exception:
            pass
        return info

    def _check_policy(self):
        c = self.console
        try:
            result = subprocess.run(["net", "accounts"], capture_output=True, text=True, timeout=10)
            output = result.stdout
        except Exception as e:
            c.print(f"  [bright_red]Error: {e}[/bright_red]")
            return

        table = Table(
            title="[bold bright_yellow]Password Policy[/bold bright_yellow]",
            box=box.DOUBLE_EDGE, border_style="bright_yellow", header_style="bold bright_cyan",
        )
        table.add_column("SETTING", style="bold bright_white", width=40)
        table.add_column("VALUE", style="bright_cyan", width=30)
        table.add_column("ASSESSMENT", style="bold", width=20)

        for line in output.splitlines():
            if ":" in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    setting = parts[0].strip()
                    value = parts[1].strip()
                    assessment = self._assess_policy(setting, value)
                    table.add_row(setting, value, assessment)

        c.print()
        c.print(Align.center(table))

    def _assess_policy(self, setting: str, value: str) -> str:
        setting_l = setting.lower()
        if "minimum password length" in setting_l:
            try:
                length = int(value)
                if length >= 12:
                    return "[bright_green]GOOD[/bright_green]"
                elif length >= 8:
                    return "[bright_yellow]ACCEPTABLE[/bright_yellow]"
                else:
                    return "[bright_red]WEAK[/bright_red]"
            except ValueError:
                pass
        if "lockout threshold" in setting_l:
            if value == "Never" or value == "0":
                return "[bright_red]NO LOCKOUT[/bright_red]"
            return "[bright_green]OK[/bright_green]"
        if "password history" in setting_l:
            if value == "None" or value == "0":
                return "[bright_red]NONE[/bright_red]"
        return "[dim]--[/dim]"

    def _test_strength(self):
        c = self.console
        pw = Prompt.ask("  [bright_cyan]Enter password to test[/bright_cyan]", password=True)
        if not pw:
            return

        rating, color, entropy = password_strength(pw)

        # Build visual bar
        bar_len = min(int(entropy / 2), 40)
        bar = "[" + "=" * bar_len + " " * (40 - bar_len) + "]"

        c.print()
        c.print(Panel(
            f"[bold {color}]Rating: {rating}[/bold {color}]\n"
            f"[dim]Entropy: {entropy:.1f} bits[/dim]\n"
            f"[{color}]{bar}[/{color}]\n\n"
            f"[dim]Length: {len(pw)} chars[/dim]\n"
            f"[dim]Has uppercase: {'Yes' if any(c.isupper() for c in pw) else 'No'}[/dim]\n"
            f"[dim]Has digits: {'Yes' if any(c.isdigit() for c in pw) else 'No'}[/dim]\n"
            f"[dim]Has symbols: {'Yes' if any(c in string.punctuation for c in pw) else 'No'}[/dim]\n"
            f"[dim]In common list: {'YES' if pw.lower() in COMMON_PASSWORDS else 'No'}[/dim]",
            title="[bold bright_yellow]Password Analysis[/bold bright_yellow]",
            border_style=color, box=box.DOUBLE_EDGE,
        ))

    def _check_hibp_interactive(self):
        c = self.console
        if not HAS_REQUESTS:
            c.print("  [bright_red]'requests' library not installed.[/bright_red]")
            return

        pw = Prompt.ask("  [bright_cyan]Enter password to check[/bright_cyan]", password=True)
        if not pw:
            return

        c.print("  [dim]Checking against Have I Been Pwned (k-anonymity)...[/dim]")
        count = check_hibp(pw)

        if count is None:
            c.print("  [bright_yellow]Could not reach HIBP API.[/bright_yellow]")
        elif count == 0:
            c.print("  [bold bright_green]This password was NOT found in any known data breaches.[/bold bright_green]")
        else:
            c.print(f"  [bold bright_red]This password has been seen {count:,} times in data breaches![/bold bright_red]")
            c.print("  [bright_yellow]You should change it immediately.[/bright_yellow]")

    def _detect_empty_passwords(self):
        c = self.console
        try:
            result = subprocess.run(["net", "user"], capture_output=True, text=True, timeout=10)
        except Exception as e:
            c.print(f"  [bright_red]Error: {e}[/bright_red]")
            return

        users = []
        capture = False
        for line in result.stdout.splitlines():
            if "---" in line:
                capture = True
                continue
            if capture and line.strip():
                if "The command" in line:
                    break
                users.extend(line.split())

        c.print()
        empty_found = False
        for user in users:
            try:
                # Try to map a drive with empty password (harmless local test)
                test = subprocess.run(
                    ["net", "user", user],
                    capture_output=True, text=True, timeout=10
                )
                for line in test.stdout.splitlines():
                    if "Password required" in line:
                        required = line.split("Password required")[-1].strip()
                        if required.lower() == "no":
                            c.print(f"  [bold bright_red]User '{user}' does not require a password![/bold bright_red]")
                            empty_found = True
            except Exception:
                continue

        if not empty_found:
            c.print("  [bold bright_green]All accounts require a password.[/bold bright_green]")

    def _list_admins(self):
        c = self.console
        try:
            result = subprocess.run(
                ["net", "localgroup", "Administrators"],
                capture_output=True, text=True, timeout=10
            )
        except Exception as e:
            c.print(f"  [bright_red]Error: {e}[/bright_red]")
            return

        table = Table(
            title="[bold bright_yellow]Administrator Group Members[/bold bright_yellow]",
            box=box.ROUNDED, border_style="bright_yellow", header_style="bold bright_cyan",
        )
        table.add_column("MEMBER", style="bold bright_white", width=40)

        capture = False
        for line in result.stdout.splitlines():
            if "---" in line:
                capture = True
                continue
            if capture and line.strip():
                if "The command" in line:
                    break
                table.add_row(line.strip())

        c.print()
        c.print(Align.center(table))
