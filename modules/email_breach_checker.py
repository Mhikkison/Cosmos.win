"""
Email Breach Checker — Check emails and domains against known breach databases
using free APIs (XposedOrNot, HaveIBeenPwned breach list).
Provides breach details, exposed data types, and password recommendations.
"""

import hashlib
import re
import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from utils.api_keys import get_api_key


def sha1_hash(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest().upper()


def check_pwned_password(password: str) -> int:
    """Check password against HaveIBeenPwned's k-anonymity API (free, no key)."""
    h = sha1_hash(password)
    prefix, suffix = h[:5], h[5:]
    try:
        resp = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                parts = line.split(":")
                if len(parts) == 2 and parts[0] == suffix:
                    return int(parts[1])
    except Exception:
        pass
    return 0


class EmailBreachChecker:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold #ffd700]EMAIL BREACH CHECKER[/bold #ffd700]\n"
                         "[dim]Check emails & passwords against known breach databases[/dim]"),
            border_style="#ffd700", box=box.DOUBLE_EDGE,
        ))

        while True:
            c.print()
            table = Table(box=box.ROUNDED, border_style="#ffd700", header_style="bold bright_cyan")
            table.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            table.add_column("ACTION", style="bold #ffd700", width=55)
            table.add_row("1", "Check email for breaches (XposedOrNot)")
            table.add_row("2", "Check password against breach databases (HIBP)")
            table.add_row("3", "Domain breach lookup (XposedOrNot)")
            table.add_row("4", "Bulk email check")
            table.add_row("5", "View known major breaches")
            table.add_row("0", "Return to main menu")
            c.print(Align.center(table))

            choice = Prompt.ask("  [bold #ffd700]breach[/bold #ffd700][dim]>[/dim]", default="0")

            if choice == "1":
                self._check_email()
            elif choice == "2":
                self._check_password()
            elif choice == "3":
                self._domain_lookup()
            elif choice == "4":
                self._bulk_check()
            elif choice == "5":
                self._major_breaches()
            elif choice == "0":
                break

    def _check_email(self):
        c = self.console
        email = Prompt.ask("  [bright_cyan]Email address[/bright_cyan]").strip()

        if not re.match(r'^[\w.+-]+@[\w-]+\.[\w.]+$', email):
            c.print("  [bright_red]Invalid email format.[/bright_red]")
            return

        if not HAS_REQUESTS:
            c.print("  [bright_red]requests library required.[/bright_red]")
            return

        c.print(f"\n  [dim]Checking {email} against breach databases...[/dim]")

        # XposedOrNot free API
        breaches_found = []
        try:
            resp = requests.get(
                f"https://api.xposedornot.com/v1/check-email/{email}",
                timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if "breaches" in data:
                    breach_list = data["breaches"]
                    if isinstance(breach_list, list):
                        breaches_found = breach_list
                    elif isinstance(breach_list, dict):
                        for name, details in breach_list.items():
                            breaches_found.append({"name": name, **(details if isinstance(details, dict) else {})})
            elif resp.status_code == 404:
                c.print(Panel(
                    f"[bold bright_green]No breaches found for {email}[/bold bright_green]\n"
                    f"[dim]This email was not found in any known breach database.[/dim]",
                    border_style="bright_green", box=box.DOUBLE_EDGE,
                ))
                return
        except Exception as e:
            c.print(f"  [bright_red]Error querying XposedOrNot: {e}[/bright_red]")

        # Also try breach-analytics endpoint
        try:
            resp2 = requests.get(
                f"https://api.xposedornot.com/v1/breach-analytics?email={email}",
                timeout=10)
            if resp2.status_code == 200:
                data2 = resp2.json()
                exposed_data = data2.get("ExposedBreaches", {})
                if isinstance(exposed_data, dict):
                    breach_detail = exposed_data.get("breaches_details", [])
                    if breach_detail and not breaches_found:
                        breaches_found = breach_detail
        except Exception:
            pass

        if not breaches_found:
            c.print(Panel(
                f"[bold bright_green]No breaches found for {email}[/bold bright_green]",
                border_style="bright_green", box=box.DOUBLE_EDGE,
            ))
            return

        # Display breaches
        table = Table(
            title=f"[bold bright_red]Breaches for {email} ({len(breaches_found)} found)[/bold bright_red]",
            box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
        )
        table.add_column("BREACH", style="bold bright_white", width=25)
        table.add_column("DATE", style="bright_yellow", width=14)
        table.add_column("EXPOSED DATA", style="dim", width=40)
        table.add_column("RECORDS", style="bright_red", width=14, justify="right")

        for b in breaches_found[:20]:
            if isinstance(b, str):
                table.add_row(b, "?", "?", "?")
            elif isinstance(b, dict):
                name = b.get("breach", b.get("name", b.get("Name", "?")))
                date = b.get("xposed_date", b.get("date", b.get("BreachDate", "?")))
                data_types = b.get("xposed_data", b.get("DataClasses", "?"))
                if isinstance(data_types, list):
                    data_types = ", ".join(data_types[:5])
                records = b.get("xposed_records", b.get("PwnCount", "?"))
                if isinstance(records, int):
                    records = f"{records:,}"
                table.add_row(str(name)[:25], str(date)[:14], str(data_types)[:40], str(records))

        c.print()
        c.print(Align.center(table))

        c.print(Panel(
            "[bold bright_yellow]Recommendations:[/bold bright_yellow]\n"
            "[bright_white]1.[/bright_white] Change passwords for all breached services immediately\n"
            "[bright_white]2.[/bright_white] Enable 2FA/MFA on all accounts\n"
            "[bright_white]3.[/bright_white] Use unique passwords per service (password manager)\n"
            "[bright_white]4.[/bright_white] Check for suspicious account activity\n"
            "[bright_white]5.[/bright_white] Consider using email aliases for future registrations",
            border_style="bright_yellow",
        ))

    def _check_password(self):
        c = self.console
        c.print("  [dim]Password is hashed locally. Only first 5 chars of SHA1 are sent (k-anonymity).[/dim]")
        password = Prompt.ask("  [bright_cyan]Password to check[/bright_cyan]", password=True)

        if not password:
            return
        if not HAS_REQUESTS:
            c.print("  [bright_red]requests library required.[/bright_red]")
            return

        count = check_pwned_password(password)

        if count > 0:
            col = "bright_red" if count > 100 else "bright_yellow"
            c.print(Panel(
                f"[bold {col}]PASSWORD COMPROMISED[/bold {col}]\n\n"
                f"This password has been seen [bold bright_red]{count:,}[/bold bright_red] time(s) in data breaches.\n\n"
                f"[dim]You should change this password immediately and never reuse it.[/dim]",
                border_style=col, box=box.DOUBLE_EDGE,
            ))
        else:
            c.print(Panel(
                "[bold bright_green]PASSWORD NOT FOUND IN BREACHES[/bold bright_green]\n\n"
                "[dim]This password has not appeared in known breach databases.\n"
                "This does not guarantee it's secure - use long, unique passwords.[/dim]",
                border_style="bright_green", box=box.DOUBLE_EDGE,
            ))

        # Password strength hints
        score = 0
        if len(password) >= 12:
            score += 2
        elif len(password) >= 8:
            score += 1
        if re.search(r'[A-Z]', password):
            score += 1
        if re.search(r'[a-z]', password):
            score += 1
        if re.search(r'\d', password):
            score += 1
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1

        strength = "WEAK" if score < 3 else "FAIR" if score < 5 else "STRONG"
        s_col = "bright_red" if score < 3 else "bright_yellow" if score < 5 else "bright_green"
        c.print(f"  [dim]Password strength:[/dim] [bold {s_col}]{strength} ({score}/6)[/bold {s_col}]")

    def _domain_lookup(self):
        c = self.console
        domain = Prompt.ask("  [bright_cyan]Domain (e.g. example.com)[/bright_cyan]").strip()

        if not HAS_REQUESTS:
            c.print("  [bright_red]requests library required.[/bright_red]")
            return

        try:
            resp = requests.get(
                f"https://api.xposedornot.com/v1/domain-breaches/?domain={domain}",
                timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                breaches = data.get("breaches", [])
                if breaches:
                    table = Table(
                        title=f"[bold bright_red]Domain Breaches: {domain}[/bold bright_red]",
                        box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
                    )
                    table.add_column("BREACH", style="bold bright_white", width=30)
                    table.add_column("DATE", style="bright_yellow", width=14)
                    table.add_column("RECORDS", style="bright_red", width=14, justify="right")

                    for b in breaches[:20]:
                        if isinstance(b, dict):
                            table.add_row(
                                str(b.get("breach", "?"))[:30],
                                str(b.get("date", "?"))[:14],
                                str(b.get("records", "?"))[:14],
                            )
                        else:
                            table.add_row(str(b)[:30], "?", "?")

                    c.print()
                    c.print(Align.center(table))
                else:
                    c.print(f"\n  [bright_green]No breaches found for {domain}[/bright_green]")
            else:
                c.print(f"  [dim]No data found or API error (HTTP {resp.status_code})[/dim]")
        except Exception as e:
            c.print(f"  [bright_red]Error: {e}[/bright_red]")

    def _bulk_check(self):
        c = self.console
        c.print("  [dim]Enter emails separated by commas or newlines.[/dim]")
        raw = Prompt.ask("  [bright_cyan]Emails[/bright_cyan]")
        emails = [e.strip() for e in re.split(r'[,\n;]+', raw) if e.strip()]

        if not emails:
            return
        if not HAS_REQUESTS:
            c.print("  [bright_red]requests library required.[/bright_red]")
            return

        table = Table(
            title=f"[bold #ffd700]Bulk Breach Check ({len(emails)} emails)[/bold #ffd700]",
            box=box.DOUBLE_EDGE, border_style="#ffd700", header_style="bold bright_cyan",
        )
        table.add_column("EMAIL", style="bold bright_white", width=30)
        table.add_column("STATUS", style="bold", width=15)
        table.add_column("BREACHES", style="bright_red", width=8, justify="center")

        with Progress(
            SpinnerColumn(style="#ffd700"),
            TextColumn("[bold #ffd700]Checking...[/bold #ffd700]"),
            BarColumn(bar_width=30),
            console=c,
        ) as progress:
            t = progress.add_task("", total=len(emails))
            for email in emails[:20]:
                try:
                    resp = requests.get(
                        f"https://api.xposedornot.com/v1/check-email/{email}",
                        timeout=8)
                    if resp.status_code == 200:
                        data = resp.json()
                        breaches = data.get("breaches", [])
                        count = len(breaches) if isinstance(breaches, list) else 1
                        table.add_row(email, "[bright_red]BREACHED[/bright_red]", str(count))
                    else:
                        table.add_row(email, "[bright_green]CLEAN[/bright_green]", "0")
                except Exception:
                    table.add_row(email, "[dim]ERROR[/dim]", "?")
                progress.advance(t)
                time.sleep(0.5)  # Rate limiting

        c.print()
        c.print(Align.center(table))

    def _major_breaches(self):
        c = self.console

        breaches = [
            ("Yahoo", "2013-2014", "3,000,000,000", "Names, emails, DOB, passwords"),
            ("LinkedIn", "2021", "700,000,000", "Emails, phone numbers, names"),
            ("Facebook", "2019", "533,000,000", "Phone numbers, emails, names"),
            ("Marriott", "2018", "500,000,000", "Names, passports, credit cards"),
            ("Adobe", "2013", "153,000,000", "Emails, passwords, credit cards"),
            ("Equifax", "2017", "147,000,000", "SSN, DOB, addresses"),
            ("eBay", "2014", "145,000,000", "Emails, passwords, addresses"),
            ("Canva", "2019", "137,000,000", "Emails, names, passwords"),
            ("Dropbox", "2012", "68,648,009", "Emails, passwords"),
            ("Tumblr", "2013", "65,469,298", "Emails, passwords"),
        ]

        table = Table(
            title="[bold bright_red]Top 10 Largest Known Data Breaches[/bold bright_red]",
            box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
        )
        table.add_column("SERVICE", style="bold bright_white", width=15)
        table.add_column("YEAR", style="bright_yellow", width=12)
        table.add_column("RECORDS", style="bold bright_red", width=18, justify="right")
        table.add_column("DATA EXPOSED", style="dim", width=40)

        for name, year, records, data in breaches:
            table.add_row(name, year, records, data)

        c.print()
        c.print(Align.center(table))
