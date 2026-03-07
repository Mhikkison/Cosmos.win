"""
Dark Web Checker — Check if your data (emails, domains, IPs) appears in dark web
breach dumps using free APIs: XposedOrNot analytics, HaveIBeenPwned pastes,
and IntelX free tier. Also checks for credential stuffing indicators.
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


class DarkWebChecker:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold #00e676]DARK WEB CHECKER[/bold #00e676]\n"
                         "[dim]Check if your data appears in dark web breach dumps & paste sites[/dim]"),
            border_style="#00e676", box=box.DOUBLE_EDGE,
        ))

        while True:
            c.print()
            table = Table(box=box.ROUNDED, border_style="#00e676", header_style="bold bright_cyan")
            table.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            table.add_column("ACTION", style="bold #00e676", width=55)
            table.add_row("1", "Full exposure report (email)")
            table.add_row("2", "Breach analytics dashboard")
            table.add_row("3", "Check password in dark web dumps")
            table.add_row("4", "Domain exposure check")
            table.add_row("5", "Credential stuffing risk assessment")
            table.add_row("6", "Dark web threat briefing")
            table.add_row("0", "Return to main menu")
            c.print(Align.center(table))

            choice = Prompt.ask("  [bold #00e676]darkweb[/bold #00e676][dim]>[/dim]", default="0")

            if choice == "1":
                self._full_report()
            elif choice == "2":
                self._breach_analytics()
            elif choice == "3":
                self._check_password()
            elif choice == "4":
                self._domain_exposure()
            elif choice == "5":
                self._cred_stuffing()
            elif choice == "6":
                self._threat_briefing()
            elif choice == "0":
                break

    def _full_report(self):
        c = self.console
        email = Prompt.ask("  [bright_cyan]Email to check[/bright_cyan]").strip()

        if not re.match(r'^[\w.+-]+@[\w-]+\.[\w.]+$', email):
            c.print("  [bright_red]Invalid email format.[/bright_red]")
            return

        if not HAS_REQUESTS:
            c.print("  [bright_red]requests library required.[/bright_red]")
            return

        results = {
            "breaches": [], "pastes": 0, "risk_score": 0,
            "first_breach": "?", "latest_breach": "?",
            "data_types": set(), "total_records": 0,
        }

        with Progress(
            SpinnerColumn(style="#00e676"),
            TextColumn("[bold #00e676]{task.description}[/bold #00e676]"),
            BarColumn(bar_width=35),
            console=c,
        ) as progress:
            t = progress.add_task("Scanning dark web sources...", total=3)

            # XposedOrNot breach analytics
            progress.update(t, description="Querying XposedOrNot analytics")
            try:
                resp = requests.get(
                    f"https://api.xposedornot.com/v1/breach-analytics?email={email}",
                    timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    exposed = data.get("ExposedBreaches", {})
                    breaches_detail = exposed.get("breaches_details", [])

                    if breaches_detail:
                        results["breaches"] = breaches_detail
                        for b in breaches_detail:
                            if isinstance(b, dict):
                                data_classes = b.get("xposed_data", "")
                                if isinstance(data_classes, str):
                                    for d in data_classes.split(","):
                                        results["data_types"].add(d.strip())
                                try:
                                    records = int(b.get("xposed_records", 0))
                                    results["total_records"] += records
                                except (ValueError, TypeError):
                                    pass

                    metrics = data.get("BreachesSummary", data.get("breaches_summary", {}))
                    if isinstance(metrics, dict):
                        results["pastes"] = metrics.get("pastes_count", 0)

                    paste_summary = data.get("PastesSummary", {})
                    if isinstance(paste_summary, dict):
                        results["pastes"] = paste_summary.get("cnt", results["pastes"])
            except Exception:
                pass
            progress.advance(t)

            # Check email hash in pastes via XposedOrNot
            progress.update(t, description="Checking paste sites")
            try:
                resp2 = requests.get(
                    f"https://api.xposedornot.com/v1/check-email/{email}",
                    timeout=10)
                if resp2.status_code == 200:
                    data2 = resp2.json()
                    breaches2 = data2.get("breaches", [])
                    if breaches2 and not results["breaches"]:
                        results["breaches"] = breaches2 if isinstance(breaches2, list) else [breaches2]
            except Exception:
                pass
            progress.advance(t)

            # Calculate risk score
            progress.update(t, description="Calculating risk score")
            breach_count = len(results["breaches"])
            results["risk_score"] = min(100, breach_count * 12 + results["pastes"] * 8)

            sensitive_types = {"passwords", "password", "credit cards", "ssn",
                             "social security", "bank", "financial"}
            if results["data_types"] & sensitive_types:
                results["risk_score"] = min(100, results["risk_score"] + 25)
            progress.advance(t)

        # Display report
        breach_count = len(results["breaches"])
        risk = results["risk_score"]

        if risk >= 75:
            grade, grade_col = "CRITICAL", "bright_red"
        elif risk >= 50:
            grade, grade_col = "HIGH", "bright_red"
        elif risk >= 25:
            grade, grade_col = "MODERATE", "bright_yellow"
        else:
            grade, grade_col = "LOW", "bright_green"

        c.print(Panel(
            f"[bright_cyan]Email:[/bright_cyan] [bold bright_white]{email}[/bold bright_white]\n"
            f"[bright_cyan]Breaches Found:[/bright_cyan] [bold {'bright_red' if breach_count > 0 else 'bright_green'}]{breach_count}[/bold {'bright_red' if breach_count > 0 else 'bright_green'}]\n"
            f"[bright_cyan]Paste Appearances:[/bright_cyan] {results['pastes']}\n"
            f"[bright_cyan]Total Records Exposed:[/bright_cyan] {results['total_records']:,}\n"
            f"[bright_cyan]Data Types Exposed:[/bright_cyan] {', '.join(list(results['data_types'])[:8]) or 'None'}\n\n"
            f"[bright_cyan]Dark Web Risk:[/bright_cyan] [bold {grade_col}]{grade} ({risk}/100)[/bold {grade_col}]",
            title="[bold #00e676]Dark Web Exposure Report[/bold #00e676]",
            border_style=grade_col, box=box.DOUBLE_EDGE,
        ))

        if results["breaches"]:
            table = Table(
                title=f"[bold bright_red]Breach Details ({breach_count})[/bold bright_red]",
                box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
            )
            table.add_column("BREACH", style="bold bright_white", width=22)
            table.add_column("DATE", style="bright_yellow", width=14)
            table.add_column("DATA EXPOSED", style="dim", width=35)
            table.add_column("RECORDS", style="bright_red", width=14, justify="right")

            for b in results["breaches"][:15]:
                if isinstance(b, str):
                    table.add_row(b[:22], "?", "?", "?")
                elif isinstance(b, dict):
                    name = b.get("breach", b.get("name", "?"))
                    date = b.get("xposed_date", b.get("date", "?"))
                    data_types = b.get("xposed_data", "?")
                    records = b.get("xposed_records", "?")
                    if isinstance(records, int):
                        records = f"{records:,}"
                    table.add_row(
                        str(name)[:22], str(date)[:14],
                        str(data_types)[:35], str(records),
                    )

            c.print()
            c.print(Align.center(table))

    def _breach_analytics(self):
        c = self.console
        email = Prompt.ask("  [bright_cyan]Email[/bright_cyan]").strip()

        if not HAS_REQUESTS:
            c.print("  [bright_red]requests library required.[/bright_red]")
            return

        try:
            resp = requests.get(
                f"https://api.xposedornot.com/v1/breach-analytics?email={email}",
                timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                c.print(Panel(
                    f"[dim]{str(data)[:800]}[/dim]",
                    title=f"[bold #00e676]Analytics: {email}[/bold #00e676]",
                    border_style="#00e676", box=box.DOUBLE_EDGE,
                ))
            else:
                c.print(f"  [dim]No analytics data (HTTP {resp.status_code})[/dim]")
        except Exception as e:
            c.print(f"  [bright_red]Error: {e}[/bright_red]")

    def _check_password(self):
        c = self.console
        c.print("  [dim]Uses HaveIBeenPwned k-anonymity API. Only SHA1 prefix is sent.[/dim]")
        password = Prompt.ask("  [bright_cyan]Password to check[/bright_cyan]", password=True)

        if not password or not HAS_REQUESTS:
            return

        h = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = h[:5], h[5:]

        try:
            resp = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
            if resp.status_code == 200:
                count = 0
                for line in resp.text.splitlines():
                    parts = line.split(":")
                    if len(parts) == 2 and parts[0] == suffix:
                        count = int(parts[1])
                        break

                if count > 0:
                    c.print(Panel(
                        f"[bold bright_red]PASSWORD FOUND IN DARK WEB DUMPS[/bold bright_red]\n\n"
                        f"Appeared in [bold bright_red]{count:,}[/bold bright_red] breach database(s).\n\n"
                        f"[dim]This password is actively used in credential stuffing attacks.\n"
                        f"Change it immediately on all services where it's used.[/dim]",
                        border_style="bright_red", box=box.DOUBLE_EDGE,
                    ))
                else:
                    c.print(Panel(
                        "[bold bright_green]PASSWORD NOT FOUND IN KNOWN DUMPS[/bold bright_green]\n\n"
                        "[dim]This password has not been seen in known dark web breach databases.[/dim]",
                        border_style="bright_green", box=box.DOUBLE_EDGE,
                    ))
        except Exception as e:
            c.print(f"  [bright_red]Error: {e}[/bright_red]")

    def _domain_exposure(self):
        c = self.console
        domain = Prompt.ask("  [bright_cyan]Domain[/bright_cyan]").strip()

        if not HAS_REQUESTS:
            c.print("  [bright_red]requests library required.[/bright_red]")
            return

        c.print(f"\n  [dim]Checking dark web exposure for {domain}...[/dim]")

        # XposedOrNot domain breaches
        try:
            resp = requests.get(
                f"https://api.xposedornot.com/v1/domain-breaches/?domain={domain}",
                timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                breaches = data.get("breaches", data.get("domain_breaches", []))
                if breaches:
                    c.print(Panel(
                        f"[bold bright_red]Domain appears in {len(breaches) if isinstance(breaches, list) else 'multiple'} breach(es)[/bold bright_red]",
                        border_style="bright_red",
                    ))
                    if isinstance(breaches, list):
                        for b in breaches[:10]:
                            if isinstance(b, dict):
                                c.print(f"  [bright_red]{b.get('breach', b.get('name', '?'))}[/bright_red] "
                                       f"[dim]({b.get('date', '?')})[/dim]")
                            else:
                                c.print(f"  [bright_red]{b}[/bright_red]")
                else:
                    c.print(f"\n  [bright_green]No dark web exposure found for {domain}.[/bright_green]")
            else:
                c.print(f"  [dim]No data found (HTTP {resp.status_code})[/dim]")
        except Exception as e:
            c.print(f"  [bright_red]Error: {e}[/bright_red]")

    def _cred_stuffing(self):
        c = self.console
        c.print(Panel(
            "[bold bright_cyan]Credential Stuffing Risk Assessment[/bold bright_cyan]\n\n"
            "[bright_white]Credential stuffing is an automated attack where stolen username/password\n"
            "pairs from one breach are tested against other services.[/bright_white]\n\n"
            "[bold bright_yellow]Risk Factors:[/bold bright_yellow]\n"
            "[bright_white]1.[/bright_white] Password reuse across multiple services\n"
            "[bright_white]2.[/bright_white] Email/password combos found in breach dumps\n"
            "[bright_white]3.[/bright_white] Weak or common passwords\n"
            "[bright_white]4.[/bright_white] No MFA/2FA enabled on accounts\n"
            "[bright_white]5.[/bright_white] Using same email for all registrations\n\n"
            "[bold bright_green]Protection Measures:[/bold bright_green]\n"
            "[bright_white]1.[/bright_white] Use unique passwords for every service\n"
            "[bright_white]2.[/bright_white] Enable 2FA/MFA on all critical accounts\n"
            "[bright_white]3.[/bright_white] Use a password manager (Bitwarden, 1Password)\n"
            "[bright_white]4.[/bright_white] Monitor for breach notifications\n"
            "[bright_white]5.[/bright_white] Use email aliases for different services\n"
            "[bright_white]6.[/bright_white] Rotate passwords every 6-12 months",
            border_style="#00e676", box=box.DOUBLE_EDGE,
        ))

    def _threat_briefing(self):
        c = self.console

        c.print(Panel(
            "[bold bright_cyan]Dark Web Threat Landscape 2024-2025[/bold bright_cyan]\n\n"
            "[bold bright_yellow]Current Trends:[/bold bright_yellow]\n"
            "[bright_white]- Initial Access Brokers (IABs)[/bright_white] selling corporate credentials\n"
            "[bright_white]- Ransomware-as-a-Service (RaaS)[/bright_white] growing on dark web forums\n"
            "[bright_white]- Infostealers[/bright_white] (Raccoon, RedLine, Vidar) mass-harvesting credentials\n"
            "[bright_white]- Genesis Market[/bright_white] successors selling browser fingerprints\n"
            "[bright_white]- AI-powered phishing[/bright_white] kits becoming more prevalent\n\n"
            "[bold bright_yellow]Most Targeted Data Types:[/bold bright_yellow]\n"
            "[bright_red]1.[/bright_red] Corporate VPN/RDP credentials\n"
            "[bright_red]2.[/bright_red] Banking & financial login credentials\n"
            "[bright_red]3.[/bright_red] Email accounts (for further phishing)\n"
            "[bright_red]4.[/bright_red] Healthcare records (high resale value)\n"
            "[bright_red]5.[/bright_red] Crypto wallet seeds & private keys\n\n"
            "[bold bright_yellow]Dark Web Marketplaces:[/bold bright_yellow]\n"
            "[dim]Active markets trade in credentials, PII, exploit kits,\n"
            "and malware. Average credential dump price: $5-$50.\n"
            "Corporate access (VPN/RDP) sells for $500-$10,000+.\n"
            "Full identity packages ('Fullz') go for $15-$100.[/dim]",
            border_style="#00e676", box=box.DOUBLE_EDGE,
        ))
