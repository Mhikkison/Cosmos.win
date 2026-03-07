"""
SSL/TLS Certificate Scanner — Verify SSL certificates, check expiration dates,
cipher suites, protocol versions, and detect misconfigurations.
"""

import ssl
import socket
import datetime
import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box


WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon",
    "RC2", "IDEA", "SEED", "CAMELLIA128",
}

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

COMMON_TARGETS = [
    ("google.com", 443),
    ("github.com", 443),
    ("cloudflare.com", 443),
    ("microsoft.com", 443),
    ("amazon.com", 443),
]


def get_cert_info(host: str, port: int = 443, timeout: float = 5.0) -> dict | None:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                return {
                    "subject": dict(x[0] for x in cert.get("subject", ())),
                    "issuer": dict(x[0] for x in cert.get("issuer", ())),
                    "serial": cert.get("serialNumber", "?"),
                    "not_before": cert.get("notBefore", "?"),
                    "not_after": cert.get("notAfter", "?"),
                    "san": [entry[1] for entry in cert.get("subjectAltName", ())],
                    "cipher_name": cipher[0] if cipher else "?",
                    "cipher_bits": cipher[2] if cipher else 0,
                    "protocol": version or "?",
                }
    except Exception as e:
        return {"error": str(e)}


def parse_ssl_date(date_str: str) -> datetime.datetime | None:
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            return datetime.datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    return None


class SSLScanner:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold bright_cyan]SSL/TLS CERTIFICATE SCANNER[/bold bright_cyan]\n"
                         "[dim]Certificate validation, expiry check, cipher & protocol analysis[/dim]"),
            border_style="bright_cyan", box=box.DOUBLE_EDGE,
        ))

        while True:
            c.print()
            table = Table(box=box.ROUNDED, border_style="bright_cyan", header_style="bold bright_cyan")
            table.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            table.add_column("ACTION", style="bold bright_cyan", width=50)
            table.add_row("1", "Scan a single host certificate")
            table.add_row("2", "Batch scan multiple hosts")
            table.add_row("3", "Check cipher suite strength")
            table.add_row("4", "Test weak protocol support")
            table.add_row("5", "Certificate expiry calendar")
            table.add_row("0", "Return to main menu")
            c.print(Align.center(table))

            choice = Prompt.ask("  [bold bright_cyan]ssl[/bold bright_cyan][dim]>[/dim]", default="0")

            if choice == "1":
                self._scan_single()
            elif choice == "2":
                self._batch_scan()
            elif choice == "3":
                self._check_ciphers()
            elif choice == "4":
                self._test_protocols()
            elif choice == "5":
                self._expiry_calendar()
            elif choice == "0":
                break

    def _scan_single(self):
        c = self.console
        host = Prompt.ask("  [bright_cyan]Hostname (e.g., google.com)[/bright_cyan]")
        port = int(Prompt.ask("  Port", default="443"))

        info = get_cert_info(host, port)
        if not info or "error" in info:
            c.print(f"  [bright_red]Error: {info.get('error', 'Connection failed')}[/bright_red]")
            return

        # Calculate expiry
        not_after = parse_ssl_date(info["not_after"])
        days_left = (not_after - datetime.datetime.utcnow()).days if not_after else -1
        expiry_col = "bright_green" if days_left > 30 else "bright_yellow" if days_left > 7 else "bright_red"

        # Check cipher strength
        cipher_name = info.get("cipher_name", "")
        cipher_weak = any(w in cipher_name.upper() for w in WEAK_CIPHERS)
        cipher_col = "bright_red" if cipher_weak else "bright_green"

        # Check protocol
        proto = info.get("protocol", "?")
        proto_weak = proto in WEAK_PROTOCOLS
        proto_col = "bright_red" if proto_weak else "bright_green"

        san_list = ", ".join(info.get("san", [])[:5])

        c.print()
        c.print(Panel(
            f"[bold bright_white]{host}:{port}[/bold bright_white]\n\n"
            f"[bright_cyan]Subject:[/bright_cyan] {info['subject'].get('commonName', '?')}\n"
            f"[bright_cyan]Issuer:[/bright_cyan] {info['issuer'].get('organizationName', '?')}\n"
            f"[bright_cyan]Serial:[/bright_cyan] {info['serial']}\n"
            f"[bright_cyan]Valid From:[/bright_cyan] {info['not_before']}\n"
            f"[bright_cyan]Valid Until:[/bright_cyan] [{expiry_col}]{info['not_after']} ({days_left} days left)[/{expiry_col}]\n"
            f"[bright_cyan]SANs:[/bright_cyan] {san_list}\n\n"
            f"[bright_cyan]Protocol:[/bright_cyan] [{proto_col}]{proto}[/{proto_col}]\n"
            f"[bright_cyan]Cipher:[/bright_cyan] [{cipher_col}]{cipher_name}[/{cipher_col}] ({info.get('cipher_bits', '?')} bits)\n",
            title="[bold bright_cyan]Certificate Details[/bold bright_cyan]",
            border_style="bright_cyan", box=box.DOUBLE_EDGE,
        ))

        # Overall assessment
        issues = []
        if days_left <= 0:
            issues.append("[bright_red]EXPIRED[/bright_red]")
        elif days_left <= 7:
            issues.append("[bright_red]Expiring in < 7 days[/bright_red]")
        elif days_left <= 30:
            issues.append("[bright_yellow]Expiring in < 30 days[/bright_yellow]")
        if cipher_weak:
            issues.append("[bright_red]Weak cipher suite[/bright_red]")
        if proto_weak:
            issues.append("[bright_red]Outdated protocol[/bright_red]")

        if issues:
            c.print("  [bold bright_red]Issues:[/bold bright_red] " + " | ".join(issues))
        else:
            c.print("  [bold bright_green]Certificate looks good.[/bold bright_green]")

    def _batch_scan(self):
        c = self.console
        hosts_input = Prompt.ask("  [bright_cyan]Hosts (comma-separated, or 'common' for defaults)[/bright_cyan]",
                                 default="common")
        if hosts_input == "common":
            targets = COMMON_TARGETS
        else:
            targets = [(h.strip(), 443) for h in hosts_input.split(",")]

        table = Table(
            title=f"[bold bright_cyan]SSL Batch Scan ({len(targets)} hosts)[/bold bright_cyan]",
            box=box.DOUBLE_EDGE, border_style="bright_cyan", header_style="bold bright_cyan",
        )
        table.add_column("HOST", style="bold bright_white", width=25)
        table.add_column("ISSUER", style="dim", width=22)
        table.add_column("EXPIRES", style="bold", width=15)
        table.add_column("DAYS LEFT", style="bold", width=12, justify="center")
        table.add_column("PROTOCOL", style="bright_cyan", width=10)
        table.add_column("GRADE", style="bold", width=8, justify="center")

        with Progress(
            SpinnerColumn(style="bright_cyan"),
            TextColumn("[bold bright_cyan]Scanning...[/bold bright_cyan]"),
            BarColumn(bar_width=30),
            console=c,
        ) as progress:
            t = progress.add_task("Scanning...", total=len(targets))
            for host, port in targets:
                if isinstance(host, tuple):
                    host, port = host
                info = get_cert_info(host, port)
                if not info or "error" in info:
                    table.add_row(host, "ERROR", "-", "-", "-", "[bright_red]F[/bright_red]")
                else:
                    not_after = parse_ssl_date(info.get("not_after", ""))
                    days = (not_after - datetime.datetime.utcnow()).days if not_after else -1
                    days_col = "bright_green" if days > 30 else "bright_yellow" if days > 7 else "bright_red"

                    proto = info.get("protocol", "?")
                    grade = "A" if proto.startswith("TLSv1.3") else "B" if proto.startswith("TLSv1.2") else "C"
                    grade_col = "bright_green" if grade == "A" else "bright_yellow" if grade == "B" else "bright_red"

                    table.add_row(
                        host,
                        info.get("issuer", {}).get("organizationName", "?")[:22],
                        info.get("not_after", "?")[:15],
                        f"[{days_col}]{days}[/{days_col}]",
                        proto,
                        f"[{grade_col}]{grade}[/{grade_col}]",
                    )
                progress.advance(t)

        c.print()
        c.print(Align.center(table))

    def _check_ciphers(self):
        c = self.console
        host = Prompt.ask("  [bright_cyan]Hostname[/bright_cyan]")
        info = get_cert_info(host)
        if not info or "error" in info:
            c.print(f"  [bright_red]Error: {info.get('error', 'Failed')}[/bright_red]")
            return

        cipher = info.get("cipher_name", "?")
        bits = info.get("cipher_bits", 0)
        is_weak = any(w in cipher.upper() for w in WEAK_CIPHERS)
        col = "bright_red" if is_weak else "bright_green"

        c.print(Panel(
            f"[bright_cyan]Cipher:[/bright_cyan] [{col}]{cipher}[/{col}]\n"
            f"[bright_cyan]Bits:[/bright_cyan] {bits}\n"
            f"[bright_cyan]Assessment:[/bright_cyan] [{'bright_red]WEAK' if is_weak else 'bright_green]STRONG'}[/]",
            title="[bold bright_cyan]Cipher Analysis[/bold bright_cyan]",
            border_style=col,
        ))

    def _test_protocols(self):
        c = self.console
        host = Prompt.ask("  [bright_cyan]Hostname[/bright_cyan]")

        protocols = [
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3 if hasattr(ssl.TLSVersion, "TLSv1_3") else None),
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2 if hasattr(ssl.TLSVersion, "TLSv1_2") else None),
        ]

        table = Table(
            title=f"[bold bright_cyan]Protocol Support: {host}[/bold bright_cyan]",
            box=box.DOUBLE_EDGE, border_style="bright_cyan", header_style="bold bright_cyan",
        )
        table.add_column("PROTOCOL", style="bold bright_white", width=15)
        table.add_column("SUPPORTED", style="bold", width=12)
        table.add_column("ASSESSMENT", style="bold", width=15)

        for name, ver in protocols:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                if ver:
                    ctx.minimum_version = ver
                    ctx.maximum_version = ver
                ctx.check_hostname = True
                ctx.load_default_certs()
                with socket.create_connection((host, 443), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host):
                        supported = True
            except Exception:
                supported = False

            sup_col = "bright_green" if supported else "bright_red"
            assess = "[bright_green]GOOD[/bright_green]" if name in ("TLSv1.2", "TLSv1.3") and supported else "[dim]N/A[/dim]"
            table.add_row(name, f"[{sup_col}]{'YES' if supported else 'NO'}[/{sup_col}]", assess)

        c.print()
        c.print(Align.center(table))

    def _expiry_calendar(self):
        c = self.console
        hosts_input = Prompt.ask("  [bright_cyan]Hosts (comma-separated, or 'common')[/bright_cyan]", default="common")
        if hosts_input == "common":
            targets = [h[0] for h in COMMON_TARGETS]
        else:
            targets = [h.strip() for h in hosts_input.split(",")]

        table = Table(
            title="[bold bright_cyan]Certificate Expiry Calendar[/bold bright_cyan]",
            box=box.DOUBLE_EDGE, border_style="bright_cyan", header_style="bold bright_cyan",
        )
        table.add_column("HOST", style="bold bright_white", width=25)
        table.add_column("EXPIRES", style="dim", width=25)
        table.add_column("DAYS LEFT", style="bold", width=12, justify="center")
        table.add_column("URGENCY", style="bold", width=15)

        for host in targets:
            info = get_cert_info(host)
            if not info or "error" in info:
                table.add_row(host, "ERROR", "-", "[bright_red]FAILED[/bright_red]")
                continue

            not_after = parse_ssl_date(info.get("not_after", ""))
            days = (not_after - datetime.datetime.utcnow()).days if not_after else -1

            if days <= 0:
                urgency = "[bright_red]EXPIRED[/bright_red]"
            elif days <= 7:
                urgency = "[bright_red]CRITICAL[/bright_red]"
            elif days <= 30:
                urgency = "[bright_yellow]WARNING[/bright_yellow]"
            elif days <= 90:
                urgency = "[bright_cyan]MONITOR[/bright_cyan]"
            else:
                urgency = "[bright_green]OK[/bright_green]"

            days_col = "bright_green" if days > 30 else "bright_yellow" if days > 7 else "bright_red"
            table.add_row(host, info.get("not_after", "?")[:25], f"[{days_col}]{days}[/{days_col}]", urgency)

        c.print()
        c.print(Align.center(table))
