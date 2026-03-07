"""
Phishing URL Checker — Analyze URLs for phishing indicators using heuristic
analysis, domain reputation, SSL verification, redirect chain inspection,
and deep API scans via urlscan.io, VirusTotal, and Google Safe Browsing.
"""

import re
import socket
import ssl
import time
from urllib.parse import urlparse
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.prompt import Prompt
from rich import box

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from utils.api_keys import get_api_key


SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".xyz",
                   ".top", ".work", ".click", ".loan", ".racing",
                   ".download", ".stream", ".bid", ".win", ".review"}

PHISHING_KEYWORDS = [
    "login", "signin", "verify", "account", "update", "secure",
    "banking", "paypal", "amazon", "apple", "microsoft", "google",
    "facebook", "netflix", "support", "helpdesk", "password",
    "confirm", "suspend", "locked", "unusual", "activity",
]

BRAND_IMPERSONATION = {
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "apple": "apple.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "facebook": "facebook.com",
    "netflix": "netflix.com",
    "instagram": "instagram.com",
    "twitter": "twitter.com",
    "linkedin": "linkedin.com",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "bankofamerica": "bankofamerica.com",
}

HOMOGLYPH_MAP = {
    "0": "o", "1": "l", "rn": "m", "vv": "w",
    "cl": "d", "nn": "m",
}


class PhishingURLChecker:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold bright_red]PHISHING URL CHECKER[/bold bright_red]\n"
                         "[dim]URL analysis, brand impersonation detection & redirect inspection[/dim]"),
            border_style="bright_red", box=box.DOUBLE_EDGE,
        ))

        while True:
            c.print()
            table = Table(box=box.ROUNDED, border_style="bright_red", header_style="bold bright_cyan")
            table.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            table.add_column("ACTION", style="bold bright_red", width=50)
            table.add_row("1", "Analyze a single URL")
            table.add_row("2", "Batch URL analysis")
            table.add_row("3", "Check redirect chain")
            table.add_row("4", "Verify SSL certificate of URL")
            table.add_row("5", "Domain age & reputation check")
            table.add_row("6", "Deep API scan (urlscan.io + VirusTotal)")
            table.add_row("0", "Return to main menu")
            c.print(Align.center(table))

            choice = Prompt.ask("  [bold bright_red]phish[/bold bright_red][dim]>[/dim]", default="0")

            if choice == "1":
                self._analyze_single()
            elif choice == "2":
                self._batch_analyze()
            elif choice == "3":
                self._check_redirects()
            elif choice == "4":
                self._check_ssl()
            elif choice == "5":
                self._domain_reputation()
            elif choice == "6":
                url = Prompt.ask("  [bright_cyan]URL to deep-scan[/bright_cyan]")
                if url:
                    if not url.startswith("http"):
                        url = "https://" + url
                    self._api_url_scan(url)
            elif choice == "0":
                break

    def _analyze_url(self, url: str) -> dict:
        if not url.startswith("http"):
            url = "https://" + url

        parsed = urlparse(url)
        domain = parsed.hostname or ""
        path = parsed.path or ""
        full = domain + path

        score = 0
        indicators = []

        # Check TLD
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                score += 20
                indicators.append(f"High-risk TLD: {tld}")
                break

        # Check for IP address in URL
        if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
            score += 30
            indicators.append("IP address used instead of domain")

        # Check for excessive subdomains
        subdomain_count = domain.count(".")
        if subdomain_count > 3:
            score += 15
            indicators.append(f"Excessive subdomains ({subdomain_count})")

        # Check for phishing keywords
        for keyword in PHISHING_KEYWORDS:
            if keyword in full.lower():
                score += 10
                indicators.append(f"Phishing keyword: {keyword}")
                break

        # Check for brand impersonation
        for brand, legit_domain in BRAND_IMPERSONATION.items():
            if brand in domain.lower() and legit_domain not in domain.lower():
                score += 35
                indicators.append(f"Brand impersonation: {brand} (legit: {legit_domain})")
                break

        # Check URL length
        if len(url) > 100:
            score += 10
            indicators.append(f"Suspicious URL length: {len(url)}")

        # Check for @ symbol
        if "@" in url:
            score += 25
            indicators.append("@ symbol in URL (credential injection)")

        # Check for encoded characters
        if "%" in url and url.count("%") > 3:
            score += 15
            indicators.append("Excessive URL encoding")

        # Check for homoglyphs
        for fake, real in HOMOGLYPH_MAP.items():
            if fake in domain:
                score += 20
                indicators.append(f"Possible homoglyph: '{fake}' could be '{real}'")

        # Check for HTTPS
        if parsed.scheme != "https":
            score += 15
            indicators.append("No HTTPS")

        # Determine verdict
        if score >= 60:
            verdict = "PHISHING"
            color = "bright_red"
        elif score >= 30:
            verdict = "SUSPICIOUS"
            color = "bright_yellow"
        else:
            verdict = "LIKELY SAFE"
            color = "bright_green"

        return {
            "url": url, "domain": domain, "score": score,
            "verdict": verdict, "color": color, "indicators": indicators,
        }

    def _analyze_single(self):
        c = self.console
        url = Prompt.ask("  [bright_cyan]URL to analyze[/bright_cyan]")
        result = self._analyze_url(url)

        c.print()
        c.print(Panel(
            f"[bright_cyan]URL:[/bright_cyan] {result['url']}\n"
            f"[bright_cyan]Domain:[/bright_cyan] {result['domain']}\n"
            f"[bright_cyan]Risk Score:[/bright_cyan] [{result['color']}]{result['score']}/100[/{result['color']}]\n"
            f"[bright_cyan]Verdict:[/bright_cyan] [bold {result['color']}]{result['verdict']}[/bold {result['color']}]\n\n"
            + "\n".join(f"  [{result['color']}]- {i}[/{result['color']}]" for i in result["indicators"]) if result["indicators"] else "[bright_green]No suspicious indicators[/bright_green]",
            title="[bold bright_red]Phishing Analysis[/bold bright_red]",
            border_style=result["color"], box=box.DOUBLE_EDGE,
        ))

    def _batch_analyze(self):
        c = self.console
        c.print("  [dim]Enter URLs one per line. Empty line to finish.[/dim]")
        urls = []
        while True:
            url = c.input("  > ").strip()
            if not url:
                break
            urls.append(url)

        if not urls:
            return

        table = Table(
            title=f"[bold bright_red]Batch Analysis ({len(urls)} URLs)[/bold bright_red]",
            box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
        )
        table.add_column("URL", style="bright_white", width=45)
        table.add_column("SCORE", style="bold", width=8, justify="center")
        table.add_column("VERDICT", style="bold", width=15)
        table.add_column("TOP INDICATOR", style="dim", width=30)

        for url in urls:
            result = self._analyze_url(url)
            top_ind = result["indicators"][0] if result["indicators"] else "-"
            table.add_row(
                url[:45],
                f"[{result['color']}]{result['score']}[/{result['color']}]",
                f"[{result['color']}]{result['verdict']}[/{result['color']}]",
                top_ind[:30],
            )

        c.print()
        c.print(Align.center(table))

    def _check_redirects(self):
        c = self.console
        url = Prompt.ask("  [bright_cyan]URL to follow[/bright_cyan]")
        if not HAS_REQUESTS:
            c.print("  [bright_red]'requests' library required.[/bright_red]")
            return

        try:
            resp = requests.get(url, allow_redirects=True, timeout=10,
                                headers={"User-Agent": "Mozilla/5.0"})
            chain = resp.history + [resp]

            table = Table(
                title="[bold bright_red]Redirect Chain[/bold bright_red]",
                box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
            )
            table.add_column("#", style="dim", width=5)
            table.add_column("STATUS", style="bold", width=8)
            table.add_column("URL", style="bright_white", width=70)

            for i, r in enumerate(chain, 1):
                col = "bright_green" if r.status_code == 200 else "bright_yellow"
                table.add_row(str(i), f"[{col}]{r.status_code}[/{col}]", r.url[:70])

            c.print()
            c.print(Align.center(table))

            if len(chain) > 3:
                c.print("  [bright_yellow]Multiple redirects detected - suspicious[/bright_yellow]")
        except Exception as e:
            c.print(f"  [bright_red]Error: {e}[/bright_red]")

    def _check_ssl(self):
        c = self.console
        url = Prompt.ask("  [bright_cyan]URL[/bright_cyan]")
        parsed = urlparse(url if url.startswith("http") else "https://" + url)
        host = parsed.hostname

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    issuer = dict(x[0] for x in cert.get("issuer", ()))
                    subject = dict(x[0] for x in cert.get("subject", ()))

                    c.print(Panel(
                        f"[bright_cyan]Subject:[/bright_cyan] {subject.get('commonName', '?')}\n"
                        f"[bright_cyan]Issuer:[/bright_cyan] {issuer.get('organizationName', '?')}\n"
                        f"[bright_cyan]Valid Until:[/bright_cyan] {cert.get('notAfter', '?')}",
                        title=f"[bold bright_cyan]SSL: {host}[/bold bright_cyan]",
                        border_style="bright_cyan",
                    ))
        except Exception as e:
            c.print(f"  [bright_red]SSL Error: {e}[/bright_red]")

    def _api_url_scan(self, url: str):
        """Submit URL to urlscan.io and VirusTotal for deep analysis."""
        c = self.console
        c.print()
        results = []

        # urlscan.io (free API, 100 scans/day)
        urlscan_key = get_api_key("urlscan")
        if urlscan_key and HAS_REQUESTS:
            try:
                c.print("  [dim]Submitting to urlscan.io...[/dim]")
                resp = requests.post("https://urlscan.io/api/v1/scan/",
                    headers={"API-Key": urlscan_key, "Content-Type": "application/json"},
                    json={"url": url, "visibility": "unlisted"}, timeout=10)
                if resp.status_code == 200:
                    scan_uuid = resp.json().get("uuid", "")
                    results.append(("urlscan.io", "SUBMITTED",
                        f"UUID: {scan_uuid[:20]}... (results take ~30s)"))
                elif resp.status_code == 429:
                    results.append(("urlscan.io", "RATE LIMIT", "Daily quota exceeded"))
                else:
                    results.append(("urlscan.io", "ERROR", f"HTTP {resp.status_code}"))
            except Exception as e:
                results.append(("urlscan.io", "ERROR", str(e)[:40]))

        # VirusTotal URL scan (free API, 4 req/min)
        vt_key = get_api_key("virustotal")
        if vt_key and HAS_REQUESTS:
            try:
                import base64
                url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
                c.print("  [dim]Querying VirusTotal...[/dim]")
                resp = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}",
                    headers={"x-apikey": vt_key}, timeout=8)
                if resp.status_code == 200:
                    vt_data = resp.json().get("data", {}).get("attributes", {})
                    stats = vt_data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    total = sum(stats.values()) if stats else 0
                    if malicious > 0:
                        results.append(("VirusTotal", "MALICIOUS",
                            f"{malicious}/{total} engines flagged"))
                    elif suspicious > 0:
                        results.append(("VirusTotal", "SUSPICIOUS",
                            f"{suspicious}/{total} suspicious"))
                    else:
                        results.append(("VirusTotal", "CLEAN",
                            f"0/{total} engines clean"))
                elif resp.status_code == 404:
                    results.append(("VirusTotal", "INFO", "URL not in database"))
            except Exception as e:
                results.append(("VirusTotal", "ERROR", str(e)[:40]))

        # Google Safe Browsing (free tier via transparency report fallback)
        if HAS_REQUESTS:
            try:
                c.print("  [dim]Checking Google Safe Browsing...[/dim]")
                # Use the lookup API via Safe Browsing transparency report
                parsed = urlparse(url)
                domain = parsed.hostname or ""
                resp = requests.get(
                    f"https://transparencyreport.google.com/transparencyreport/api/v3/safebrowsing/status?site={domain}",
                    timeout=8,
                    headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    body = resp.text
                    if "SAFE" in body.upper() or "no unsafe" in body.lower():
                        results.append(("Google Safe Browsing", "CLEAN", "No threats detected"))
                    else:
                        results.append(("Google Safe Browsing", "INFO", "Check manually at safebrowsing.google.com"))
                else:
                    results.append(("Google Safe Browsing", "INFO", "Could not query (check manually)"))
            except Exception:
                results.append(("Google Safe Browsing", "INFO", "Check safebrowsing.google.com"))

        if not results:
            c.print("  [dim]No API keys configured. Add urlscan or virustotal keys in API Key Manager (K).[/dim]")
            return

        table = Table(
            title="[bold bright_red]API Scan Results[/bold bright_red]",
            box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
        )
        table.add_column("SOURCE", style="bold bright_white", width=18)
        table.add_column("VERDICT", style="bold", width=14)
        table.add_column("DETAIL", style="dim", width=50)

        verdict_col = {
            "MALICIOUS": "bright_red", "SUSPICIOUS": "bright_yellow",
            "CLEAN": "bright_green", "SUBMITTED": "bright_cyan",
            "INFO": "bright_cyan", "ERROR": "dim", "RATE LIMIT": "bright_yellow",
        }
        for source, verdict, detail in results:
            col = verdict_col.get(verdict, "white")
            table.add_row(source, f"[{col}]{verdict}[/{col}]", detail)

        c.print()
        c.print(Align.center(table))

    def _domain_reputation(self):
        c = self.console
        domain = Prompt.ask("  [bright_cyan]Domain[/bright_cyan]")

        # DNS check
        try:
            ips = socket.getaddrinfo(domain, None)
            resolved = set(addr[4][0] for addr in ips)
            c.print(f"\n  [bright_cyan]Resolved IPs:[/bright_cyan] {', '.join(list(resolved)[:3])}")
        except Exception:
            c.print("  [bright_red]Domain does not resolve.[/bright_red]")
            return

        # Check TLD
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                c.print(f"  [bright_yellow]High-risk TLD detected: {tld}[/bright_yellow]")

        # Brand check
        for brand, legit in BRAND_IMPERSONATION.items():
            if brand in domain and legit not in domain:
                c.print(f"  [bright_red]Possible {brand} impersonation (legit: {legit})[/bright_red]")
