"""
Threat Intel Lookup — Query public threat intelligence APIs for IPs, domains,
hashes, and URLs. Uses AbuseIPDB, VirusTotal, OTX, Shodan,
SecurityTrails, and local blacklists for comprehensive reputation scoring.
"""

import socket
import hashlib
import re
import os
import json
import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from utils.api_keys import get_api_key

_THREAT_CACHE = {}  # In-memory cache for API results

KNOWN_MALICIOUS_IPS = {
    "45.33.32.156": "Known scanner (Shodan)",
    "185.220.101.1": "Tor Exit Node",
    "198.51.100.1": "Documented test IP",
    "203.0.113.1": "Documented test IP",
    "23.129.64.1": "Tor Exit Node",
    "171.25.193.1": "Tor Exit Node",
}

KNOWN_MALICIOUS_DOMAINS = {
    "malware.testing.google.test": "Test malware domain",
    "evil.com": "Known phishing domain",
    "malwaretraffic.com": "Malware distribution analysis",
}

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".xyz",
    ".top", ".work", ".click", ".loan", ".racing",
    ".download", ".stream", ".bid", ".win",
}


def is_ip(value: str) -> bool:
    try:
        socket.inet_aton(value)
        return True
    except socket.error:
        return False


def is_domain(value: str) -> bool:
    return bool(re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', value))


def is_hash(value: str) -> bool:
    return bool(re.match(r'^[a-fA-F0-9]{32,64}$', value))


class ThreatIntelLookup:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        c = self.console
        while True:
            c.print()
            table = Table(
                title="[bold bright_red]Threat Intelligence Lookup[/bold bright_red]",
                header_style="bold bright_cyan", box=box.ROUNDED, expand=False
            )
            table.add_column("OPT", style="bright_yellow", justify="center")
            table.add_column("ACTION", style="bright_white")
            
            table.add_row("1", "Lookup IP Address")
            table.add_row("2", "Lookup Domain")
            table.add_row("3", "Lookup File Hash (VT/HA)")
            table.add_row("4", "Bulk Check Active Connections")
            table.add_row("5", "View Network Conn Reputation")
            table.add_row("6", "WHOIS Lookup")
            table.add_row("7", "Shodan Host Lookup")
            table.add_row("8", "SecurityTrails Domain Details")
            table.add_row("9", "Combined Full Intel Report")
            table.add_row("0", "Return to Menu")
            
            c.print(Align.center(table))
            c.print()
            
            choice = Prompt.ask("  [bold bright_red]intel[/bold bright_red][dim]>[/dim]", default="0")
            if choice == "1":
                self._lookup_ip()
            elif choice == "2":
                self._lookup_domain()
            elif choice == "3":
                self._lookup_hash()
            elif choice == "4":
                self._bulk_ip_check()
            elif choice == "5":
                self._check_connections()
            elif choice == "6":
                self._whois()
            elif choice == "7":
                self._shodan_lookup()
            elif choice == "8":
                self._securitytrails_lookup()
            elif choice == "9":
                self._combined_report()
            elif choice == "0":
                break

    def _shodan_lookup(self):
        """Query Shodan for host intelligence."""
        c = self.console
        if not HAS_REQUESTS:
            c.print("  [bright_red]'requests' library required.[/bright_red]")
            return

        shodan_key = get_api_key("shodan")
        if not shodan_key:
            c.print("  [bright_yellow]Add your Shodan API key in the API Key Manager (K).[/bright_yellow]")
            c.print("  [dim]Free key: https://account.shodan.io/register[/dim]")
            return

        target = Prompt.ask("  [bright_cyan]IP address[/bright_cyan]")
        if not is_ip(target):
            c.print("  [bright_red]Invalid IP address.[/bright_red]")
            return

        c.print(f"\n  [dim]Querying Shodan for {target}...[/dim]")

        try:
            resp = requests.get(
                f"https://api.shodan.io/shodan/host/{target}",
                params={"key": shodan_key}, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                ports = data.get("ports", [])
                vulns = data.get("vulns", [])
                org = data.get("org", "?")
                os_name = data.get("os", "?")
                country = data.get("country_name", "?")
                city = data.get("city", "?")
                isp = data.get("isp", "?")
                hostnames = data.get("hostnames", [])
                last_update = data.get("last_update", "?")

                # Main info panel
                c.print(Panel(
                    f"[bright_cyan]IP:[/bright_cyan] [bold bright_white]{target}[/bold bright_white]\n"
                    f"[bright_cyan]Organization:[/bright_cyan] {org}\n"
                    f"[bright_cyan]ISP:[/bright_cyan] {isp}\n"
                    f"[bright_cyan]Location:[/bright_cyan] {city}, {country}\n"
                    f"[bright_cyan]OS:[/bright_cyan] {os_name}\n"
                    f"[bright_cyan]Hostnames:[/bright_cyan] {', '.join(hostnames[:5]) if hostnames else 'None'}\n"
                    f"[bright_cyan]Open Ports:[/bright_cyan] {len(ports)} ({', '.join(str(p) for p in sorted(ports)[:15])})\n"
                    f"[bright_cyan]Known Vulns:[/bright_cyan] [{'bright_red' if vulns else 'bright_green'}]{len(vulns)}[/{'bright_red' if vulns else 'bright_green'}]\n"
                    f"[bright_cyan]Last Update:[/bright_cyan] {last_update}",
                    title="[bold bright_red]Shodan Intelligence[/bold bright_red]",
                    border_style="bright_red", box=box.DOUBLE_EDGE,
                ))

                # Services table
                if data.get("data"):
                    svc_table = Table(
                        title="[bold bright_cyan]Exposed Services[/bold bright_cyan]",
                        box=box.DOUBLE_EDGE, border_style="bright_cyan", header_style="bold bright_cyan",
                    )
                    svc_table.add_column("PORT", style="bright_yellow", width=8)
                    svc_table.add_column("PROTOCOL", style="bright_white", width=10)
                    svc_table.add_column("PRODUCT", style="bright_cyan", width=20)
                    svc_table.add_column("VERSION", style="dim", width=15)
                    svc_table.add_column("BANNER", style="dim", width=35)

                    for item in data["data"][:15]:
                        port = str(item.get("port", "?"))
                        transport = item.get("transport", "?")
                        product = item.get("product", "")
                        version = item.get("version", "")
                        banner = item.get("data", "")[:35].replace("\n", " ")
                        svc_table.add_row(port, transport, product[:20], version[:15], banner)

                    c.print()
                    c.print(Align.center(svc_table))

                # Vulnerabilities
                if vulns:
                    c.print(f"\n  [bold bright_red]Known Vulnerabilities ({len(vulns)}):[/bold bright_red]")
                    for v in sorted(vulns)[:20]:
                        c.print(f"    [bright_red]{v}[/bright_red]")

            elif resp.status_code == 404:
                c.print("  [bright_green]No Shodan data found for this IP.[/bright_green]")
            elif resp.status_code == 401:
                c.print("  [bright_red]Invalid Shodan API key.[/bright_red]")
            else:
                c.print(f"  [dim]Shodan returned HTTP {resp.status_code}[/dim]")
        except Exception as e:
            c.print(f"  [bright_red]Error: {e}[/bright_red]")

    def _securitytrails_lookup(self):
        """Query SecurityTrails for domain history and DNS records."""
        c = self.console
        if not HAS_REQUESTS:
            c.print("  [bright_red]'requests' library required.[/bright_red]")
            return

        st_key = get_api_key("securitytrails")
        if not st_key:
            c.print("  [bright_yellow]Add your SecurityTrails API key in the API Key Manager (K).[/bright_yellow]")
            c.print("  [dim]Free key: https://securitytrails.com/app/account[/dim]")
            return

        domain = Prompt.ask("  [bright_cyan]Domain[/bright_cyan]")
        if not is_domain(domain):
            c.print("  [bright_red]Invalid domain.[/bright_red]")
            return

        c.print(f"\n  [dim]Querying SecurityTrails for {domain}...[/dim]")

        try:
            # Domain details
            resp = requests.get(
                f"https://api.securitytrails.com/v1/domain/{domain}",
                headers={"APIKEY": st_key, "Accept": "application/json"},
                timeout=10)

            if resp.status_code == 200:
                data = resp.json()
                current_dns = data.get("current_dns", {})

                # Extract A records
                a_records = current_dns.get("a", {}).get("values", [])
                mx_records = current_dns.get("mx", {}).get("values", [])
                ns_records = current_dns.get("ns", {}).get("values", [])
                txt_records = current_dns.get("txt", {}).get("values", [])

                a_ips = [r.get("ip", "?") for r in a_records[:5]]
                mx_hosts = [r.get("hostname", "?") for r in mx_records[:5]]
                ns_hosts = [r.get("nameserver", "?") for r in ns_records[:5]]

                alexa_rank = data.get("alexa_rank")
                hostname = data.get("hostname", domain)

                c.print(Panel(
                    f"[bright_cyan]Domain:[/bright_cyan] [bold bright_white]{hostname}[/bold bright_white]\n"
                    f"[bright_cyan]A Records:[/bright_cyan] {', '.join(a_ips) if a_ips else 'None'}\n"
                    f"[bright_cyan]MX Records:[/bright_cyan] {', '.join(mx_hosts) if mx_hosts else 'None'}\n"
                    f"[bright_cyan]NS Records:[/bright_cyan] {', '.join(ns_hosts) if ns_hosts else 'None'}\n"
                    f"[bright_cyan]Alexa Rank:[/bright_cyan] {alexa_rank or 'N/A'}",
                    title="[bold bright_cyan]SecurityTrails: Domain Details[/bold bright_cyan]",
                    border_style="bright_cyan", box=box.DOUBLE_EDGE,
                ))

            # Subdomain enumeration
            sub_resp = requests.get(
                f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
                headers={"APIKEY": st_key, "Accept": "application/json"},
                timeout=10)

            if sub_resp.status_code == 200:
                sub_data = sub_resp.json()
                subdomains = sub_data.get("subdomains", [])
                if subdomains:
                    c.print(f"\n  [bold bright_cyan]Subdomains Found: {len(subdomains)}[/bold bright_cyan]")
                    sub_table = Table(box=box.ROUNDED, border_style="bright_cyan",
                                    header_style="bold bright_cyan", expand=False)
                    sub_table.add_column("#", style="dim", width=5)
                    sub_table.add_column("SUBDOMAIN", style="bold bright_white", width=50)

                    for i, sub in enumerate(subdomains[:25], 1):
                        sub_table.add_row(str(i), f"{sub}.{domain}")

                    c.print(Align.center(sub_table))
                    if len(subdomains) > 25:
                        c.print(f"  [dim]... and {len(subdomains) - 25} more[/dim]")

        except Exception as e:
            c.print(f"  [bright_red]Error: {e}[/bright_red]")

    def _combined_report(self):
        """Run IP through all available threat intel sources at once."""
        c = self.console
        target = Prompt.ask("  [bright_cyan]IP address for combined report[/bright_cyan]")
        if not is_ip(target):
            c.print("  [bright_red]Invalid IP address.[/bright_red]")
            return

        if not HAS_REQUESTS:
            c.print("  [bright_red]'requests' library required.[/bright_red]")
            return

        results = {"ip": target, "checks": []}
        sources_checked = 0

        with Progress(
            SpinnerColumn(style="bright_red"),
            TextColumn("[bold bright_red]{task.description}[/bold bright_red]"),
            BarColumn(bar_width=35),
            console=c,
        ) as progress:
            t = progress.add_task("Gathering intelligence...", total=6)

            # 1. Local blacklist
            progress.update(t, description="Checking local blacklist")
            if target in KNOWN_MALICIOUS_IPS:
                results["checks"].append(("Local Blacklist", "MALICIOUS", KNOWN_MALICIOUS_IPS[target]))
            else:
                results["checks"].append(("Local Blacklist", "CLEAN", "Not in local database"))
            progress.advance(t)

            # 2. Reverse DNS
            progress.update(t, description="Reverse DNS lookup")
            try:
                hostname = socket.gethostbyaddr(target)[0]
                results["checks"].append(("Reverse DNS", "INFO", hostname))
            except Exception:
                results["checks"].append(("Reverse DNS", "INFO", "No PTR record"))
            progress.advance(t)

            # 3. AbuseIPDB
            progress.update(t, description="Querying AbuseIPDB")
            abuseipdb_key = get_api_key("abuseipdb")
            if abuseipdb_key:
                try:
                    resp = requests.get("https://api.abuseipdb.com/api/v2/check",
                        params={"ipAddress": target, "maxAgeInDays": 90},
                        headers={"Accept": "application/json", "Key": abuseipdb_key},
                        timeout=5)
                    if resp.status_code == 200:
                        data = resp.json().get("data", {})
                        score = data.get("abuseConfidenceScore", 0)
                        reports = data.get("totalReports", 0)
                        country = data.get("countryCode", "?")
                        verdict = "MALICIOUS" if score > 50 else "SUSPICIOUS" if score > 20 else "LOW RISK"
                        results["checks"].append(("AbuseIPDB", verdict,
                            f"Confidence: {score}% | Reports: {reports} | Country: {country}"))
                        sources_checked += 1
                except Exception:
                    results["checks"].append(("AbuseIPDB", "ERROR", "Connection failed"))
            progress.advance(t)

            # 4. VirusTotal
            progress.update(t, description="Querying VirusTotal")
            vt_key = get_api_key("virustotal")
            if vt_key:
                try:
                    resp = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{target}",
                        headers={"x-apikey": vt_key}, timeout=8)
                    if resp.status_code == 200:
                        vt_data = resp.json().get("data", {}).get("attributes", {})
                        stats = vt_data.get("last_analysis_stats", {})
                        malicious = stats.get("malicious", 0)
                        total = sum(stats.values()) if stats else 0
                        verdict = "MALICIOUS" if malicious > 0 else "CLEAN"
                        results["checks"].append(("VirusTotal", verdict,
                            f"{malicious}/{total} engines flagged"))
                        sources_checked += 1
                except Exception:
                    results["checks"].append(("VirusTotal", "ERROR", "Connection failed"))
            progress.advance(t)

            # 5. Shodan
            progress.update(t, description="Querying Shodan")
            shodan_key = get_api_key("shodan")
            if shodan_key:
                try:
                    resp = requests.get(f"https://api.shodan.io/shodan/host/{target}",
                        params={"key": shodan_key}, timeout=10)
                    if resp.status_code == 200:
                        sh = resp.json()
                        ports = sh.get("ports", [])
                        vulns = sh.get("vulns", [])
                        verdict = "SUSPICIOUS" if vulns else "INFO"
                        results["checks"].append(("Shodan", verdict,
                            f"Ports: {len(ports)} | Vulns: {len(vulns)} | Org: {sh.get('org', '?')}"))
                        sources_checked += 1
                    elif resp.status_code == 404:
                        results["checks"].append(("Shodan", "CLEAN", "Not indexed (low exposure)"))
                except Exception:
                    pass
            progress.advance(t)

            # 6. OTX
            progress.update(t, description="Querying AlienVault OTX")
            otx_key = get_api_key("otx")
            if otx_key:
                try:
                    resp = requests.get(
                        f"https://otx.alienvault.com/api/v1/indicators/IPv4/{target}/general",
                        headers={"X-OTX-API-KEY": otx_key}, timeout=5)
                    if resp.status_code == 200:
                        otx = resp.json()
                        pulse_count = otx.get("pulse_info", {}).get("count", 0)
                        verdict = "MALICIOUS" if pulse_count > 5 else "SUSPICIOUS" if pulse_count > 0 else "CLEAN"
                        results["checks"].append(("AlienVault OTX", verdict,
                            f"Threat pulses: {pulse_count}"))
                        sources_checked += 1
                except Exception:
                    pass
            progress.advance(t)

        # Overall threat score
        malicious_count = sum(1 for _, v, _ in results["checks"] if v == "MALICIOUS")
        suspicious_count = sum(1 for _, v, _ in results["checks"] if v == "SUSPICIOUS")
        overall_score = malicious_count * 30 + suspicious_count * 15
        overall_score = min(100, overall_score)

        if overall_score >= 60:
            grade, grade_col = "CRITICAL THREAT", "bright_red"
        elif overall_score >= 30:
            grade, grade_col = "SUSPICIOUS", "bright_yellow"
        else:
            grade, grade_col = "LOW RISK", "bright_green"

        c.print(Panel(
            f"[bright_cyan]Target:[/bright_cyan] [bold bright_white]{target}[/bold bright_white]\n"
            f"[bright_cyan]Sources Queried:[/bright_cyan] {sources_checked + 2}\n"
            f"[bright_cyan]Malicious Flags:[/bright_cyan] [bright_red]{malicious_count}[/bright_red]\n"
            f"[bright_cyan]Suspicious Flags:[/bright_cyan] [bright_yellow]{suspicious_count}[/bright_yellow]\n\n"
            f"[bright_cyan]Overall Assessment:[/bright_cyan] [bold {grade_col}]{grade} ({overall_score}/100)[/bold {grade_col}]",
            title="[bold bright_red]Combined Threat Intelligence Report[/bold bright_red]",
            border_style=grade_col, box=box.DOUBLE_EDGE,
        ))

        self._display_results(results)


    def _lookup_ip(self):
        c = self.console
        ip = Prompt.ask("  [bright_cyan]IP address[/bright_cyan]")
        if not is_ip(ip):
            c.print("  [bright_red]Invalid IP address.[/bright_red]")
            return

        results = {"ip": ip, "checks": []}

        # Local blacklist check
        if ip in KNOWN_MALICIOUS_IPS:
            results["checks"].append(("Local Blacklist", "MALICIOUS", KNOWN_MALICIOUS_IPS[ip]))
        else:
            results["checks"].append(("Local Blacklist", "CLEAN", "Not in local database"))

        # Reverse DNS
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            results["checks"].append(("Reverse DNS", "INFO", hostname))
        except Exception:
            results["checks"].append(("Reverse DNS", "INFO", "No PTR record"))

        # AbuseIPDB (uses API key from vault if available)
        if HAS_REQUESTS:
            abuseipdb_key = get_api_key("abuseipdb")
            try:
                headers = {"Accept": "application/json"}
                if abuseipdb_key:
                    headers["Key"] = abuseipdb_key
                resp = requests.get(f"https://api.abuseipdb.com/api/v2/check",
                                    params={"ipAddress": ip, "maxAgeInDays": 90},
                                    headers=headers,
                                    timeout=5)
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    score = data.get("abuseConfidenceScore", 0)
                    reports = data.get("totalReports", 0)
                    country = data.get("countryCode", "?")
                    isp = data.get("isp", "?")
                    usage = data.get("usageType", "?")
                    if score > 50:
                        results["checks"].append(("AbuseIPDB", "MALICIOUS",
                            f"Confidence: {score}% | Reports: {reports} | Country: {country}"))
                    elif score > 20:
                        results["checks"].append(("AbuseIPDB", "SUSPICIOUS",
                            f"Confidence: {score}% | Reports: {reports} | Country: {country}"))
                    else:
                        results["checks"].append(("AbuseIPDB", "LOW RISK",
                            f"Confidence: {score}% | Reports: {reports}"))
                    results["checks"].append(("AbuseIPDB ISP", "INFO", f"{isp} ({usage})"))
                elif resp.status_code == 401:
                    results["checks"].append(("AbuseIPDB", "SKIP", "Invalid or missing API key (add in K menu)"))
                else:
                    results["checks"].append(("AbuseIPDB", "ERROR", f"HTTP {resp.status_code}"))
            except Exception:
                results["checks"].append(("AbuseIPDB", "ERROR", "Connection failed"))

        # VirusTotal IP report (uses API key from vault)
        if HAS_REQUESTS:
            vt_key = get_api_key("virustotal")
            if vt_key:
                try:
                    resp = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                                        headers={"x-apikey": vt_key}, timeout=8)
                    if resp.status_code == 200:
                        vt_data = resp.json().get("data", {}).get("attributes", {})
                        stats = vt_data.get("last_analysis_stats", {})
                        malicious = stats.get("malicious", 0)
                        suspicious = stats.get("suspicious", 0)
                        total = sum(stats.values()) if stats else 0
                        reputation = vt_data.get("reputation", 0)
                        if malicious > 0:
                            results["checks"].append(("VirusTotal", "MALICIOUS",
                                f"{malicious}/{total} engines flagged | Rep: {reputation}"))
                        elif suspicious > 0:
                            results["checks"].append(("VirusTotal", "SUSPICIOUS",
                                f"{suspicious}/{total} suspicious | Rep: {reputation}"))
                        else:
                            results["checks"].append(("VirusTotal", "CLEAN",
                                f"0/{total} engines flagged | Rep: {reputation}"))
                    elif resp.status_code == 401:
                        results["checks"].append(("VirusTotal", "SKIP", "Invalid API key"))
                except Exception:
                    results["checks"].append(("VirusTotal", "ERROR", "Connection failed"))

        # OTX AlienVault (free, uses API key from vault)
        if HAS_REQUESTS:
            otx_key = get_api_key("otx")
            if otx_key:
                try:
                    resp = requests.get(
                        f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/reputation",
                        headers={"X-OTX-API-KEY": otx_key}, timeout=5)
                    if resp.status_code == 200:
                        otx_data = resp.json()
                        reputation = otx_data.get("reputation", {})
                        threat_score = reputation.get("threat_score", 0) if reputation else 0
                        if threat_score and threat_score > 3:
                            results["checks"].append(("AlienVault OTX", "MALICIOUS",
                                f"Threat score: {threat_score}"))
                        else:
                            results["checks"].append(("AlienVault OTX", "CLEAN",
                                f"Threat score: {threat_score}"))
                except Exception:
                    pass

        self._display_results(results)

    def _lookup_domain(self):
        c = self.console
        domain = Prompt.ask("  [bright_cyan]Domain[/bright_cyan]")

        results = {"ip": domain, "checks": []}

        # TLD check
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                results["checks"].append(("TLD Analysis", "SUSPICIOUS", f"High-risk TLD: {tld}"))
                break
        else:
            results["checks"].append(("TLD Analysis", "CLEAN", "Standard TLD"))

        # Local blacklist
        if domain.lower() in KNOWN_MALICIOUS_DOMAINS:
            results["checks"].append(("Local Blacklist", "MALICIOUS", KNOWN_MALICIOUS_DOMAINS[domain.lower()]))
        else:
            results["checks"].append(("Local Blacklist", "CLEAN", "Not in local database"))

        # DNS resolution
        try:
            ips = socket.getaddrinfo(domain, None)
            resolved = set(addr[4][0] for addr in ips)
            results["checks"].append(("DNS Resolution", "INFO", ", ".join(list(resolved)[:3])))
            for ip in resolved:
                if ip in KNOWN_MALICIOUS_IPS:
                    results["checks"].append(("IP Check", "MALICIOUS", f"{ip}: {KNOWN_MALICIOUS_IPS[ip]}"))
        except Exception:
            results["checks"].append(("DNS Resolution", "ERROR", "Could not resolve"))

        self._display_results(results)

    def _lookup_hash(self):
        c = self.console
        hash_val = Prompt.ask("  [bright_cyan]File hash (MD5/SHA1/SHA256)[/bright_cyan]")
        if not is_hash(hash_val):
            c.print("  [bright_red]Invalid hash format.[/bright_red]")
            return

        results = {"ip": hash_val[:32] + "...", "checks": []}
        results["checks"].append(("Hash Length", "INFO",
                                  f"{'MD5' if len(hash_val) == 32 else 'SHA1' if len(hash_val) == 40 else 'SHA256'} ({len(hash_val)} chars)"))

        # Check against local known hashes
        from modules.luckyware_scanner import KNOWN_MALWARE_HASHES
        if hash_val.lower() in KNOWN_MALWARE_HASHES:
            results["checks"].append(("Local Database", "MALICIOUS", KNOWN_MALWARE_HASHES[hash_val.lower()]))
        else:
            results["checks"].append(("Local Database", "CLEAN", "Not in local malware database"))

        # VirusTotal hash lookup
        if HAS_REQUESTS:
            vt_key = get_api_key("virustotal")
            if vt_key:
                try:
                    resp = requests.get(f"https://www.virustotal.com/api/v3/files/{hash_val}",
                                        headers={"x-apikey": vt_key}, timeout=8)
                    if resp.status_code == 200:
                        vt_data = resp.json().get("data", {}).get("attributes", {})
                        stats = vt_data.get("last_analysis_stats", {})
                        malicious = stats.get("malicious", 0)
                        total = sum(stats.values()) if stats else 0
                        name = vt_data.get("meaningful_name", vt_data.get("type_description", "?"))
                        if malicious > 0:
                            results["checks"].append(("VirusTotal", "MALICIOUS",
                                f"{malicious}/{total} detections | {name}"))
                        else:
                            results["checks"].append(("VirusTotal", "CLEAN",
                                f"0/{total} detections | {name}"))
                    elif resp.status_code == 404:
                        results["checks"].append(("VirusTotal", "INFO", "Hash not found in VT database"))
                except Exception:
                    results["checks"].append(("VirusTotal", "ERROR", "Connection failed"))

        # Hybrid Analysis hash lookup
        if HAS_REQUESTS:
            ha_key = get_api_key("hybridanalysis")
            if ha_key:
                try:
                    resp = requests.post(
                        "https://www.hybrid-analysis.com/api/v2/search/hash",
                        headers={"api-key": ha_key, "User-Agent": "Falcon Sandbox"},
                        data={"hash": hash_val}, timeout=8)
                    if resp.status_code == 200:
                        ha_data = resp.json()
                        if ha_data and len(ha_data) > 0:
                            verdict = ha_data[0].get("verdict", "unknown")
                            threat_score = ha_data[0].get("threat_score", 0)
                            if verdict == "malicious":
                                results["checks"].append(("Hybrid Analysis", "MALICIOUS",
                                    f"Score: {threat_score}/100 | {verdict}"))
                            else:
                                results["checks"].append(("Hybrid Analysis", "INFO",
                                    f"Score: {threat_score}/100 | {verdict}"))
                        else:
                            results["checks"].append(("Hybrid Analysis", "INFO", "Not found"))
                except Exception:
                    pass

        self._display_results(results)

    def _bulk_ip_check(self):
        c = self.console
        import psutil
        connections = psutil.net_connections(kind="inet")
        remote_ips = set()
        for conn in connections:
            if conn.raddr and conn.status == "ESTABLISHED":
                remote_ips.add(conn.raddr.ip)

        if not remote_ips:
            c.print("  [dim]No active outbound connections found.[/dim]")
            return

        table = Table(
            title=f"[bold bright_red]Bulk IP Reputation ({len(remote_ips)} IPs)[/bold bright_red]",
            box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
        )
        table.add_column("IP", style="bold bright_white", width=18)
        table.add_column("HOSTNAME", style="dim", width=30)
        table.add_column("STATUS", style="bold", width=14)
        table.add_column("NOTE", style="dim", width=30)

        for ip in sorted(remote_ips):
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = "N/A"

            if ip in KNOWN_MALICIOUS_IPS:
                status = "[bright_red]MALICIOUS[/bright_red]"
                note = KNOWN_MALICIOUS_IPS[ip]
            elif ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
                status = "[bright_green]PRIVATE[/bright_green]"
                note = "Local network"
            else:
                status = "[bright_green]CLEAN[/bright_green]"
                note = ""

            table.add_row(ip, hostname[:30], status, note[:30])

        c.print()
        c.print(Align.center(table))

    def _check_connections(self):
        c = self.console
        import psutil
        connections = psutil.net_connections(kind="inet")

        table = Table(
            title="[bold bright_red]Current Network Connections[/bold bright_red]",
            box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
        )
        table.add_column("PID", style="bright_yellow", width=8)
        table.add_column("PROCESS", style="bold bright_white", width=20)
        table.add_column("LOCAL", style="dim", width=22)
        table.add_column("REMOTE", style="bright_cyan", width=22)
        table.add_column("STATUS", style="bold", width=14)

        shown = 0
        for conn in connections:
            if conn.status != "ESTABLISHED" or not conn.raddr:
                continue
            try:
                proc_name = psutil.Process(conn.pid).name() if conn.pid else "?"
            except Exception:
                proc_name = "?"

            local = f"{conn.laddr.ip}:{conn.laddr.port}"
            remote = f"{conn.raddr.ip}:{conn.raddr.port}"
            remote_ip = conn.raddr.ip

            if remote_ip in KNOWN_MALICIOUS_IPS:
                status = "[bright_red]SUSPICIOUS[/bright_red]"
            else:
                status = "[bright_green]OK[/bright_green]"

            table.add_row(str(conn.pid or "?"), proc_name[:20], local, remote, status)
            shown += 1
            if shown >= 50:
                break

        c.print()
        c.print(Align.center(table))

    def _whois(self):
        c = self.console
        target = Prompt.ask("  [bright_cyan]IP or domain[/bright_cyan]")
        if not HAS_REQUESTS:
            c.print("  [bright_red]'requests' library required for WHOIS lookup.[/bright_red]")
            return

        try:
            resp = requests.get(f"https://whois.arin.net/rest/ip/{target}.json",
                                headers={"Accept": "application/json"}, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                net = data.get("net", {})
                c.print(Panel(
                    f"[bright_cyan]Name:[/bright_cyan] {net.get('name', {}).get('$', 'N/A')}\n"
                    f"[bright_cyan]Handle:[/bright_cyan] {net.get('handle', {}).get('$', 'N/A')}\n"
                    f"[bright_cyan]Ref:[/bright_cyan] {net.get('ref', {}).get('$', 'N/A')}\n"
                    f"[bright_cyan]Start:[/bright_cyan] {net.get('startAddress', {}).get('$', 'N/A')}\n"
                    f"[bright_cyan]End:[/bright_cyan] {net.get('endAddress', {}).get('$', 'N/A')}",
                    title="[bold bright_red]WHOIS Result[/bold bright_red]",
                    border_style="bright_red",
                ))
            else:
                c.print(f"  [dim]WHOIS lookup returned HTTP {resp.status_code}[/dim]")
        except Exception as e:
            c.print(f"  [bright_red]Error: {e}[/bright_red]")

    def _display_results(self, results: dict):
        c = self.console
        table = Table(
            title=f"[bold bright_red]Threat Intel: {results['ip']}[/bold bright_red]",
            box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
        )
        table.add_column("SOURCE", style="bold bright_white", width=20)
        table.add_column("VERDICT", style="bold", width=14)
        table.add_column("DETAIL", style="dim", width=45)

        verdict_col = {
            "MALICIOUS": "bright_red", "SUSPICIOUS": "bright_yellow",
            "CLEAN": "bright_green", "LOW RISK": "bright_green",
            "INFO": "bright_cyan", "ERROR": "dim", "SKIP": "dim",
        }

        for source, verdict, detail in results["checks"]:
            col = verdict_col.get(verdict, "white")
            table.add_row(source, f"[{col}]{verdict}[/{col}]", detail[:45])

        c.print()
        c.print(Align.center(table))
        c.print()
        
        # Cache the results
        _THREAT_CACHE[results["ip"]] = results

        # Export Prompt
        export = Prompt.ask("  [bright_cyan]Export results to file? (y/N)[/bright_cyan]", default="N").strip().lower()
        if export == "y":
            filename = f"threat_report_{results['ip'].replace('.', '_').replace(':', '_')}.txt"
            try:
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(f"=== THREAT INTEL REPORT: {results['ip']} ===\n")
                    f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                    for src, verd, det in results["checks"]:
                        f.write(f"[{src}] {verd}: {det}\n")
                c.print(f"  [bold bright_green]✓ Exported to {filename}[/bold bright_green]")
                time.sleep(1)
            except Exception as e:
                c.print(f"  [bold bright_red]✗ Error exporting: {e}[/bold bright_red]")
                time.sleep(1)
