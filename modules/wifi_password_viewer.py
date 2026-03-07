"""
WiFi Password Viewer — Extract saved WiFi profiles and passwords from Windows,
display security types, analyze password strength, and export profiles.
"""

import subprocess
import re
import os
import time
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box


def run_cmd(args, timeout=15):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception as e:
        return str(e)


def assess_password_strength(password: str) -> tuple[str, str]:
    """Return (strength_label, color)."""
    if not password or password == "N/A":
        return "NONE", "dim"
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
    if re.search(r'[^A-Za-z0-9]', password):
        score += 1

    if score >= 5:
        return "STRONG", "bright_green"
    elif score >= 3:
        return "FAIR", "bright_yellow"
    else:
        return "WEAK", "bright_red"


class WiFiPasswordViewer:
    def __init__(self, console: Console):
        self.console = console

    def run(self):
        c = self.console
        c.print()
        c.print(Panel(
            Align.center("[bold #ffd700]WIFI PASSWORD VIEWER[/bold #ffd700]\n"
                         "[dim]Extract saved WiFi profiles, passwords & security analysis[/dim]"),
            border_style="#ffd700", box=box.DOUBLE_EDGE,
        ))

        while True:
            c.print()
            table = Table(box=box.ROUNDED, border_style="#ffd700", header_style="bold bright_cyan")
            table.add_column("KEY", style="bold bright_yellow", justify="center", width=5)
            table.add_column("ACTION", style="bold #ffd700", width=55)
            table.add_row("1", "View all saved WiFi passwords")
            table.add_row("2", "View specific network profile")
            table.add_row("3", "WiFi password security audit")
            table.add_row("4", "Export profiles to text file")
            table.add_row("5", "Show current WiFi connection details")
            table.add_row("0", "Return to main menu")
            c.print(Align.center(table))

            choice = Prompt.ask("  [bold #ffd700]wifi[/bold #ffd700][dim]>[/dim]", default="0")

            if choice == "1":
                self._view_all()
            elif choice == "2":
                self._view_specific()
            elif choice == "3":
                self._security_audit()
            elif choice == "4":
                self._export()
            elif choice == "5":
                self._current_connection()
            elif choice == "0":
                break

    def _get_profiles(self) -> list[dict]:
        """Extract all WiFi profiles with their passwords."""
        output = run_cmd(["netsh", "wlan", "show", "profiles"])
        profiles = []

        profile_names = re.findall(r'All User Profile\s*:\s*(.+)', output)
        if not profile_names:
            profile_names = re.findall(r'Profil Tous les utilisateurs\s*:\s*(.+)', output)
        if not profile_names:
            profile_names = re.findall(r':\s*(.+)', output)
            profile_names = [p.strip() for p in profile_names if p.strip() and
                           not any(x in p.lower() for x in ["version", "guid", "type", "---"])]

        for name in profile_names:
            name = name.strip()
            if not name:
                continue

            detail = run_cmd(["netsh", "wlan", "show", "profile", name, "key=clear"])

            password = "N/A"
            pw_match = re.search(r'Key Content\s*:\s*(.+)', detail)
            if not pw_match:
                pw_match = re.search(r'Contenu de la cl.*:\s*(.+)', detail)
            if pw_match:
                password = pw_match.group(1).strip()

            auth = "?"
            auth_match = re.search(r'Authentication\s*:\s*(.+)', detail)
            if not auth_match:
                auth_match = re.search(r'Authentification\s*:\s*(.+)', detail)
            if auth_match:
                auth = auth_match.group(1).strip()

            cipher = "?"
            cipher_match = re.search(r'Cipher\s*:\s*(.+)', detail)
            if not cipher_match:
                cipher_match = re.search(r'Chiffrement\s*:\s*(.+)', detail)
            if cipher_match:
                cipher = cipher_match.group(1).strip()

            conn_mode = "?"
            mode_match = re.search(r'Connection mode\s*:\s*(.+)', detail)
            if mode_match:
                conn_mode = mode_match.group(1).strip()

            profiles.append({
                "name": name,
                "password": password,
                "auth": auth,
                "cipher": cipher,
                "connection_mode": conn_mode,
            })

        return profiles

    def _view_all(self):
        c = self.console
        c.print("\n  [dim]Extracting saved WiFi profiles...[/dim]")

        profiles = self._get_profiles()
        if not profiles:
            c.print("  [bright_yellow]No saved WiFi profiles found.[/bright_yellow]")
            return

        table = Table(
            title=f"[bold #ffd700]Saved WiFi Profiles ({len(profiles)})[/bold #ffd700]",
            box=box.DOUBLE_EDGE, border_style="#ffd700", header_style="bold bright_cyan",
        )
        table.add_column("#", style="dim", width=4, justify="center")
        table.add_column("NETWORK", style="bold bright_white", width=28)
        table.add_column("PASSWORD", style="bold bright_cyan", width=25)
        table.add_column("AUTH", style="bright_yellow", width=16)
        table.add_column("CIPHER", style="dim", width=12)
        table.add_column("STRENGTH", style="bold", width=10)

        for i, p in enumerate(profiles, 1):
            strength, s_col = assess_password_strength(p["password"])
            # Mask last 3 chars unless user reveals
            pw = p["password"]
            if pw and pw != "N/A" and len(pw) > 4:
                masked = pw[:3] + "*" * (len(pw) - 3)
            else:
                masked = pw

            table.add_row(
                str(i), p["name"][:28], masked[:25],
                p["auth"][:16], p["cipher"][:12],
                f"[{s_col}]{strength}[/{s_col}]",
            )

        c.print()
        c.print(Align.center(table))

        if Confirm.ask("\n  Show full passwords (unmasked)?", default=False):
            c.print()
            for p in profiles:
                if p["password"] and p["password"] != "N/A":
                    c.print(f"  [bright_cyan]{p['name']}[/bright_cyan]: [bold bright_white]{p['password']}[/bold bright_white]")

    def _view_specific(self):
        c = self.console
        name = Prompt.ask("  [bright_cyan]WiFi network name[/bright_cyan]")
        detail = run_cmd(["netsh", "wlan", "show", "profile", name, "key=clear"])

        if "is not found" in detail.lower() or "not found" in detail.lower():
            c.print(f"  [bright_red]Profile '{name}' not found.[/bright_red]")
            return

        c.print(Panel(
            f"[dim]{detail[:600]}[/dim]",
            title=f"[bold #ffd700]Profile: {name}[/bold #ffd700]",
            border_style="#ffd700", box=box.DOUBLE_EDGE,
        ))

    def _security_audit(self):
        c = self.console
        profiles = self._get_profiles()
        if not profiles:
            c.print("  [dim]No profiles found.[/dim]")
            return

        issues = []
        for p in profiles:
            pw = p["password"]
            auth = p["auth"].lower()

            if "open" in auth or "none" in auth:
                issues.append((p["name"], "CRITICAL", "Open network (no encryption)"))
            elif "wep" in auth:
                issues.append((p["name"], "HIGH", "WEP encryption (easily cracked)"))
            elif "wpa " in auth and "wpa2" not in auth:
                issues.append((p["name"], "MED", "WPA1 only (deprecated)"))

            if pw and pw != "N/A":
                strength, _ = assess_password_strength(pw)
                if strength == "WEAK":
                    issues.append((p["name"], "HIGH", f"Weak password ({len(pw)} chars)"))

                if pw.lower() in ["password", "12345678", "password1", "qwerty123",
                                   "admin123", "letmein", "welcome"]:
                    issues.append((p["name"], "CRITICAL", "Default/common password"))

        table = Table(
            title=f"[bold bright_red]WiFi Security Audit ({len(issues)} issues)[/bold bright_red]",
            box=box.DOUBLE_EDGE, border_style="bright_red", header_style="bold bright_cyan",
        )
        table.add_column("NETWORK", style="bold bright_white", width=28)
        table.add_column("SEVERITY", style="bold", width=12)
        table.add_column("ISSUE", style="dim", width=45)

        sev_col = {"CRITICAL": "bright_red", "HIGH": "bright_red", "MED": "bright_yellow", "LOW": "bright_green"}
        for name, sev, issue in issues:
            col = sev_col.get(sev, "white")
            table.add_row(name[:28], f"[{col}]{sev}[/{col}]", issue)

        c.print()
        if issues:
            c.print(Align.center(table))
        else:
            c.print(Panel(
                "[bold bright_green]No security issues found with saved WiFi profiles.[/bold bright_green]",
                border_style="bright_green",
            ))

        c.print(f"\n  [dim]{len(profiles)} profiles audited, {len(issues)} issues found.[/dim]")

    def _export(self):
        c = self.console
        profiles = self._get_profiles()
        if not profiles:
            c.print("  [dim]No profiles to export.[/dim]")
            return

        filename = f"wifi_profiles_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        filepath = os.path.join(os.path.expanduser("~"), "Desktop", filename)

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(f"WiFi Profiles Export - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 60 + "\n\n")
                for p in profiles:
                    f.write(f"Network: {p['name']}\n")
                    f.write(f"Password: {p['password']}\n")
                    f.write(f"Auth: {p['auth']}\n")
                    f.write(f"Cipher: {p['cipher']}\n")
                    f.write("-" * 40 + "\n\n")

            c.print(f"\n  [bold bright_green]Exported {len(profiles)} profiles to {filepath}[/bold bright_green]")
        except Exception as e:
            c.print(f"  [bright_red]Export failed: {e}[/bright_red]")

    def _current_connection(self):
        c = self.console
        output = run_cmd(["netsh", "wlan", "show", "interfaces"])

        ssid_match = re.search(r'SSID\s*:\s*(.+)', output)
        bssid_match = re.search(r'BSSID\s*:\s*(.+)', output)
        signal_match = re.search(r'Signal\s*:\s*(.+)', output)
        speed_match = re.search(r'Receive rate.*:\s*(.+)', output)
        channel_match = re.search(r'Channel\s*:\s*(.+)', output)
        auth_match = re.search(r'Authentication\s*:\s*(.+)', output)
        band_match = re.search(r'Radio type\s*:\s*(.+)', output)

        ssid = ssid_match.group(1).strip() if ssid_match else "?"
        bssid = bssid_match.group(1).strip() if bssid_match else "?"
        signal = signal_match.group(1).strip() if signal_match else "?"
        speed = speed_match.group(1).strip() if speed_match else "?"
        channel = channel_match.group(1).strip() if channel_match else "?"
        auth = auth_match.group(1).strip() if auth_match else "?"
        band = band_match.group(1).strip() if band_match else "?"

        sig_val = int(signal.replace("%", "")) if "%" in signal else 0
        sig_col = "bright_green" if sig_val > 70 else "bright_yellow" if sig_val > 40 else "bright_red"

        c.print(Panel(
            f"[bright_cyan]Network:[/bright_cyan] [bold bright_white]{ssid}[/bold bright_white]\n"
            f"[bright_cyan]BSSID:[/bright_cyan] {bssid}\n"
            f"[bright_cyan]Signal:[/bright_cyan] [{sig_col}]{signal}[/{sig_col}]\n"
            f"[bright_cyan]Speed:[/bright_cyan] {speed}\n"
            f"[bright_cyan]Channel:[/bright_cyan] {channel}\n"
            f"[bright_cyan]Auth:[/bright_cyan] {auth}\n"
            f"[bright_cyan]Band:[/bright_cyan] {band}",
            title="[bold #ffd700]Current WiFi Connection[/bold #ffd700]",
            border_style="#ffd700", box=box.DOUBLE_EDGE,
        ))
