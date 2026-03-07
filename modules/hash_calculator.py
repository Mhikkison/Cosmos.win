import os
import hashlib
from rich.panel import Panel
from rich.align import Align
from rich import box
from rich.prompt import Prompt
from rich.console import Console

class HashCalculator:
    def __init__(self, console: Console):
        self.console = console
        self.col_neon = "#00ffcc"
        self.col_dim = "bright_black"

    def run(self):
        c = self.console
        c.print()
        c.print(Align.center(Panel(
            f"[bold {self.col_neon}]✦ OFFLINE HASH CALCULATOR ✦[/bold {self.col_neon}]\n\n"
            f"[{self.col_dim}]Calculate MD5, SHA-1, and SHA-256 for any local file.[/{self.col_dim}]",
            border_style=self.col_neon,
            box=box.ROUNDED,
            padding=(1, 4)
        )))
        c.print()
        
        while True:
            file_path = Prompt.ask(f"  [{self.col_neon}]Path to file (or 'q' to quit)[/{self.col_neon}]").strip()
            
            if file_path.lower() == 'q':
                break
                
            if not file_path:
                continue
                
            # Remove quotes if dragged in
            file_path = file_path.strip('"').strip("'")
            
            if not os.path.isfile(file_path):
                c.print("  [bold red]✗ File not found.[/bold red]")
                c.print()
                continue
                
            try:
                md5 = hashlib.md5()
                sha1 = hashlib.sha1()
                sha256 = hashlib.sha256()
                
                with open(file_path, "rb") as f:
                    while chunk := f.read(8192):
                        md5.update(chunk)
                        sha1.update(chunk)
                        sha256.update(chunk)
                        
                c.print()
                c.print(f"  [bright_cyan]File:[/bright_cyan] {os.path.basename(file_path)}")
                c.print(f"  [bright_cyan]Size:[/bright_cyan] {os.path.getsize(file_path)} bytes")
                c.print(f"  [bright_yellow]MD5:[/bright_yellow]    {md5.hexdigest()}")
                c.print(f"  [bright_yellow]SHA-1:[/bright_yellow]  {sha1.hexdigest()}")
                c.print(f"  [bright_yellow]SHA-256:[/bright_yellow]{sha256.hexdigest()}")
                c.print()
                
            except Exception as e:
                c.print(f"  [bold red]✗ Error reading file: {e}[/bold red]")
                c.print()
                
        c.input(f"\n  [{self.col_dim}]Press Enter to return...[/{self.col_dim}]")
