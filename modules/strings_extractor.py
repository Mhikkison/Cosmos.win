import os
import re
import string
from rich.panel import Panel
from rich.align import Align
from rich import box
from rich.prompt import Prompt
from rich.console import Console

class StringsExtractor:
    def __init__(self, console: Console):
        self.console = console
        self.col_neon = "#00ffcc"
        self.col_dim = "bright_black"

    def _extract_strings(self, data: bytes, min_len=4) -> list:
        # Match standard printable ascii sequences
        # Not using standard Regex because python regex on raw bytes can be slow/annoying
        result = []
        current_str = bytearray()
        
        for b in data:
            if 32 <= b <= 126 or b in (9, 10, 13): # Printable ASCII + tab/newlines
                current_str.append(b)
            else:
                if len(current_str) >= min_len:
                    try:
                        result.append(current_str.decode('ascii'))
                    except Exception:
                        pass
                current_str = bytearray()
                
        if len(current_str) >= min_len:
            try:
                result.append(current_str.decode('ascii'))
            except Exception:
                pass
                
        return result

    def run(self):
        c = self.console
        c.print()
        c.print(Align.center(Panel(
            f"[bold {self.col_neon}]✦ STRINGS EXTRACTOR (BINARIES) ✦[/bold {self.col_neon}]\n\n"
            f"[{self.col_dim}]Extract hidden human-readable text strings from Compiled Binaries,\n"
            f"PE Executables (.exe), DLLs, or Memory Dumps.[/{self.col_dim}]",
            border_style=self.col_neon,
            box=box.ROUNDED,
            padding=(1, 4)
        )))
        c.print()
        
        export_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "exports")
        os.makedirs(export_dir, exist_ok=True)

        while True:
            file_path = Prompt.ask(f"  [{self.col_neon}]Path to binary file (or 'q' to quit)[/{self.col_neon}]").strip()
            
            if file_path.lower() == 'q':
                break
                
            if not file_path:
                continue
                
            file_path = file_path.strip('"').strip("'").strip()
            
            if not os.path.isfile(file_path):
                c.print("  [bold red]✗ File not found.[/bold red]\n")
                continue
                
            c.print(f"\n  [dim]Extracting ASCII and Unicode strings from {os.path.basename(file_path)}...[/dim]")
            try:
                with open(file_path, "rb") as f:
                    data = f.read()
                    
                strings = self._extract_strings(data, min_len=5)
                
                if not strings:
                    c.print("  [bold yellow]No readable strings found in this file.[/bold yellow]\n")
                    continue
                    
                # Export it
                out_name = os.path.basename(file_path) + '_strings.txt'
                out_path = os.path.join(export_dir, out_name)
                
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write(f"Strings extraction for {os.path.basename(file_path)}\n")
                    f.write(f"Total entries: {len(strings)}\n")
                    f.write("-" * 50 + "\n\n")
                    f.write("\n".join(strings))
                    
                c.print(f"  [bold green]✓ Found {len(strings)} strings. Exported to:[/bold green] {out_path}")
                try:
                    if os.name == 'nt':
                        os.startfile(export_dir)
                except Exception:
                    pass
                c.print()
                    
            except Exception as e:
                c.print(f"  [bold red]✗ Unexpected error reading file: {e}[/bold red]\n")
                
        c.input(f"\n  [{self.col_dim}]Press Enter to return...[/{self.col_dim}]")
