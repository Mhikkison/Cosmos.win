import base64
import binascii
from rich.panel import Panel
from rich.align import Align
from rich import box
from rich.prompt import Prompt
from rich.console import Console

class Base64HexEncoder:
    def __init__(self, console: Console):
        self.console = console
        self.col_neon = "#00ffcc"
        self.col_dim = "bright_black"

    def run(self):
        c = self.console
        
        while True:
            c.print()
            c.print(Align.center(Panel(
                f"[bold {self.col_neon}]✦ BASE64 & HEX ENCODER/DECODER ✦[/bold {self.col_neon}]\n\n"
                f"[{self.col_dim}]Offline tool to safely encode or decode text and payloads.[/{self.col_dim}]",
                border_style=self.col_neon,
                box=box.ROUNDED,
                padding=(1, 4)
            )))
            c.print()

            c.print("  [1] Base64 Encode")
            c.print("  [2] Base64 Decode")
            c.print("  [3] Hex Encode")
            c.print("  [4] Hex Decode")
            c.print("  [q] Quit to menu")
            
            choice = Prompt.ask(f"\n  [{self.col_neon}]Select mode[/{self.col_neon}]").strip().lower()
            if choice == 'q':
                break
                
            if choice not in ['1', '2', '3', '4']:
                c.print("  [bold red]Invalid choice.[/bold red]\n")
                continue
                
            text = Prompt.ask(f"  [{self.col_neon}]Enter text[/{self.col_neon}]").strip()
            if not text:
                continue
                
            c.print()
            try:
                if choice == '1':
                    res = base64.b64encode(text.encode('utf-8')).decode('utf-8')
                    c.print(f"  [bright_yellow]Base64:[/bright_yellow] {res}")
                elif choice == '2':
                    res = base64.b64decode(text).decode('utf-8')
                    c.print(f"  [bright_yellow]Decoded:[/bright_yellow] {res}")
                elif choice == '3':
                    res = binascii.hexlify(text.encode('utf-8')).decode('utf-8')
                    c.print(f"  [bright_yellow]Hex:[/bright_yellow] {res}")
                elif choice == '4':
                    res = binascii.unhexlify(text).decode('utf-8')
                    c.print(f"  [bright_yellow]Decoded:[/bright_yellow] {res}")
            except Exception as e:
                c.print(f"  [bold red]✗ Conversion error. Is the input well-formed?[/bold red]")
            
            c.input(f"\n  [{self.col_dim}]Press Enter to continue...[/{self.col_dim}]")
