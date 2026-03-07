import os
import subprocess
import urllib.request
from rich.panel import Panel
from rich.align import Align
from rich import box
from rich.prompt import Prompt
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

class LuaDecompiler:
    def __init__(self, console: Console):
        self.console = console
        self.col_neon = "#00ffcc"
        self.col_dim = "bright_black"
        self.tools_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "tools")
        self.unluac_jar = os.path.join(self.tools_dir, "unluac.jar")
        self.unluac_url = "https://sourceforge.net/projects/unluac/files/latest/download"

    def _ensure_unluac(self) -> bool:
        if os.path.exists(self.unluac_jar):
            return True
            
        self.console.print()
        self.console.print(f"  [{self.col_dim}]First run: Downloading Unluac Engine (<1MB)...[/{self.col_dim}]")
        os.makedirs(self.tools_dir, exist_ok=True)
        try:
            opener = urllib.request.build_opener()
            opener.addheaders = [('User-agent', 'Mozilla/5.0')]
            urllib.request.install_opener(opener)
            urllib.request.urlretrieve(self.unluac_url, self.unluac_jar)
            return True
        except Exception as e:
            self.console.print(f"  [bold red]✗ Failed to download unluac: {e}[/bold red]")
            return False

    def _check_and_install_java(self) -> bool:
        try:
            subprocess.run(["java", "-version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except FileNotFoundError:
            self.console.print("  [bold red]✗ Java is not installed or not in PATH.[/bold red]")
            self.console.print("  [dim]The Java Runtime Environment is strictly required for this modern decompiler.[/dim]")
            
            ans = Prompt.ask("  [bright_cyan]Would you like to automatically install Java via Winget now? (y/N)[/bright_cyan]").strip().lower()
            if ans == 'y':
                self.console.print("\n  [dim]Installing Oracle JRE via winget (requires admin prompt)...[/dim]")
                try:
                    cmd = ["winget", "install", "-e", "--id", "Oracle.JavaRuntimeEnvironment", "--accept-package-agreements", "--accept-source-agreements"]
                    subprocess.run(cmd, check=True)
                    self.console.print("  [bold green]✓ Java successfully installed![/bold green]")
                    self.console.print("  [bold yellow]Please restart Cosmos.win for paths to refresh.[/bold yellow]")
                    return False
                except Exception as e:
                    self.console.print(f"  [bold red]✗ Winget installation failed: {e}[/bold red]")
                    return False
            return False

    def run(self):
        c = self.console
        c.print()
        c.print(Align.center(Panel(
            f"[bold {self.col_neon}]✦ LUA DECOMPILER (UNLUAC) ✦[/bold {self.col_neon}]\n\n"
            f"[{self.col_dim}]Decompile Lua 5.1/5.2 compiled script bytecode (.luac) back to source.\n"
            f"Results are automatically exported to the 'exports' folder.[/{self.col_dim}]",
            border_style=self.col_neon,
            box=box.ROUNDED,
            padding=(1, 4)
        )))
        c.print()
        
        export_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "exports")
        os.makedirs(export_dir, exist_ok=True)
        
        if not self._check_and_install_java():
            c.input(f"\n  [{self.col_dim}]Press Enter to return...[/{self.col_dim}]")
            return
            
        if not self._ensure_unluac():
            c.input(f"\n  [{self.col_dim}]Press Enter to return...[/{self.col_dim}]")
            return

        while True:
            file_path = Prompt.ask(f"  [{self.col_neon}]Path to compiled .luac (or 'q' to quit)[/{self.col_neon}]").strip()
            
            if file_path.lower() == 'q':
                break
                
            if not file_path:
                continue
                
            file_path = file_path.strip('"').strip("'").strip()
            
            if not os.path.isfile(file_path):
                c.print("  [bold red]✗ File not found.[/bold red]\n")
                continue
                
            c.print(f"\n  [dim]Decompiling {os.path.basename(file_path)}...[/dim]")
            try:
                with Progress(
                    SpinnerColumn("dots2", style=self.col_neon),
                    TextColumn("[bold bright_cyan]Decompiling Lua Bytecode...[/bold bright_cyan]"),
                    console=c,
                    transient=True
                ) as prog:
                    prog.add_task("work", total=None)
                    result = subprocess.run(
                        ["java", "-jar", self.unluac_jar, file_path],
                        capture_output=True,
                        text=True,
                        encoding='utf-8',
                        errors='replace'
                    )
                
                output = result.stdout.strip()
                if not output and result.stderr:
                    c.print(f"  [bold red]Error decompiling (Unsupported Lua version?):[/bold red]\n{result.stderr}")
                    continue
                    
                if output:
                    out_name = os.path.basename(file_path) + '_decompiled.lua'
                    out_path = os.path.join(export_dir, out_name)
                    
                    with open(out_path, "w", encoding="utf-8") as f:
                        f.write(f"-- Decompiled Lua Source for {os.path.basename(file_path)}\n")
                        f.write(f"-- Generated by Cosmos.win Lua Decompiler (Unluac)\n")
                        f.write("-- " + "-" * 60 + "\n\n")
                        f.write(output)

                    with c.pager(styles=True):
                        c.print(f"[bold bright_cyan]Decompiled Output for {os.path.basename(file_path)}[/bold bright_cyan]")
                        c.print("-" * 50)
                        from rich.syntax import Syntax
                        syntax = Syntax(output, "lua", theme="monokai", line_numbers=True)
                        c.print(syntax)
                        
                c.print(f"  [bold green]✓ Decompilation finished. Exported to:[/bold green] {out_path}")
                try:
                    if os.name == 'nt':
                        os.startfile(export_dir)
                except Exception:
                    pass
                c.print()
                
            except Exception as e:
                c.print(f"  [bold red]✗ Unexpected error: {e}[/bold red]\n")
                
        c.input(f"\n  [{self.col_dim}]Press Enter to return...[/{self.col_dim}]")
