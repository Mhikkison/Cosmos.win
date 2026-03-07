"""
Universal Decompiler Engine
Integrates external tools and modern UI for comprehensive reverse engineering
Supports Java, .NET, Python, Lua, C/C++, and many more formats
"""

import os
import sys
import subprocess
import tempfile
import shutil
import json
import time
import hashlib
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from rich.panel import Panel
from rich.align import Align
from rich import box
from rich.prompt import Prompt, Confirm
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.tree import Tree
from rich.columns import Columns
from rich.text import Text
from rich.live import Live
from rich.layout import Layout

@dataclass
class DecompilerConfig:
    """Configuration for external decompiler tools"""
    name: str
    executable: str
    args: List[str]
    supported_extensions: List[str]
    description: str
    install_url: str = ""
    auto_detect: bool = True

class UniversalDecompiler:
    def __init__(self, console: Console):
        self.console = console
        self.col_neon = "#00ffcc"
        self.col_success = "#00e676"
        self.col_warn = "#ffab00"
        self.col_danger = "#ff1744"
        self.col_pink = "#ff6ec7"
        self.col_purple = "#bb86fc"
        self.col_gold = "#ffd700"
        self.col_cyan = "#4fc3f7"
        
        # Initialize decompiler configurations
        self.decompilers = self._initialize_decompilers()
        self.temp_dir = tempfile.mkdtemp(prefix="cosmos_decompiler_")
        
        # Statistics
        self.stats = {
            'files_processed': 0,
            'decompilation_success': 0,
            'external_tools_used': 0,
            'formats_supported': 0,
            'total_size_processed': 0
        }
    
    def _initialize_decompilers(self) -> Dict[str, DecompilerConfig]:
        """Initialize all supported decompiler configurations"""
        return {
            'java_cfr': DecompilerConfig(
                name="CFR Java Decompiler",
                executable="cfr.jar",
                args=["--outputdir", "{output_dir}", "{input_file}"],
                supported_extensions=[".class", ".jar"],
                description="Modern Java decompiler with excellent support",
                install_url="https://github.com/leibnitz27/cfr",
                auto_detect=True
            ),
            'java_procyon': DecompilerConfig(
                name="Procyon Java Decompiler",
                executable="procyon.jar",
                args=["-o", "{output_file}", "{input_file}"],
                supported_extensions=[".class", ".jar"],
                description="Advanced Java decompiler with lambda support",
                install_url="https://github.com/mstrobel/procyon",
                auto_detect=True
            ),
            'net_ildasm': DecompilerConfig(
                name="IL Disassembler",
                executable="ildasm.exe",
                args=["/output={output_file}", "/text", "{input_file}"],
                supported_extensions=[".exe", ".dll"],
                description=".NET IL disassembler (built-in with Visual Studio)",
                install_url="https://visualstudio.microsoft.com/",
                auto_detect=False
            ),
            'net_dnspy': DecompilerConfig(
                name="dnSpy Decompiler",
                executable="dnSpy.Console.exe",
                args=["--output", "{output_dir}", "{input_file}"],
                supported_extensions=[".exe", ".dll"],
                description="Advanced .NET decompiler and debugger",
                install_url="https://github.com/dnSpy/dnSpy",
                auto_detect=False
            ),
            'python_uncompyle6': DecompilerConfig(
                name="Uncompyle6",
                executable="uncompyle6",
                args=["-o", "{output_file}", "{input_file}"],
                supported_extensions=[".pyc", ".pyo"],
                description="Python bytecode decompiler",
                install_url="https://github.com/rocky/python-uncompyle6",
                auto_detect=True
            ),
            'python_decompile3': DecompilerConfig(
                name="Decompile3",
                executable="decompile3",
                args=["{input_file}", "-o", "{output_file}"],
                supported_extensions=[".pyc", ".pyo"],
                description="Modern Python 3.7+ decompiler",
                install_url="https://github.com/rocky/python-decompile3",
                auto_detect=True
            ),
            'lua_unluac': DecompilerConfig(
                name="Unluac",
                executable="unluac.jar",
                args=["--output={output_file}", "{input_file}"],
                supported_extensions=[".lua", ".luac"],
                description="Lua 5.1/5.2 bytecode decompiler",
                install_url="https://github.com/vi-k/unluac",
                auto_detect=True
            ),
            'c_ghidra': DecompilerConfig(
                name="Ghidra Headless",
                executable="ghidraRun",
                args=["headless", "{project_dir}", "DecompileScript", "{input_file}"],
                supported_extensions=[".exe", ".dll", ".so", ".dylib"],
                description="NSA's reverse engineering suite",
                install_url="https://github.com/NationalSecurityAgency/ghidra",
                auto_detect=False
            ),
            'c_ida_pro': DecompilerConfig(
                name="IDA Pro",
                executable="idat64",
                args=["-A", "-S\"decompile_all.py\"", "{input_file}"],
                supported_extensions=[".exe", ".dll", ".so", ".dylib"],
                description="Professional disassembler and decompiler",
                install_url="https://hex-rays.com/ida-pro/",
                auto_detect=False
            ),
            'binary_strings': DecompilerConfig(
                name="Strings Extractor",
                executable="strings",
                args=["-a", "-n", "4", "{input_file}"],
                supported_extensions=["*"],
                description="Extract human-readable strings from binaries",
                install_url="Built-in with most OS",
                auto_detect=True
            ),
            'hex_editor': DecompilerConfig(
                name="Hex Editor Integration",
                executable="hexdump",
                args=["-C", "{input_file}"],
                supported_extensions=["*"],
                description="Hexadecimal viewer and editor",
                install_url="Built-in with most OS",
                auto_detect=True
            )
        }
    
    def _detect_available_tools(self) -> List[str]:
        """Detect which decompiler tools are available"""
        available = []
        c = self.console
        
        with Progress(
            SpinnerColumn(style=f"bold {self.col_neon}"),
            TextColumn("[bold bright_white]Scanning for decompilers...[/bold bright_white]"),
            console=c,
            transient=True
        ) as progress:
            task = progress.add_task("Detecting tools...", total=len(self.decompilers))
            
            for name, config in self.decompilers.items():
                progress.update(task, description=f"Checking {config.name}...")
                
                if self._check_tool_availability(config):
                    available.append(name)
                    c.print(f"  [{self.col_success}]✓[/self.col_success] {config.name}")
                else:
                    c.print(f"  [{self.col_dim}]⚠[/self.col_dim] {config.name} (not found)")
                
                progress.advance(task)
                time.sleep(0.1)
        
        return available
    
    def _check_tool_availability(self, config: DecompilerConfig) -> bool:
        """Check if a specific tool is available"""
        try:
            # Check if executable exists in PATH
            result = subprocess.run(
                ["where" if os.name == "nt" else "which", config.executable],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return True
            
            # Check for Java JAR files
            if config.executable.endswith('.jar'):
                # Look in common locations
                jar_paths = [
                    os.path.join(os.path.dirname(__file__), "..", "tools", config.executable),
                    os.path.join(os.getcwd(), "tools", config.executable),
                    config.executable
                ]
                for jar_path in jar_paths:
                    if os.path.exists(jar_path):
                        return True
            
            # Check for built-in Windows tools
            if os.name == "nt":
                if config.executable in ["ildasm.exe", "strings.exe", "hexdump.exe"]:
                    return True
            
            return False
        except Exception:
            return False
    
    def _create_modern_ui(self) -> Layout:
        """Create a modern UI layout"""
        layout = Layout()
        
        # Create header
        header = Panel(
            f"[bold {self.col_neon}]✦ UNIVERSAL DECOMPILER ENGINE ✦[/bold {self.col_neon}]\n\n"
            f"[{self.col_dim}]Advanced reverse engineering with external tools\n"
            f"Support: Java, .NET, Python, Lua, C/C++, Binaries & more[/{self.col_dim}]",
            border_style=self.col_neon,
            box=box.ROUNDED,
            padding=(1, 4)
        )
        
        layout.split_column(
            Layout(header, size=8),
            Layout(name="main"),
            Layout(name="footer", size=3)
        )
        
        return layout
    
    def _display_tool_status(self, available_tools: List[str]):
        """Display modern tool status dashboard"""
        c = self.console
        
        # Create main table
        table = Table(
            title=f"[bold {self.col_pink}]Available Decompiler Tools[/bold {self.col_pink}]",
            box=box.ROUNDED,
            show_header=True,
            header_style=f"bold {self.col_gold}"
        )
        
        table.add_column("Tool", style=f"bold {self.col_cyan}", justify="left")
        table.add_column("Status", justify="center")
        table.add_column("Supported Formats", style=self.col_dim, justify="left")
        table.add_column("Description", style=self.col_dim, justify="left")
        
        for name, config in self.decompilers.items():
            is_available = name in available_tools
            status = f"[{self.col_success}]✓ READY[/{self.col_success}]" if is_available else f"[{self.col_danger}]✗ MISSING[/{self.col_danger}]"
            formats = ", ".join(config.supported_extensions[:3]) + ("..." if len(config.supported_extensions) > 3 else "")
            
            table.add_row(
                config.name,
                status,
                formats,
                config.description[:40] + ("..." if len(config.description) > 40 else "")
            )
        
        c.print("\n")
        c.print(Align.center(table))
        c.print()
    
    def _get_decompiler_for_file(self, file_path: str) -> Optional[str]:
        """Get the best decompiler for a given file"""
        file_ext = Path(file_path).suffix.lower()
        
        # Priority order for decompilers
        priority_map = {
            '.class': ['java_cfr', 'java_procyon'],
            '.jar': ['java_cfr', 'java_procyon'],
            '.pyc': ['python_uncompyle6', 'python_decompile3'],
            '.pyo': ['python_uncompyle6', 'python_decompile3'],
            '.lua': ['lua_unluac'],
            '.luac': ['lua_unluac'],
            '.exe': ['net_ildasm', 'net_dnspy', 'c_ghidra', 'c_ida_pro'],
            '.dll': ['net_ildasm', 'net_dnspy', 'c_ghidra', 'c_ida_pro'],
            '.so': ['c_ghidra', 'c_ida_pro'],
            '.dylib': ['c_ghidra', 'c_ida_pro']
        }
        
        if file_ext in priority_map:
            for decompiler in priority_map[file_ext]:
                if decompiler in self.decompilers:
                    return decompiler
        
        # Fallback to binary tools
        return 'binary_strings'
    
    def _run_external_decompiler(self, decompiler_name: str, input_file: str, output_dir: str) -> Tuple[bool, str]:
        """Run an external decompiler tool"""
        config = self.decompilers[decompiler_name]
        input_path = Path(input_file)
        output_path = Path(output_dir)
        
        try:
            # Prepare output file name
            output_file = output_path / f"{input_path.stem}_decompiled{input_path.suffix}"
            
            # Prepare command arguments
            args = []
            for arg in config.args:
                arg = arg.replace("{input_file}", str(input_path))
                arg = arg.replace("{output_file}", str(output_file))
                arg = arg.replace("{output_dir}", str(output_path))
                arg = arg.replace("{project_dir}", str(output_path))
                args.append(arg)
            
            # Handle Java JAR files
            if config.executable.endswith('.jar'):
                jar_path = self._find_jar_file(config.executable)
                if not jar_path:
                    return False, f"JAR file not found: {config.executable}"
                cmd = ["java", "-jar", jar_path] + args
            else:
                cmd = [config.executable] + args
            
            # Run the decompiler
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
                cwd=str(output_path)
            )
            
            if result.returncode == 0:
                # Check if output file was created
                if output_file.exists():
                    return True, str(output_file)
                else:
                    # Look for any generated files
                    generated_files = list(output_path.glob("*"))
                    if generated_files:
                        return True, str(generated_files[0])
                    else:
                        return False, "No output file generated"
            else:
                return False, f"Decompiler error: {result.stderr}"
                
        except subprocess.TimeoutExpired:
            return False, "Decompiler timeout (5 minutes)"
        except Exception as e:
            return False, f"Unexpected error: {str(e)}"
    
    def _find_jar_file(self, jar_name: str) -> Optional[str]:
        """Find a JAR file in common locations"""
        search_paths = [
            os.path.join(os.path.dirname(__file__), "..", "tools"),
            os.path.join(os.getcwd(), "tools"),
            os.getcwd(),
            os.path.dirname(__file__)
        ]
        
        for search_path in search_paths:
            jar_path = os.path.join(search_path, jar_name)
            if os.path.exists(jar_path):
                return jar_path
        
        return None
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of a file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    def run_decompilation_session(self):
        """Run the main decompilation session"""
        c = self.console
        
        # Display modern UI
        layout = self._create_modern_ui()
        c.print()
        
        # Detect available tools
        c.print(f"[{self.col_neon}]🔍 Scanning for decompiler tools...[/{self.col_neon}]")
        available_tools = self._detect_available_tools()
        
        # Display tool status
        self._display_tool_status(available_tools)
        
        if not available_tools:
            c.print(f"[{self.col_danger}]⚠ No decompiler tools found![/{self.col_danger}]")
            c.print(f"[{self.col_dim}]Please install external tools to use advanced features.[/{self.col_dim}]")
            return
        
        # Main decompilation loop
        export_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "exports", "decompiled")
        os.makedirs(export_dir, exist_ok=True)
        
        while True:
            file_path = Prompt.ask(
                f"\n[{self.col_neon}]📁 Enter file path to decompile (or 'q' to quit)[/{self.col_neon}]"
            ).strip().strip('"').strip("'")
            
            if file_path.lower() == 'q':
                break
            
            if not os.path.isfile(file_path):
                c.print(f"[{self.col_danger}]✗ File not found: {file_path}[/{self.col_danger}]")
                continue
            
            # Get file info
            file_size = os.path.getsize(file_path)
            file_hash = self._calculate_file_hash(file_path)
            file_ext = Path(file_path).suffix.lower()
            
            # Select decompiler
            decompiler = self._get_decompiler_for_file(file_path)
            if not decompiler:
                c.print(f"[{self.col_danger}]✗ No suitable decompiler found for {file_ext}[/{self.col_danger}]")
                continue
            
            config = self.decompilers[decompiler]
            
            # Display file info
            info_table = Table(box=box.ROUNDED, show_header=False)
            info_table.add_column("Property", style=f"bold {self.col_cyan}")
            info_table.add_column("Value")
            
            info_table.add_row("File", os.path.basename(file_path))
            info_table.add_row("Size", f"{file_size:,} bytes")
            info_table.add_row("Hash", file_hash[:16] + "...")
            info_table.add_row("Type", file_ext)
            info_table.add_row("Decompiler", config.name)
            
            c.print("\n")
            c.print(Align.center(info_table))
            
            # Confirm decompilation
            if not Confirm.ask(f"[{self.col_warn}]Proceed with decompilation?[/{self.col_warn}]"):
                continue
            
            # Run decompilation with progress
            c.print(f"\n[{self.col_neon}]⚡ Starting decompilation...[/{self.col_neon}]")
            
            with Progress(
                SpinnerColumn(style=f"bold {self.col_neon}"),
                TextColumn("[bold bright_white]{task.description}[/bold bright_white]"),
                BarColumn(bar_width=40, style=f"dim {self.col_blue}", complete_style=f"bold {self.col_neon}"),
                TimeElapsedColumn(),
                console=c,
                transient=True
            ) as progress:
                task = progress.add_task("Decompiling...", total=100)
                
                # Create temporary output directory
                temp_output = os.path.join(self.temp_dir, f"decompile_{int(time.time())}")
                os.makedirs(temp_output, exist_ok=True)
                
                # Run decompiler
                success, result = self._run_external_decompiler(decompiler, file_path, temp_output)
                
                progress.update(task, completed=100)
            
            # Display results
            if success:
                self.stats['decompilation_success'] += 1
                self.stats['external_tools_used'] += 1
                
                # Move results to export directory
                final_output = os.path.join(export_dir, f"{Path(file_path).stem}_decompiled")
                if os.path.exists(result):
                    if os.path.isfile(result):
                        shutil.move(result, final_output + Path(result).suffix)
                    else:
                        shutil.move(result, final_output)
                
                c.print(f"\n[{self.col_success}]✓ Decompilation successful![/{self.col_success}]")
                c.print(f"[{self.col_dim}]Output saved to: {final_output}[/{self.col_dim}]")
                
                # Try to open output directory
                try:
                    if os.name == 'nt':
                        os.startfile(export_dir)
                except Exception:
                    pass
            else:
                c.print(f"\n[{self.col_danger}]✗ Decompilation failed:[/{self.col_danger}] {result}")
            
            self.stats['files_processed'] += 1
            self.stats['total_size_processed'] += file_size
        
        # Display session statistics
        self._display_session_stats()
    
    def _display_session_stats(self):
        """Display session statistics"""
        c = self.console
        
        stats_table = Table(
            title=f"[bold {self.col_gold}]Session Statistics[/bold {self.col_gold}]",
            box=box.ROUNDED
        )
        
        stats_table.add_column("Metric", style=f"bold {self.col_pink}")
        stats_table.add_column("Value", style=f"bold {self.col_neon}")
        
        stats_table.add_row("Files Processed", str(self.stats['files_processed']))
        stats_table.add_row("Successful Decompilations", str(self.stats['decompilation_success']))
        stats_table.add_row("External Tools Used", str(self.stats['external_tools_used']))
        stats_table.add_row("Total Size Processed", f"{self.stats['total_size_processed']:,} bytes")
        stats_table.add_row("Success Rate", f"{(self.stats['decompilation_success'] / max(1, self.stats['files_processed']) * 100):.1f}%")
        
        c.print("\n")
        c.print(Align.center(stats_table))
        c.print()
    
    def cleanup(self):
        """Clean up temporary files"""
        try:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except Exception:
            pass
