"""
Enhanced Java Decompiler with External Tool Integration
Supports CFR, Procyon, Fernflower, and JD-Core with modern UI
"""

import os
import sys
import subprocess
import tempfile
import shutil
import time
from pathlib import Path
from typing import Dict, List, Tuple, Optional
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

class EnhancedJavaDecompiler:
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
        
        # Java decompiler configurations
        self.decompilers = {
            'cfr': {
                'name': 'CFR (Modern Java Decompiler)',
                'executable': 'cfr.jar',
                'args': ['--outputdir', '{output_dir}', '{input_file}'],
                'description': 'Excellent support for modern Java features',
                'website': 'https://github.com/leibnitz27/cfr',
                'supported_versions': 'Java 8 - Java 21',
                'features': ['Lambda expressions', 'Method references', 'Type annotations', 'Records', 'Pattern matching']
            },
            'procyon': {
                'name': 'Procyon Decompiler',
                'executable': 'procyon.jar',
                'args': ['-o', '{output_file}', '{input_file}'],
                'description': 'Advanced decompiler with excellent lambda support',
                'website': 'https://github.com/mstrobel/procyon',
                'supported_versions': 'Java 5 - Java 17',
                'features': ['Lambda expressions', 'Method handles', 'Type inference', 'Generic types']
            },
            'fernflower': {
                'name': 'Fernflower',
                'executable': 'fernflower.jar',
                'args': ['-dgs=1', '-rsy=1', '-rbr=1', '-dce=1', '{input_file}', '{output_dir}'],
                'description': 'IntelliJ IDEA built-in decompiler',
                'website': 'https://github.com/JetBrains/intellij-community',
                'supported_versions': 'Java 5 - Java 17',
                'features': ['Control flow analysis', 'Dead code elimination', 'Variable renaming']
            },
            'jdcore': {
                'name': 'JD-Core',
                'executable': 'jd-core.jar',
                'args': ['--outputdir', '{output_dir}', '{input_file}'],
                'description': 'Fast and reliable Java decompiler',
                'website': 'https://github.com/java-decompiler/jd-core',
                'supported_versions': 'Java 5 - Java 17',
                'features': ['High speed', 'Low memory usage', 'Accurate decompilation']
            }
        }
        
        self.stats = {
            'files_processed': 0,
            'classes_decompiled': 0,
            'methods_restored': 0,
            'errors_encountered': 0,
            'total_size_processed': 0
        }
    
    def _check_java_availability(self) -> bool:
        """Check if Java is available"""
        try:
            result = subprocess.run(['java', '-version'], capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except Exception:
            return False
    
    def _find_decompiler_jar(self, jar_name: str) -> Optional[str]:
        """Find decompiler JAR file in various locations"""
        search_paths = [
            os.path.join(os.path.dirname(__file__), "..", "tools", "java"),
            os.path.join(os.getcwd(), "tools", "java"),
            os.path.join(os.getcwd(), "tools"),
            os.path.dirname(__file__),
            os.getcwd()
        ]
        
        for search_path in search_paths:
            jar_path = os.path.join(search_path, jar_name)
            if os.path.exists(jar_path):
                return jar_path
        
        return None
    
    def _get_available_decompilers(self) -> List[str]:
        """Get list of available decompilers"""
        available = []
        
        for decompiler_id, config in self.decompilers.items():
            jar_path = self._find_decompiler_jar(config['executable'])
            if jar_path:
                available.append(decompiler_id)
        
        return available
    
    def _analyze_java_file(self, file_path: str) -> Dict:
        """Analyze Java class/JAR file"""
        file_info = {
            'path': file_path,
            'size': os.path.getsize(file_path),
            'type': 'unknown',
            'class_count': 0,
            'java_version': 'unknown',
            'is_obfuscated': False
        }
        
        file_ext = Path(file_path).suffix.lower()
        
        if file_ext == '.class':
            file_info['type'] = 'class'
            # Simple class file analysis
            try:
                with open(file_path, 'rb') as f:
                    header = f.read(8)
                    if len(header) >= 8:
                        # Check magic number CAFEBABE
                        if header[:4] == b'\\xca\\xfe\\xba\\xbe':
                            # Get minor and major version
                            minor_version = int.from_bytes(header[4:6], 'big')
                            major_version = int.from_bytes(header[6:8], 'big')
                            
                            # Map Java version numbers to versions
                            version_map = {
                                45: 'Java 1.1',
                                46: 'Java 1.2',
                                47: 'Java 1.3',
                                48: 'Java 1.4',
                                49: 'Java 5',
                                50: 'Java 6',
                                51: 'Java 7',
                                52: 'Java 8',
                                53: 'Java 9',
                                54: 'Java 10',
                                55: 'Java 11',
                                56: 'Java 12',
                                57: 'Java 13',
                                58: 'Java 14',
                                59: 'Java 15',
                                60: 'Java 16',
                                61: 'Java 17',
                                62: 'Java 18',
                                63: 'Java 19',
                                64: 'Java 20',
                                65: 'Java 21'
                            }
                            
                            file_info['java_version'] = version_map.get(major_version, f'Unknown ({major_version})')
            except Exception:
                pass
        
        elif file_ext == '.jar':
            file_info['type'] = 'jar'
            # Count classes in JAR
            try:
                result = subprocess.run(['jar', 'tf', file_path], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    class_files = [line for line in result.stdout.split('\\n') if line.strip().endswith('.class')]
                    file_info['class_count'] = len(class_files)
            except Exception:
                pass
        
        return file_info
    
    def _run_decompiler(self, decompiler_id: str, input_file: str, output_dir: str) -> Tuple[bool, str]:
        """Run specific decompiler"""
        config = self.decompilers[decompiler_id]
        jar_path = self._find_decompiler_jar(config['executable'])
        
        if not jar_path:
            return False, f"JAR file not found: {config['executable']}"
        
        try:
            # Prepare arguments
            args = []
            for arg in config['args']:
                arg = arg.replace('{input_file}', input_file)
                arg = arg.replace('{output_dir}', output_dir)
                arg = arg.replace('{output_file}', os.path.join(output_dir, f"{Path(input_file).stem}.java"))
                args.append(arg)
            
            # Run decompiler
            cmd = ['java', '-jar', jar_path] + args
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
                cwd=output_dir
            )
            
            if result.returncode == 0:
                return True, "Decompilation successful"
            else:
                return False, f"Decompiler error: {result.stderr}"
                
        except subprocess.TimeoutExpired:
            return False, "Decompiler timeout (5 minutes)"
        except Exception as e:
            return False, f"Unexpected error: {str(e)}"
    
    def _display_decompiler_comparison(self):
        """Display comparison of available decompilers"""
        available = self._get_available_decompilers()
        
        table = Table(
            title=f"[bold {self.col_pink}]Java Decompiler Comparison[/bold {self.col_pink}]",
            box=box.ROUNDED,
            show_header=True,
            header_style=f"bold {self.col_gold}"
        )
        
        table.add_column("Decompiler", style=f"bold {self.col_cyan}", justify="left")
        table.add_column("Status", justify="center")
        table.add_column("Java Support", justify="center")
        table.add_column("Key Features", style=self.col_dim, justify="left")
        
        for decompiler_id, config in self.decompilers.items():
            is_available = decompiler_id in available
            status = f"[{self.col_success}]✓ Available[/{self.col_success}]" if is_available else f"[{self.col_danger}]✗ Missing[/{self.col_danger}]"
            
            features_text = ", ".join(config['features'][:2]) + ("..." if len(config['features']) > 2 else "")
            
            table.add_row(
                config['name'],
                status,
                config['supported_versions'],
                features_text
            )
        
        self.console.print("\\n")
        self.console.print(Align.center(table))
        self.console.print()
    
    def _display_file_analysis(self, file_info: Dict):
        """Display file analysis results"""
        table = Table(
            title=f"[bold {self.col_neon}]File Analysis[/bold {self.col_neon}]",
            box=box.ROUNDED,
            show_header=False
        )
        
        table.add_column("Property", style=f"bold {self.col_cyan}")
        table.add_column("Value")
        
        table.add_row("File", os.path.basename(file_info['path']))
        table.add_row("Type", file_info['type'].upper())
        table.add_row("Size", f"{file_info['size']:,} bytes")
        table.add_row("Java Version", file_info['java_version'])
        
        if file_info['type'] == 'jar':
            table.add_row("Class Count", str(file_info['class_count']))
        
        self.console.print("\\n")
        self.console.print(Align.center(table))
        self.console.print()
    
    def run(self):
        """Run enhanced Java decompiler"""
        c = self.console
        
        # Display header
        c.print()
        c.print(Align.center(Panel(
            f"[bold {self.col_neon}]✦ ENHANCED JAVA DECOMPILER ✦[/bold {self.col_neon}]\\n\\n"
            f"[{self.col_dim}]Advanced Java decompilation with multiple engines\\n"
            f"Support for CFR, Procyon, Fernflower, and JD-Core\\n"
            f"Modern Java features: lambdas, records, pattern matching[/{self.col_dim}]",
            border_style=self.col_neon,
            box=box.ROUNDED,
            padding=(1, 4)
        )))
        
        # Check Java availability
        if not self._check_java_availability():
            c.print(f"[{self.col_danger}]✗ Java is not installed or not in PATH[/{self.col_danger}]")
            c.print(f"[{self.col_dim}]Please install Java to use the decompiler[/{self.col_dim}]")
            return
        
        # Display decompiler comparison
        self._display_decompiler_comparison()
        
        available = self._get_available_decompilers()
        if not available:
            c.print(f"[{self.col_danger}]✗ No Java decompilers found![/{self.col_danger}]")
            c.print(f"[{self.col_dim}]Please download decompiler JAR files and place them in the tools directory[/{self.col_dim}]")
            return
        
        # Main decompilation loop
        export_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "exports", "java_decompiled")
        os.makedirs(export_dir, exist_ok=True)
        
        while True:
            file_path = Prompt.ask(
                f"\\n[{self.col_neon}]📁 Enter Java file path (.class/.jar) or 'q' to quit[/{self.col_neon}]"
            ).strip().strip('"').strip("'")
            
            if file_path.lower() == 'q':
                break
            
            if not os.path.isfile(file_path):
                c.print(f"[{self.col_danger}]✗ File not found: {file_path}[/{self.col_danger}]")
                continue
            
            file_ext = Path(file_path).suffix.lower()
            if file_ext not in ['.class', '.jar']:
                c.print(f"[{self.col_danger}]✗ Unsupported file type: {file_ext}[/{self.col_danger}]")
                continue
            
            # Analyze file
            file_info = self._analyze_java_file(file_path)
            self._display_file_analysis(file_info)
            
            # Select decompiler
            if len(available) == 1:
                selected_decompiler = available[0]
                c.print(f"[{self.col_info}]Using {self.decompilers[selected_decompiler]['name']}[/{self.col_info}]")
            else:
                c.print(f"[{self.col_neon}]Available decompilers:[/{self.col_neon}]")
                for i, decompiler_id in enumerate(available, 1):
                    c.print(f"  {i}. {self.decompilers[decompiler_id]['name']}")
                
                choice = Prompt.ask(f"[{self.col_neon}]Select decompiler (1-{len(available)})[/{self.col_neon}]")
                try:
                    choice_idx = int(choice) - 1
                    if 0 <= choice_idx < len(available):
                        selected_decompiler = available[choice_idx]
                    else:
                        c.print(f"[{self.col_danger}]✗ Invalid choice[/{self.col_danger}]")
                        continue
                except ValueError:
                    c.print(f"[{self.col_danger}]✗ Invalid input[/{self.col_danger}]")
                    continue
            
            # Confirm decompilation
            if not Confirm.ask(f"[{self.col_warn}]Proceed with decompilation?[/{self.col_warn}]"):
                continue
            
            # Run decompilation with progress
            c.print(f"\\n[{self.col_neon}]⚡ Starting decompilation...[/{self.col_neon}]")
            
            with Progress(
                SpinnerColumn(style=f"bold {self.col_neon}"),
                TextColumn("[bold bright_white]{task.description}[/bold bright_white]"),
                BarColumn(bar_width=40, style=f"dim {self.col_blue}", complete_style=f"bold {self.col_neon}"),
                TimeElapsedColumn(),
                console=c,
                transient=True
            ) as progress:
                task = progress.add_task("Decompiling Java bytecode...", total=100)
                
                # Create output directory
                output_path = os.path.join(export_dir, f"{Path(file_path).stem}_decompiled")
                os.makedirs(output_path, exist_ok=True)
                
                # Run decompiler
                success, result = self._run_decompiler(selected_decompiler, file_path, output_path)
                
                progress.update(task, completed=100)
            
            # Display results
            if success:
                self.stats['files_processed'] += 1
                self.stats['classes_decompiled'] += file_info.get('class_count', 1)
                self.stats['total_size_processed'] += file_info['size']
                
                c.print(f"\\n[{self.col_success}]✓ Decompilation successful![/{self.col_success}]")
                c.print(f"[{self.col_dim}]Output saved to: {output_path}[/{self.col_dim}]")
                
                # Count generated Java files
                java_files = list(Path(output_path).rglob("*.java"))
                c.print(f"[{self.col_info}]Generated {len(java_files)} Java files[/{self.col_info}]")
                
                # Try to open output directory
                try:
                    if os.name == 'nt':
                        os.startfile(output_path)
                except Exception:
                    pass
            else:
                self.stats['errors_encountered'] += 1
                c.print(f"\\n[{self.col_danger}]✗ Decompilation failed:[/{self.col_danger}] {result}")
        
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
        stats_table.add_row("Classes Decompiled", str(self.stats['classes_decompiled']))
        stats_table.add_row("Errors Encountered", str(self.stats['errors_encountered']))
        stats_table.add_row("Total Size Processed", f"{self.stats['total_size_processed']:,} bytes")
        
        if self.stats['files_processed'] > 0:
            success_rate = ((self.stats['files_processed'] - self.stats['errors_encountered']) / self.stats['files_processed']) * 100
            stats_table.add_row("Success Rate", f"{success_rate:.1f}%")
        
        c.print("\\n")
        c.print(Align.center(stats_table))
        c.print()
