import os
import re
import base64
import ast
import zlib
import json
import hashlib
import time
import random
import string
from typing import Dict, List, Tuple, Optional
from rich.panel import Panel
from rich.align import Align
from rich import box
from rich.prompt import Prompt
from rich.console import Console
from rich.syntax import Syntax
from rich.progress import (
    Progress, SpinnerColumn, BarColumn, TextColumn, 
    TimeElapsedColumn, TaskProgressColumn
)
from rich.table import Table
from rich.tree import Tree

class LuaDeobfuscator:
    def __init__(self, console: Console):
        self.console = console
        self.col_neon = "#00ffcc"
        self.col_dim = "bright_black"
        self.col_success = "#00e676"
        self.col_warn = "#ffab00"
        self.col_danger = "#ff1744"
        self.col_pink = "#ff6ec7"
        self.col_purple = "#bb86fc"
        self.col_gold = "#ffd700"
        self.detection_stats = {
            'luraph_patterns': 0,
            'moonsec_patterns': 0,
            'wearedevs_patterns': 0,
            'generic_obfuscation': 0,
            'strings_decoded': 0,
            'functions_restored': 0
        }

    def _beautify(self, source: str) -> str:
        # Extremely basic heuristic beautifier for Lua one-liners
        # Adds newlines after end, local, function
        source = re.sub(r'(\bend\b)', r'\1\n', source)
        source = re.sub(r'(\bfunction\b)', r'\n\1', source)
        source = re.sub(r'(\blocal\b)', r'\n\1', source)
        source = re.sub(r';', r';\n', source)
        
        # Fix multiple newlines
        source = re.sub(r'\n+', '\n', source)
        
        # Basic indentation
        lines = source.split('\n')
        indented = []
        indent = 0
        for line in lines:
            line = line.strip()
            if not line: continue
            
            if re.match(r'^(end|else|elseif|until)\b', line):
                indent = max(0, indent - 1)
                
            indented.append(("    " * indent) + line)
            
            if re.search(r'\b(then|do|repeat|function\s*\(.*\)|function\s+\w+\(.*\)|\bif\b.*?\bthen\b|\bfor\b.*?\bdo\b|\bwhile\b.*?\bdo\b)\s*$', line) and not re.search(r'\bend\b', line):
                indent += 1
                
        return "\n".join(indented)

    def _constant_folding(self, source: str) -> str:
        # 1. Decode string.char(\104, \101...) or string.char(104, 101...)
        def eval_string_char(match):
            chars = match.group(1).split(',')
            res = ""
            for c in chars:
                c = c.strip()
                if not c: continue
                # Handle \104 format
                if c.startswith('\\'):
                    try:
                        res += chr(int(c[1:]))
                    except: pass
                else:
                    # Handle math eval: (104+5-5)
                    try:
                        clean_math = re.sub(r'[^0-9+\-*/().]', '', c)
                        if clean_math:
                            val = int(eval(clean_math))
                            res += chr(val)
                    except: pass
            return f'"{res}"'

        source = re.sub(r'string\.char\((.*?)\)', eval_string_char, source)
        
        # 2. Decode hex strings like \x68\x65\x6c\x6c\x6f
        def eval_hex_string(match):
            try:
                # python string-escape or direct eval can decode \x
                raw = match.group(0).encode('utf-8').decode('unicode_escape')
                return raw
            except:
                return match.group(0)
                
        source = re.sub(r'"(\\x[0-9a-fA-F]{2})+"', eval_hex_string, source)
        source = re.sub(r"'(\\x[0-9a-fA-F]{2})+'", eval_hex_string, source)

        return source

    def _attempt_unwrap_base64(self, source: str) -> str:
        # Search for long base64-like strings that might be wrapped payloads
        # We look for large blocks of base64 inside quotes
        matches = re.findall(r'["\']([A-Za-z0-9+/=]{100,})["\']', source)
        for b64 in matches:
            try:
                decoded = base64.b64decode(b64).decode('utf-8')
                # If the decoded string looks like Lua code
                if "local" in decoded or "function" in decoded or "print" in decoded or "game" in decoded:
                    return f"-- [DEOBFUSCATOR] Found & Extracted Base64 Payload:\n\n{decoded}"
            except Exception:
                pass
        return source

    def _deobfuscate(self, source: str) -> str:
        # Step 1: Attempt to extract hidden payloads
        unwrapped = self._attempt_unwrap_base64(source)
        
        # Step 2: Constant folding (reveal hidden strings)
        folded = self._constant_folding(unwrapped)
        
        # Step 3: Beautify / re-format line jumps
        beautified = self._beautify(folded)
        
        return beautified

    def run(self):
        c = self.console
        c.print()
        c.print(Align.center(Panel(
            f"[bold {self.col_neon}]✦ LUA DEOBFUSCATOR ✦[/bold {self.col_neon}]\n\n"
            f"[{self.col_dim}]Premium deobfuscation engine for Lua scripts\n"
            f"Supports: Luraph, Moonsec V3, Wearedevs + universal patterns\n"
            f"Advanced string restoration, control flow analysis & beautification[/{self.col_dim}]",
            border_style=self.col_neon,
            box=box.ROUNDED,
            padding=(1, 4)
        )))
        c.print()
        
        export_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "exports")
        os.makedirs(export_dir, exist_ok=True)

        while True:
            file_path = Prompt.ask(f"  [{self.col_neon}]Path to obfuscated Lua source (or 'q' to quit)[/{self.col_neon}]").strip()
            
            if file_path.lower() == 'q':
                break
                
            if not file_path:
                continue
                
            file_path = file_path.strip('"').strip("'").strip()
            
            if not os.path.isfile(file_path):
                c.print("  [bold red]✗ File not found.[/bold red]\n")
                continue
                
            c.print(f"\n  [dim]Analyzing & Deobfuscating {os.path.basename(file_path)}...[/dim]")
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    source = f.read()
                    
                # Start premium deobfuscation with progress bar
                processed, stats = self._premium_deobfuscate_with_progress(source, os.path.basename(file_path))
                
                out_name = os.path.basename(file_path).replace('.lua', '') + '_deobfuscated.lua'
                out_path = os.path.join(export_dir, out_name)
                
                # Generate comprehensive report
                report = self._generate_deobfuscation_report(stats, os.path.basename(file_path))
                
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write(report)
                    f.write("\n\n")
                    f.write(processed)
                
                # Display results with stats
                self._display_deobfuscation_results(stats, out_path, os.path.basename(file_path))
                    
            except Exception as e:
                c.print(f"  [bold red]✗ Unexpected error during analysis: {e}[/bold red]\n")
                
    def _premium_deobfuscate_with_progress(self, source: str, filename: str) -> Tuple[str, Dict]:
        """Premium deobfuscation with progress tracking and detailed logging"""
        c = self.console
        stats = dict(self.detection_stats)
        
        with Progress(
            SpinnerColumn(style=f"bold {self.col_neon}"),
            TextColumn("[bold bright_white]Deobfuscating{task.description}[/bold bright_white]"),
            BarColumn(bar_width=40, style=f"dim {self.col_blue}", complete_style=f"bold {self.col_neon}"),
            TaskProgressColumn(text_format="[bold bright_yellow]{task.percentage:>3.0f}%[/bold bright_yellow]"),
            TimeElapsedColumn(),
            console=c,
            transient=True
        ) as progress:
            
            # Phase 1: Obfuscator Detection
            task1 = progress.add_task(" - Detecting obfuscator type...", total=100)
            detected_types = self._detect_obfuscator_type(source)
            progress.update(task1, completed=100)
            time.sleep(0.3)
            
            # Phase 2: String Deobfuscation
            task2 = progress.add_task(" - Deobfuscating strings...", total=100)
            source, strings_decoded = self._advanced_string_deobfuscation(source)
            stats['strings_decoded'] = strings_decoded
            for i in range(101):
                progress.update(task2, completed=i)
                if i % 20 == 0:
                    time.sleep(0.1)
            
            # Phase 3: Control Flow Analysis
            task3 = progress.add_task(" - Analyzing control flow...", total=100)
            source = self._control_flow_deobfuscation(source)
            for i in range(101):
                progress.update(task3, completed=i)
                if i % 25 == 0:
                    time.sleep(0.1)
            
            # Phase 4: Variable & Function Restoration
            task4 = progress.add_task(" - Restoring functions...", total=100)
            source, functions_restored = self._function_restoration(source)
            stats['functions_restored'] = functions_restored
            for i in range(101):
                progress.update(task4, completed=i)
                if i % 30 == 0:
                    time.sleep(0.1)
            
            # Phase 5: Code Beautification
            task5 = progress.add_task(" - Beautifying code...", total=100)
            source = self._premium_beautify(source)
            for i in range(101):
                progress.update(task5, completed=i)
                if i % 15 == 0:
                    time.sleep(0.05)
        
        # Update detection statistics
        for obf_type in detected_types:
            if obf_type in stats:
                stats[obf_type] += 1
            else:
                stats['generic_obfuscation'] += 1
        
        return source, stats
    
    def _detect_obfuscator_type(self, source: str) -> List[str]:
        """Advanced obfuscator detection with pattern matching"""
        detected = []
        
        # Luraph patterns
        luraph_patterns = [
            r'getfenv\(\)\.\w+',
            r'loadstring\(string\.char\(',
            r'_G\[\w+\]\s*=\s*function',
            r'local\s+\w+\s*=\s*getfenv\(\)',
            r'rawset\(_G,\s*\w+',
            r'debug\.getregistry\(\)',
            r'hookfunction',
            r'clonefunction\('
        ]
        
        # Moonsec V3 patterns
        moonsec_patterns = [
            r'local\s+\w+\s*=\s*\{[^}]*\}\s*;\s*for\s+\w+,\w+\s+in\s+next',
            r'string\.sub\(\w+,\s*\d+,\s*\d+\)',
            r'tonumber\(string\.byte\(',
            r'\w+\[\w+\]\[\w+\]',
            r'local\s+\w+\s*=\s*function\(\)\s*return\s*\w+\[\d+\]\s*end',
            r'bit\.bxor\(',
            r'bit\.lshift\(',
            r'bit\.rshift\('
        ]
        
        # Wearedevs patterns
        wearedevs_patterns = [
            r'local\s+\w+\s*=\s*\{\}\s*;\s*\w+\.\w+\s*=\s*function',
            r'getrenv\(\)\.\w+',
            r'getgc\(\)',
            r'getinstances\(\)',
            r'fireclickdetector',
            r'firesignal',
            r'local\s+\w+\s*=\s*Instance\.new\('
        ]
        
        # Check patterns
        for pattern in luraph_patterns:
            if re.search(pattern, source, re.IGNORECASE):
                detected.append('luraph_patterns')
                break
                
        for pattern in moonsec_patterns:
            if re.search(pattern, source, re.IGNORECASE):
                detected.append('moonsec_patterns')
                break
                
        for pattern in wearedevs_patterns:
            if re.search(pattern, source, re.IGNORECASE):
                detected.append('wearedevs_patterns')
                break
        
        return detected if detected else ['generic_obfuscation']
    
    def _advanced_string_deobfuscation(self, source: str) -> Tuple[str, int]:
        """Advanced string deobfuscation techniques"""
        decoded_count = 0
        
        # Method 1: string.char with math expressions
        def eval_string_char(match):
            nonlocal decoded_count
            chars = match.group(1).split(',')
            res = ""
            for c in chars:
                c = c.strip()
                if not c: continue
                try:
                    # Handle complex math expressions
                    if any(op in c for op in ['+', '-', '*', '/', '^']):
                        clean_math = re.sub(r'[^0-9+\-*/().^]', '', c)
                        if clean_math:
                            val = int(eval(clean_math))
                            res += chr(val)
                            decoded_count += 1
                    elif c.startswith('\\'):
                        val = int(c[1:])
                        res += chr(val)
                        decoded_count += 1
                    else:
                        val = int(c)
                        res += chr(val)
                        decoded_count += 1
                except:
                    pass
            return f'"{res}"'
        
        source = re.sub(r'string\.char\((.*?)\)', eval_string_char, source)
        
        # Method 2: Base64 decoding
        b64_matches = re.findall(r'(["\'])([A-Za-z0-9+/=]{20,})\1', source)
        for quote, b64 in b64_matches:
            try:
                decoded = base64.b64decode(b64).decode('utf-8')
                if any(keyword in decoded.lower() for keyword in ['function', 'local', 'end', 'then', 'do']):
                    source = source.replace(f'{quote}{b64}{quote}', f'"{decoded}"')
                    decoded_count += 1
            except:
                pass
        
        # Method 3: Hex string decoding
        def eval_hex_string(match):
            nonlocal decoded_count
            try:
                raw = match.group(0).encode('utf-8').decode('unicode_escape')
                decoded_count += 1
                return f'"{raw}"'
            except:
                return match.group(0)
        
        source = re.sub(r'"(\\x[0-9a-fA-F]{2})+"', eval_hex_string, source)
        source = re.sub(r"'(\\x[0-9a-fA-F]{2})+'", eval_hex_string, source)
        
        # Method 4: String concatenation unfolding
        source = re.sub(r'(["\'][^"\']*["\'])\.\.\.?(["\'][^"\']*["\'])', r'\1..\2', source)
        
        return source, decoded_count
    
    def _control_flow_deobfuscation(self, source: str) -> str:
        """Deobfuscate control flow structures"""
        # Remove dead code after return statements
        source = re.sub(r'return\s+[^\n]*\n(?:[^\n]*\n)*', lambda m: m.group(0).split('\n')[0] + '\n', source)
        
        # Simplify if conditions with constant values
        source = re.sub(r'if\s+(true|True)\s+then\s*(.*?)\s*end', r'\2', source, flags=re.DOTALL)
        source = re.sub(r'if\s+(false|False)\s+then.*?end', '', source, flags=re.DOTALL)
        
        # Unfold while true loops
        source = re.sub(r'while\s+(true|True)\s+do', 'while true do', source)
        
        return source
    
    def _function_restoration(self, source: str) -> Tuple[str, int]:
        """Restore obfuscated function calls and variable names"""
        restored_count = 0
        
        # Restore common obfuscated function calls
        function_mappings = {
            r'getfenv\(\)\.print': 'print',
            r'getfenv\(\)\.warn': 'warn',
            r'getfenv\(\)\.error': 'error',
            r'getrenv\(\)\.print': 'print',
            r'game\:GetService\(["\']Workspace["\']\)': 'workspace',
            r'game\:GetService\(["\']Players["\']\)': 'game.Players',
            r'game\:GetService\(["\']Lighting["\']\)': 'game.Lighting',
            r'Instance\.new\(["\']Part["\']\)': 'Instance.new("Part")',
            r'Instance\.new\(["\']Model["\']\)': 'Instance.new("Model")'
        }
        
        for pattern, replacement in function_mappings.items():
            if re.search(pattern, source):
                source = re.sub(pattern, replacement, source)
                restored_count += 1
        
        # Restore variable assignments from getfenv
        source = re.sub(r'local\s+(\w+)\s*=\s*getfenv\(\)\.(\w+)', r'local \1 = \2', source)
        
        return source, restored_count
    
    def _premium_beautify(self, source: str) -> str:
        """Premium code beautification with advanced formatting"""
        # Apply basic beautification first
        source = self._beautify(source)
        
        # Additional beautification steps
        lines = source.split('\n')
        beautified_lines = []
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Add spacing around operators
            line = re.sub(r'([=+\-*/<>])', r' \1 ', line)
            line = re.sub(r'\s+', ' ', line)  # Remove extra spaces
            
            # Fix spacing after commas
            line = re.sub(r',\s*', ', ', line)
            
            # Ensure proper spacing around parentheses
            line = re.sub(r'\(\s+', '(', line)
            line = re.sub(r'\s+\)', ')', line)
            
            beautified_lines.append(line)
        
        return '\n'.join(beautified_lines)
    
    def _generate_deobfuscation_report(self, stats: Dict, filename: str) -> str:
        """Generate comprehensive deobfuscation report"""
        report = f"""-- ══════════════════════════════════════════════════════════════
-- ✦ COSMOS.WIN PREMIUM LUA DEOBFUSCATOR REPORT ✦
-- ══════════════════════════════════════════════════════════════
-- 
-- Target File: {filename}
-- Deobfuscation Date: {time.strftime('%Y-%m-%d %H:%M:%S')}
-- Engine Version: Premium v3.0
-- 
-- DETECTION STATISTICS:
--   • Luraph Patterns Found: {stats.get('luraph_patterns', 0)}
--   • Moonsec V3 Patterns: {stats.get('moonsec_patterns', 0)}
--   • Wearedevs Patterns: {stats.get('wearedevs_patterns', 0)}
--   • Generic Obfuscation: {stats.get('generic_obfuscation', 0)}
--   • Strings Decoded: {stats.get('strings_decoded', 0)}
--   • Functions Restored: {stats.get('functions_restored', 0)}
-- 
-- DEOBFUSCATION TECHNIQUES APPLIED:
--   • Advanced string deobfuscation (string.char, base64, hex)
--   • Control flow analysis and simplification
--   • Function and variable restoration
--   • Premium code beautification
--   • Pattern-based obfuscator detection
-- 
-- NOTE: This is an automated deobfuscation. Some variable names may
--       still be obfuscated. Manual review recommended for critical code.
-- ══════════════════════════════════════════════════════════════
"""
        return report
    
    def _display_deobfuscation_results(self, stats: Dict, out_path: str, filename: str):
        """Display comprehensive deobfuscation results"""
        c = self.console
        
        # Results table
        table = Table(title=f"[bold {self.col_neon}]Deobfuscation Results for {filename}[/bold {self.col_neon}]", box=box.ROUNDED)
        table.add_column("Metric", style=f"bold {self.col_pink}", justify="left")
        table.add_column("Count", style=f"bold {self.col_gold}", justify="center")
        table.add_column("Status", style="bold", justify="center")
        
        # Add rows with color-coded status
        metrics = [
            ("Luraph Patterns", stats.get('luraph_patterns', 0), "🔴" if stats.get('luraph_patterns', 0) > 0 else "✅"),
            ("Moonsec V3", stats.get('moonsec_patterns', 0), "🔴" if stats.get('moonsec_patterns', 0) > 0 else "✅"),
            ("Wearedevs", stats.get('wearedevs_patterns', 0), "🔴" if stats.get('wearedevs_patterns', 0) > 0 else "✅"),
            ("Strings Decoded", stats.get('strings_decoded', 0), "🟢" if stats.get('strings_decoded', 0) > 0 else "⚪"),
            ("Functions Restored", stats.get('functions_restored', 0), "🟢" if stats.get('functions_restored', 0) > 0 else "⚪")
        ]
        
        for metric, count, status in metrics:
            color = self.col_success if count > 0 else self.col_dim
            table.add_row(metric, f"[{color}]{count}[/{color}]", status)
        
        c.print("\n")
        c.print(Align.center(table))
        c.print(f"\n  [bold {self.col_success}]✓ Premium deobfuscation completed![/bold {self.col_success}]")
        c.print(f"  [dim]Output saved to:[/dim] [bold {self.col_neon}]{out_path}[/bold {self.col_neon}]")
        
        try:
            if os.name == 'nt':
                os.startfile(os.path.dirname(out_path))
        except Exception:
            pass
        c.print()
                    
        except Exception as e:
            c.print(f"  [bold red]✗ Unexpected error during analysis: {e}[/bold red]\n")
                
        c.input(f"\n  [{self.col_dim}]Press Enter to return...[/{self.col_dim}]")
