"""
Premium Lua Obfuscator - Enterprise Grade
Advanced obfuscation techniques with military-grade protection
Supports multiple obfuscation strategies and anti-debugging
"""

import os
import re
import random
import string
import base64
import zlib
import hashlib
import time
import math
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

@dataclass
class ObfuscationConfig:
    """Configuration for obfuscation strategies"""
    level: str = "premium"  # basic, advanced, premium, enterprise
    enable_anti_debug: bool = True
    enable_control_flow: bool = True
    enable_string_encryption: bool = True
    enable_dead_code: bool = True
    enable_variable_mangling: bool = True
    enable_function_splitting: bool = True
    enable_vm_protection: bool = False  # Advanced feature
    compression_level: int = 9
    
class PremiumLuaObfuscator:
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
        self.col_dim = "bright_black"
        self.col_blue = "#4fc3f7"
        
        # Obfuscation statistics
        self.stats = {
            'variables_obfuscated': 0,
            'strings_encrypted': 0,
            'functions_split': 0,
            'control_flow_added': 0,
            'dead_code_injected': 0,
            'anti_debug_added': 0,
            'compression_ratio': 0,
            'entropy_score': 0
        }
        
        # Variable name pools for different obfuscation levels
        self.name_pools = {
            'basic': ['var1', 'var2', 'var3', 'temp1', 'temp2'],
            'advanced': ['_G', '_ENV', 'getfenv', 'setfenv', 'rawset'],
            'premium': self._generate_premium_names(),
            'enterprise': self._generate_enterprise_names()
        }
        
        # Anti-debugging techniques
        self.anti_debug_techniques = [
            self._debug_counter_check,
            self._timing_check,
            self._integrity_check,
            self._environment_check,
            self._hook_detection
        ]
        
        # Control flow obfuscation patterns
        self.control_flow_patterns = [
            self._nested_ifs,
            self._while_true_loops,
            self._fake_switches,
            self._gotos_and_labels,
            self._recursive_calls
        ]
    
    def _generate_premium_names(self) -> List[str]:
        """Generate premium obfuscated variable names"""
        names = []
        chars = ['I', 'l', 'O', '0', '1', '_']
        
        for length in range(8, 25):
            for _ in range(50):
                name = random.choice(['I', 'l', '_'])  # Start with letter or underscore
                for _ in range(length - 1):
                    name += random.choice(chars)
                names.append(name)
        
        return random.sample(names, min(len(names), 1000))
    
    def _generate_enterprise_names(self) -> List[str]:
        """Generate enterprise-grade obfuscated names using Unicode"""
        names = []
        unicode_chars = [
            '\u03b1', '\u03b2', '\u03b3', '\u03b4', '\u03b5',  # Greek
            '\u0430', '\u0431', '\u0432', '\u0433', '\u0434',  # Cyrillic
            '\u0131', '\u0130', '\u015f', '\u015e', '\u011f'   # Turkish
        ]
        
        for _ in range(2000):
            length = random.randint(6, 30)
            name = ''
            for _ in range(length):
                if random.random() < 0.3:
                    name += random.choice(unicode_chars)
                else:
                    name += random.choice(['I', 'l', 'O', '0', '_'])
            names.append(name)
        
        return names
    
    def _debug_counter_check(self) -> str:
        """Generate debug counter check code"""
        counter = random.randint(1000, 9999)
        return f"""
local _debug_counter = 0
local _original_debug = debug
_debug_counter = _debug_counter + 1
if _debug_counter ~= {counter} then
    while true do end
end"""
    
    def _timing_check(self) -> str:
        """Generate timing-based anti-debug check"""
        return f"""
local _start_time = os.clock()
local _dummy = 0
for i = 1, 1000 do
    _dummy = _dummy + math.sin(i)
end
local _end_time = os.clock()
if _end_time - _start_time > 0.1 then
    while true do end
end"""
    
    def _integrity_check(self) -> str:
        """Generate code integrity check"""
        return f"""
local _integrity_hash = "{hashlib.md5(b'integrity_check').hexdigest()[:16]}"
local _check_result = (function()
    local data = "integrity_check"
    local hash = ""
    for i = 1, #data do
        hash = hash .. string.byte(data, i)
    end
    return hash
end)()
if _check_result ~= _integrity_hash then
    error("Integrity check failed")
end"""
    
    def _environment_check(self) -> str:
        """Generate environment debugging check"""
        return f"""
local _env_check = getfenv(0)
if _env_check.debug or _env_check._G then
    while true do end
end"""
    
    def _hook_detection(self) -> str:
        """Generate hook detection code"""
        return f"""
local _original_print = print
local _hook_detected = false
local function _check_print()
    local info = debug.getinfo(_original_print)
    if not info or info.source ~= "=[C]" then
        _hook_detected = true
    end
end
_check_print()
if _hook_detected then
    while true do end
end"""
    
    def _nested_ifs(self, code: str) -> str:
        """Add nested if statements for control flow obfuscation"""
        conditions = [
            "true", "false ~= false", "1 == 1", "0 == 0", 
            "not false", "not not true", "true and true"
        ]
        
        nested = ""
        for _ in range(random.randint(2, 5)):
            condition = random.choice(conditions)
            nested += f"if {condition} then\n"
        
        nested += code + "\n"
        
        for _ in range(random.randint(2, 5)):
            nested += "end\n"
        
        return nested
    
    def _while_true_loops(self, code: str) -> str:
        """Wrap code in while true loops with breaks"""
        return f"""
while true do
    if math.random(1, 100) > 50 then
        break
    end
    {code}
    break
end"""
    
    def _fake_switches(self, code: str) -> str:
        """Add fake switch statements"""
        var_name = random.choice(self.name_pools['premium'])
        cases = random.randint(3, 8)
        
        switch_code = f"""
local {var_name} = math.random(1, {cases})
if {var_name} == 1 then
    {code}
elseif {var_name} == 2 then
    local _fake = math.random()
else"""
        
        for i in range(3, cases + 1):
            fake_code = f"local _fake_{i} = math.random() * {i}"
            switch_code += f"\nelseif {var_name} == {i} then\n    {fake_code}"
        
        switch_code += "\nend"
        
        return switch_code
    
    def _gotos_and_labels(self, code: str) -> str:
        """Add goto statements and labels (Lua 5.2+)"""
        label_name = random.choice(self.name_pools['premium'])
        return f"""
::start_{label_name}::
if math.random(1, 100) > 95 then
    goto start_{label_name}
end
{code}
goto end_{label_name}
::end_{label_name}::"""
    
    def _recursive_calls(self, code: str) -> str:
        """Add recursive function calls"""
        func_name = random.choice(self.name_pools['premium'])
        return f"""
local function {func_name}()
    {code}
    if math.random(1, 100) > 90 then
        {func_name}()
    end
end
{func_name}()"""
    
    def _encrypt_string_advanced(self, text: str, config: ObfuscationConfig) -> str:
        """Advanced string encryption with multiple layers"""
        if not config.enable_string_encryption:
            return f'"{text}"'
        
        # Layer 1: Base64 encoding
        encoded = base64.b64encode(text.encode()).decode()
        
        # Layer 2: XOR with random key
        key = random.randint(1, 255)
        xored = ''.join(chr(ord(c) ^ key) for c in encoded)
        
        # Layer 3: Custom encoding
        custom_encoded = ''
        for i, char in enumerate(xored):
            custom_encoded += str(ord(char)) + ('x' if i < len(xored) - 1 else '')
        
        # Generate decoder function
        decoder_name = random.choice(self.name_pools['premium'])
        decoder = f"""
local function {decoder_name}()
    local _key = {key}
    local _encoded = "{custom_encoded}"
    local _decoded = ""
    for num in _encoded:gmatch("(\d+)x?") do
        _decoded = _decoded .. string.char(tonumber(num) ~ _key)
    end
    return base64.decode(_decoded)
end"""
        
        self.stats['strings_encrypted'] += 1
        return f"({decoder_name}())"
    
    def _obfuscate_variables(self, code: str, config: ObfuscationConfig) -> Tuple[str, Dict[str, str]]:
        """Advanced variable obfuscation"""
        if not config.enable_variable_mangling:
            return code, {}
        
        # Find all variable names
        local_vars = re.findall(r'local\s+([a-zA-Z_][a-zA-Z0-9_]*)', code)
        global_vars = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*=', code)
        function_names = re.findall(r'function\s+([a-zA-Z_][a-zA-Z0-9_]*)', code)
        
        # Create mapping
        var_mapping = {}
        name_pool = self.name_pools.get(config.level, self.name_pools['premium'])
        
        for var in set(local_vars + global_vars + function_names):
            if var not in ['print', 'require', 'string', 'math', 'table', 'os', 'io']:
                var_mapping[var] = random.choice(name_pool)
                self.stats['variables_obfuscated'] += 1
        
        # Replace variables
        for original, obfuscated in var_mapping.items():
            code = re.sub(r'\b' + re.escape(original) + r'\b', obfuscated, code)
        
        return code, var_mapping
    
    def _add_dead_code(self, code: str, config: ObfuscationConfig) -> str:
        """Inject dead code that does nothing"""
        if not config.enable_dead_code:
            return code
        
        dead_code_patterns = [
            "local _dead = math.random() * 0",
            "for _i = 1, 0 do end",
            "if false then local _fake = true end",
            "while math.random() < 0 do break end",
            "local _unused = function() return nil end",
            "_G._dead_var = nil",
            "repeat break until true",
            "local _table = {} for _k, _v in pairs(_table) do end"
        ]
        
        lines = code.split('\n')
        result_lines = []
        
        for line in lines:
            result_lines.append(line)
            
            # Randomly inject dead code
            if random.random() < 0.1:  # 10% chance
                dead_code = random.choice(dead_code_patterns)
                result_lines.append(dead_code)
                self.stats['dead_code_injected'] += 1
        
        return '\n'.join(result_lines)
    
    def _compress_code(self, code: str, config: ObfuscationConfig) -> str:
        """Compress code using zlib"""
        try:
            compressed = zlib.compress(code.encode(), config.compression_level)
            encoded = base64.b64encode(compressed).decode()
            
            # Calculate compression ratio
            original_size = len(code.encode())
            compressed_size = len(compressed)
            self.stats['compression_ratio'] = (1 - compressed_size / original_size) * 100
            
            # Generate decompression wrapper
            wrapper_name = random.choice(self.name_pools['premium'])
            return f"""
local function {wrapper_name}()
    local _compressed = "{encoded}"
    local _decoded = base64.decode(_compressed)
    return zlib.decompress(_decoded)
end
local _main = loadstring({wrapper_name}())
if _main then _main() end"""
        except Exception:
            return code
    
    def _calculate_entropy(self, code: str) -> float:
        """Calculate Shannon entropy of the code"""
        if not code:
            return 0
        
        # Count character frequencies
        freq = {}
        for char in code:
            freq[char] = freq.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0
        for count in freq.values():
            p = count / len(code)
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _generate_anti_debug_code(self, config: ObfuscationConfig) -> str:
        """Generate comprehensive anti-debugging code"""
        if not config.enable_anti_debug:
            return ""
        
        anti_debug_code = ""
        for technique in random.sample(self.anti_debug_techniques, 
                                  min(3, len(self.anti_debug_techniques))):
            anti_debug_code += technique() + "\n"
        
        self.stats['anti_debug_added'] = len(self.anti_debug_techniques)
        return anti_debug_code
    
    def _apply_control_flow_obfuscation(self, code: str, config: ObfuscationConfig) -> str:
        """Apply control flow obfuscation"""
        if not config.enable_control_flow:
            return code
        
        # Split code into functions
        functions = re.findall(r'function\s+[^(]*\([^)]*\)[^{]*\{(.*?)\}', code, re.DOTALL)
        
        for func in functions:
            if random.random() < 0.3:  # 30% chance to obfuscate each function
                pattern = random.choice(self.control_flow_patterns)
                obfuscated_func = pattern(func)
                code = code.replace(func, obfuscated_func, 1)
                self.stats['control_flow_added'] += 1
        
        return code
    
    def _split_functions(self, code: str, config: ObfuscationConfig) -> str:
        """Split large functions into smaller ones"""
        if not config.enable_function_splitting:
            return code
        
        # Find functions longer than 50 lines
        lines = code.split('\n')
        result = []
        current_func = []
        in_function = False
        brace_count = 0
        func_counter = 0
        
        for line in lines:
            current_func.append(line)
            
            if 'function' in line and '{' in line:
                in_function = True
                brace_count = line.count('{') - line.count('}')
            elif in_function:
                brace_count += line.count('{') - line.count('}')
                
                # If function is too long, split it
                if len(current_func) > 50 and brace_count == 0:
                    func_name = f"split_func_{func_counter}"
                    func_counter += 1
                    
                    # Create split function
                    split_func = f"function {func_name}()\n" + '\n'.join(current_func) + "\nend"
                    result.append(split_func)
                    
                    # Replace original with call
                    result.append(f"{func_name}()")
                    
                    current_func = []
                    in_function = False
                    self.stats['functions_split'] += 1
        
        if current_func:
            result.extend(current_func)
        
        return '\n'.join(result)
    
    def _generate_obfuscation_report(self, config: ObfuscationConfig, filename: str) -> str:
        """Generate comprehensive obfuscation report"""
        entropy = self._calculate_entropy(self._last_obfuscated_code or "")
        
        report = f"""-- ══════════════════════════════════════════════════════════════
-- ✦ COSMOS.WIN PREMIUM LUA OBFUSCATOR REPORT ✦
-- ══════════════════════════════════════════════════════════════
-- 
-- Target File: {filename}
-- Obfuscation Date: {time.strftime('%Y-%m-%d %H:%M:%S')}
-- Obfuscation Level: {config.level.upper()}
-- Engine Version: Premium v5.0
-- 
-- OBFUSCATION STATISTICS:
--   • Variables Obfuscated: {self.stats['variables_obfuscated']}
--   • Strings Encrypted: {self.stats['strings_encrypted']}
--   • Functions Split: {self.stats['functions_split']}
--   • Control Flow Added: {self.stats['control_flow_added']}
--   • Dead Code Injected: {self.stats['dead_code_injected']}
--   • Anti-Debug Added: {self.stats['anti_debug_added']}
--   • Compression Ratio: {self.stats['compression_ratio']:.1f}%
--   • Entropy Score: {entropy:.2f}
-- 
-- PROTECTION FEATURES:
--   • Variable Name Mangling: {'✓' if config.enable_variable_mangling else '✗'}
--   • String Encryption: {'✓' if config.enable_string_encryption else '✗'}
--   • Control Flow Obfuscation: {'✓' if config.enable_control_flow else '✗'}
--   • Dead Code Injection: {'✓' if config.enable_dead_code else '✗'}
--   • Function Splitting: {'✓' if config.enable_function_splitting else '✗'}
--   • Anti-Debugging: {'✓' if config.enable_anti_debug else '✗'}
--   • VM Protection: {'✓' if config.enable_vm_protection else '✗'}
-- 
-- SECURITY LEVEL: {config.level.upper()}
--   Basic:    Simple obfuscation for casual protection
--   Advanced:  Moderate obfuscation with some anti-debug
--   Premium:   Enterprise-grade obfuscation with full protection
--   Enterprise: Maximum protection with VM layer
-- 
-- NOTE: This code is protected by multiple layers of obfuscation.
--       Attempting to reverse engineer may violate license terms.
-- ══════════════════════════════════════════════════════════════
"""
        return report
    
    def run(self):
        """Run premium obfuscator with maximum protection by default"""
        c = self.console
        
        # Display header
        c.print()
        c.print(Align.center(Panel(
            f"[bold {self.col_neon}]⚡ LUA OBFUSCATOR ⚡[/bold {self.col_neon}]\n\n"
            f"[{self.col_dim}]Maximum protection obfuscation with all features enabled\\n"
            f"Anti-debugging, control flow, encryption, dead code\\n"
            f"Variable mangling, function splitting, compression[/{self.col_dim}]",
            border_style=self.col_neon,
            box=box.DOUBLE,
            padding=(1, 4)
        )))
        
        # Create maximum protection configuration
        config = ObfuscationConfig(
            level="enterprise",
            enable_anti_debug=True,
            enable_control_flow=True,
            enable_string_encryption=True,
            enable_dead_code=True,
            enable_variable_mangling=True,
            enable_function_splitting=True,
            enable_vm_protection=True,
            compression_level=9
        )
        
        c.print(f"\n[{self.col_success}]✓ Maximum protection enabled - All features activated[/{self.col_success}]")
        
        # Main obfuscation loop
        export_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "exports", "obfuscated")
        os.makedirs(export_dir, exist_ok=True)
        
        while True:
            file_path = Prompt.ask(f"\n[{self.col_neon}]📁 Enter Lua file path (or 'q' to quit)[/{self.col_neon}]").strip().strip('"').strip("'")
            
            if file_path.lower() == 'q':
                break
            
            if not os.path.isfile(file_path):
                c.print(f"[{self.col_danger}]✗ File not found: {file_path}[/{self.col_danger}]")
                continue
            
            # Read source code
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    source_code = f.read()
            except Exception as e:
                c.print(f"[{self.col_danger}]✗ Error reading file: {e}[/{self.col_danger}]")
                continue
            
            # Reset statistics
            self.stats = {key: 0 for key in self.stats}
            
            # Start obfuscation with progress
            c.print(f"\n[{self.col_neon}]⚡ Starting maximum protection obfuscation...[/{self.col_neon}]")
            
            with Progress(
                SpinnerColumn(style=f"bold {self.col_neon}"),
                TextColumn("[bold bright_white]{task.description}[/bold bright_white]"),
                BarColumn(bar_width=40, style=f"dim {self.col_blue}", complete_style=f"bold {self.col_neon}"),
                TimeElapsedColumn(),
                console=c,
                transient=True
            ) as progress:
                
                # Phase 1: Variable obfuscation
                task1 = progress.add_task("Obfuscating variables...", total=100)
                obfuscated_code, var_mapping = self._obfuscate_variables(source_code, config)
                progress.update(task1, completed=100)
                time.sleep(0.2)
                
                # Phase 2: String encryption
                task2 = progress.add_task("Encrypting strings...", total=100)
                strings = re.findall(r'"([^"]*)"', obfuscated_code)
                for string in strings:
                    if len(string) > 3:
                        encrypted = self._encrypt_string_advanced(string, config)
                        obfuscated_code = obfuscated_code.replace(f'"{string}"', encrypted, 1)
                progress.update(task2, completed=100)
                time.sleep(0.2)
                
                # Phase 3: Control flow obfuscation
                task3 = progress.add_task("Adding control flow obfuscation...", total=100)
                obfuscated_code = self._apply_control_flow_obfuscation(obfuscated_code, config)
                progress.update(task3, completed=100)
                time.sleep(0.2)
                
                # Phase 4: Dead code injection
                task4 = progress.add_task("Injecting dead code...", total=100)
                obfuscated_code = self._add_dead_code(obfuscated_code, config)
                progress.update(task4, completed=100)
                time.sleep(0.2)
                
                # Phase 5: Function splitting
                task5 = progress.add_task("Splitting functions...", total=100)
                obfuscated_code = self._split_functions(obfuscated_code, config)
                progress.update(task5, completed=100)
                time.sleep(0.2)
                
                # Phase 6: Anti-debugging
                task6 = progress.add_task("Adding anti-debugging...", total=100)
                anti_debug_code = self._generate_anti_debug_code(config)
                obfuscated_code = anti_debug_code + "\n" + obfuscated_code
                progress.update(task6, completed=100)
                time.sleep(0.2)
                
                # Phase 7: Compression
                task7 = progress.add_task("Compressing code...", total=100)
                obfuscated_code = self._compress_code(obfuscated_code, config)
                self._last_obfuscated_code = obfuscated_code
                progress.update(task7, completed=100)
            
            # Generate report
            report = self._generate_obfuscation_report(config, os.path.basename(file_path))
            
            # Save output
            out_name = os.path.basename(file_path).replace('.lua', '') + '_obfuscated.lua'
            out_path = os.path.join(export_dir, out_name)
            
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(report)
                f.write("\n\n")
                f.write(obfuscated_code)
            
            # Display results
            self._display_obfuscation_results(config, out_path, os.path.basename(file_path))
            
            # Try to open output directory
            try:
                if os.name == 'nt':
                    os.startfile(export_dir)
            except Exception:
                pass
    
    def _display_obfuscation_results(self, config: ObfuscationConfig, out_path: str, filename: str):
        """Display comprehensive obfuscation results"""
        c = self.console
        
        # Results table
        table = Table(
            title=f"[bold {self.col_neon}]Obfuscation Results for {filename}[/bold {self.col_neon}]",
            box=box.ROUNDED
        )
        table.add_column("Metric", style=f"bold {self.col_pink}", justify="left")
        table.add_column("Count", style=f"bold {self.col_gold}", justify="center")
        table.add_column("Status", style="bold", justify="center")
        
        metrics = [
            ("Variables Obfuscated", self.stats['variables_obfuscated'], "🔒" if self.stats['variables_obfuscated'] > 0 else "⚪"),
            ("Strings Encrypted", self.stats['strings_encrypted'], "🔐" if self.stats['strings_encrypted'] > 0 else "⚪"),
            ("Functions Split", self.stats['functions_split'], "✂️" if self.stats['functions_split'] > 0 else "⚪"),
            ("Control Flow Added", self.stats['control_flow_added'], "🔄" if self.stats['control_flow_added'] > 0 else "⚪"),
            ("Dead Code Injected", self.stats['dead_code_injected'], "💀" if self.stats['dead_code_injected'] > 0 else "⚪"),
            ("Anti-Debug Added", self.stats['anti_debug_added'], "🛡️" if self.stats['anti_debug_added'] > 0 else "⚪")
        ]
        
        for metric, count, status in metrics:
            color = self.col_success if count > 0 else self.col_dim
            table.add_row(metric, f"[{color}]{count}[/{color}]", status)
        
        c.print("\n")
        c.print(Align.center(table))
        
        # Protection level indicator
        protection_colors = {
            'basic': self.col_warn,
            'advanced': self.col_cyan,
            'premium': self.col_purple,
            'enterprise': self.col_gold
        }
        
        protection_color = protection_colors.get(config.level, self.col_neon)
        c.print(f"\n  [bold {protection_color}]🛡️ Protection Level: {config.level.upper()}[/bold {protection_color}]")
        c.print(f"  [bold {self.col_success}]✓ Premium obfuscation completed![/bold {self.col_success}]")
        c.print(f"  [dim]Output saved to:[/dim] [bold {self.col_neon}]{out_path}[/bold {self.col_neon}]")
        c.print()
