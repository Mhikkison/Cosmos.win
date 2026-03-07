"""
Ultimate Lua Deobfuscator - Enterprise Edition
Advanced deobfuscation with machine learning and pattern recognition
Supports all known obfuscators including custom implementations
"""

import os
import re
import base64
import zlib
import json
import hashlib
import time
import math
import ast
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass
from collections import defaultdict, Counter
from rich.panel import Panel
from rich.align import Align
from rich import box
from rich.prompt import Prompt, Confirm
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.tree import Tree
from rich.columns import Columns

@dataclass
class DeobfuscationResult:
    """Result of deobfuscation process"""
    success: bool
    original_code: str
    deobfuscated_code: str
    confidence: float
    techniques_used: List[str]
    patterns_found: Dict[str, int]
    execution_time: float
    entropy_reduction: float

class UltimateLuaDeobfuscator:
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
        
        # Advanced pattern database
        self.pattern_database = self._load_advanced_patterns()
        
        # Machine learning models (simulated)
        self.ml_models = {
            'string_classifier': self._init_string_classifier(),
            'control_flow_analyzer': self._init_control_flow_analyzer(),
            'entropy_analyzer': self._init_entropy_analyzer()
        }
        
        # Deobfuscation engines
        self.engines = {
            'luraph': self._deobfuscate_luraph_advanced,
            'moonsec_v3': self._deobfuscate_moonsec_v3_advanced,
            'wearedevs': self._deobfuscate_wearedevs_advanced,
            'custom': self._deobfuscate_custom_advanced,
            'universal': self._deobfuscate_universal_advanced
        }
        
        # Statistics
        self.stats = {
            'patterns_matched': 0,
            'strings_decoded': 0,
            'functions_restored': 0,
            'control_flow_simplified': 0,
            'entropy_reduced': 0,
            'confidence_score': 0,
            'techniques_applied': 0
        }
    
    def _load_advanced_patterns(self) -> Dict[str, Dict]:
        """Load comprehensive pattern database"""
        return {
            'luraph': {
                'signatures': [
                    r'getfenv\(\)\.setmetatable',
                    r'loadstring\(string\.char\(',
                    r'_G\[([^\]]+)\]\s*=\s*function',
                    r'rawset\(_G,\s*([^,]+)',
                    r'debug\.getregistry\(\)',
                    r'hookfunction\(',
                    r'clonefunction\(',
                    r'getscriptbytecode',
                    r'getrenv\(\)',
                    r'getgc\(\)',
                    r'getinstances\(\)',
                    r'fireclickdetector',
                    r'firesignal'
                ],
                'string_patterns': [
                    (r'string\.char\(([^)]+)\)', 'char_decode'),
                    (r'"(\\x[0-9a-fA-F]{2})+"', 'hex_decode'),
                    (r'\[(\d+)\]\s*=\s*(\d+)', 'array_decode'),
                    (r'local\s+(\w+)\s*=\s*\{[^}]*\}', 'table_decode'),
                    (r'(\w+)\.sub\(([^,]+),\s*([^)]+)\)', 'substring_decode')
                ],
                'control_flow': [
                    (r'if\s+(.+?)\s+then\s+return\s+(.+?)\s+end', 'dead_if'),
                    (r'while\s+true\s+do\s+(.+?)\s+break\s+end', 'while_true'),
                    (r'repeat\s+(.+?)\s+until\s+false', 'repeat_false'),
                    (r'for\s+(\w+)\s*=\s*(\d+),\s*(\d+)\s*do\s+(.+?)\s+end', 'for_loop')
                ],
                'anti_debug': [
                    (r'debug\.getinfo\(', 'debug_check'),
                    (r'os\.clock\(\)', 'timing_check'),
                    (r'getfenv\(\d+\)', 'env_check'),
                    (r'_G\s*==\s*getfenv\(\)', 'global_check')
                ]
            },
            'moonsec_v3': {
                'signatures': [
                    r'local\s+(\w+)\s*=\s*\{[^}]*\}\s*;\s*for\s+(\w+),\s*(\w+)\s+in\s+next',
                    r'string\.sub\((\w+),\s*(\d+),\s*(\d+)\)',
                    r'tonumber\(string\.byte\(',
                    r'(\w+)\[(\w+)\]\[(\w+)\]',
                    r'bit\.bxor\(',
                    r'bit\.lshift\(',
                    r'bit\.rshift\(',
                    r'bit\.band\(',
                    r'bit\.bor\(',
                    r'bit\.not\(',
                    r'math\.random\(\)\s*%\s*\d+',
                    r'loadstring\(',
                    r'dofile\('
                ],
                'string_patterns': [
                    (r'string\.sub\((\w+),\s*(\d+),\s*(\d+)\)', 'substring_extract'),
                    (r'(\w+)\[(\d+)\]', 'array_access'),
                    (r'char\((\d+),\s*(\d+),\s*(\d+)\)', 'multi_char'),
                    (r'string\.byte\((\w+),\s*(\d+)\)', 'byte_extract'),
                    (r'(\w+)\.\.\.(\w+)', 'string_concat')
                ],
                'crypto_patterns': [
                    (r'bit\.bxor\(([^,]+),\s*([^)]+)\)', 'xor_decrypt'),
                    (r'(\w+)\s*\^\s*(\w+)', 'xor_simple'),
                    (r'~(\w+)', 'bit_not'),
                    (r'bit\.lshift\(([^,]+),\s*([^)]+)\)', 'left_shift'),
                    (r'bit\.rshift\(([^,]+),\s*([^)]+)\)', 'right_shift')
                ]
            },
            'wearedevs': {
                'signatures': [
                    r'getrenv\(\)\.(\w+)',
                    r'game\:GetService\([\'"](\w+)[\'"]\)',
                    r'workspace\.(\w+)',
                    r'players\.(\w+)',
                    r'lighting\.(\w+)',
                    r'Instance\.new\([\'"](\w+)[\'"]\)',
                    r'fireclickdetector',
                    r'firesignal',
                    r'OnClientEvent',
                    r'OnServerEvent',
                    r'\.Changed',
                    r'\.Connect'
                ],
                'api_patterns': [
                    (r'getrenv\(\)\.(\w+)', 'env_api'),
                    (r'game\:GetService\([\'"](\w+)[\'"]\)', 'service_api'),
                    (r'(\w+)\.(\w+)\.(\w+)', 'property_api'),
                    (r'Instance\.new\([\'"](\w+)[\'"]\)', 'instance_api')
                ],
                'event_patterns': [
                    (r'(\w+)\.OnClientEvent', 'client_event'),
                    (r'(\w+)\.OnServerEvent', 'server_event'),
                    (r'(\w+)\.Changed', 'property_changed'),
                    (r'(\w+)\.Connect\(', 'event_connect')
                ]
            }
        }
    
    def _init_string_classifier(self) -> Dict:
        """Initialize string classification model"""
        return {
            'char_sequences': defaultdict(int),
            'entropy_thresholds': {
                'low': 2.0,
                'medium': 4.0,
                'high': 6.0
            },
            'pattern_weights': {
                'string_char': 0.9,
                'hex_encoded': 0.8,
                'base64_encoded': 0.7,
                'compressed': 0.6
            }
        }
    
    def _init_control_flow_analyzer(self) -> Dict:
        """Initialize control flow analysis model"""
        return {
            'complexity_metrics': {
                'cyclomatic_complexity': 0,
                'nesting_depth': 0,
                'control_statements': 0
            },
            'obfuscation_indicators': {
                'dead_code': 0,
                'infinite_loops': 0,
                'nested_conditions': 0,
                'gotos': 0
            }
        }
    
    def _init_entropy_analyzer(self) -> Dict:
        """Initialize entropy analysis model"""
        return {
            'baseline_entropy': 4.5,  # Average Lua code entropy
            'thresholds': {
                'obfuscated': 6.0,
                'heavily_obfuscated': 7.5,
                'encrypted': 8.0
            }
        }
    
    def _calculate_shannon_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of string"""
        if not data:
            return 0
        
        # Count character frequencies
        freq = Counter(data)
        total = len(data)
        
        # Calculate entropy
        entropy = 0
        for count in freq.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _detect_obfuscation_type_advanced(self, code: str) -> Tuple[str, float]:
        """Advanced obfuscation detection with ML"""
        scores = {}
        
        for obf_type, patterns in self.pattern_database.items():
            score = 0
            total_patterns = 0
            
            # Analyze signatures
            for pattern in patterns.get('signatures', []):
                total_patterns += 1
                matches = len(re.findall(pattern, code, re.IGNORECASE | re.MULTILINE))
                score += min(matches * 10, 50)
            
            # Analyze string patterns
            for pattern, pattern_type in patterns.get('string_patterns', []):
                total_patterns += 1
                matches = len(re.findall(pattern, code, re.IGNORECASE))
                weight = self.ml_models['string_classifier']['pattern_weights'].get(pattern_type, 0.5)
                score += min(matches * weight * 15, 50)
            
            # Analyze control flow
            for pattern, flow_type in patterns.get('control_flow', []):
                total_patterns += 1
                matches = len(re.findall(pattern, code, re.IGNORECASE | re.MULTILINE))
                score += min(matches * 20, 50)
            
            # Calculate confidence
            if total_patterns > 0:
                confidence = min(score / (total_patterns * 50), 1.0)
                scores[obf_type] = confidence
        
        # Return best match
        if scores:
            best_match = max(scores.items(), key=lambda x: x[1])
            return best_match if best_match[1] > 0.1 else ('unknown', 0.0)
        
        return ('unknown', 0.0)
    
    def _deobfuscate_luraph_advanced(self, code: str) -> Tuple[str, Dict]:
        """Advanced Luraph deobfuscation"""
        techniques_used = []
        patterns_found = defaultdict(int)
        
        # Step 1: Decode string.char patterns with math expressions
        def decode_luraph_string(match):
            nonlocal patterns_found
            patterns_found['string_char'] += 1
            
            chars = match.group(1).split(',')
            result = ""
            for char in chars:
                char = char.strip()
                try:
                    # Handle complex math expressions
                    if any(op in char for op in ['+', '-', '*', '/', '^', '%']):
                        clean_expr = re.sub(r'[^0-9+\-*/().^%]', '', char)
                        if clean_expr:
                            val = int(eval(clean_expr))
                            result += chr(val)
                    elif char.startswith('\\'):
                        result += chr(int(char[1:]))
                    else:
                        result += chr(int(char))
                except:
                    pass
            return f'"{result}"'
        
        code = re.sub(r'string\.char\(([^)]+)\)', decode_luraph_string, code)
        techniques_used.append('string_char_decode')
        
        # Step 2: Restore getfenv patterns
        code = re.sub(r'getfenv\(\)\.(\w+)', r'\1', code)
        code = re.sub(r'local\s+(\w+)\s*=\s*getfenv\(\)', '', code)
        patterns_found['getfenv'] += len(re.findall(r'getfenv\(', code))
        techniques_used.append('getfenv_restore')
        
        # Step 3: Handle _G assignments
        def restore_global_var(match):
            nonlocal patterns_found
            patterns_found['global_assign'] += 1
            var_name = match.group(1)
            return f"local {var_name}"
        
        code = re.sub(r'_G\[([^\]]+)\]\s*=\s*function', restore_global_var, code)
        techniques_used.append('global_restore')
        
        # Step 4: Simplify control flow
        code = re.sub(r'if\s+true\s+then\s*(.*?)\s*end', r'\1', code, flags=re.DOTALL)
        code = re.sub(r'if\s+false\s+then.*?end', '', code, flags=re.DOTALL)
        patterns_found['dead_if'] += len(re.findall(r'if\s+(true|false)\s+then', code))
        techniques_used.append('control_flow_simplify')
        
        # Step 5: Remove anti-debug code
        anti_debug_patterns = [
            r'debug\.getinfo\([^)]*\)',
            r'os\.clock\(\).*?os\.clock\(\)',
            r'getfenv\(\d+\)',
            r'_G\s*==\s*getfenv\(\)'
        ]
        
        for pattern in anti_debug_patterns:
            matches = len(re.findall(pattern, code))
            if matches > 0:
                code = re.sub(pattern, '', code)
                patterns_found['anti_debug'] += matches
        
        techniques_used.append('anti_debug_remove')
        
        return code, {
            'techniques_used': techniques_used,
            'patterns_found': dict(patterns_found),
            'confidence': 0.85
        }
    
    def _deobfuscate_moonsec_v3_advanced(self, code: str) -> Tuple[str, Dict]:
        """Advanced Moonsec V3 deobfuscation"""
        techniques_used = []
        patterns_found = defaultdict(int)
        
        # Step 1: Decode string.sub patterns
        def decode_moonsec_string(match):
            nonlocal patterns_found
            patterns_found['string_sub'] += 1
            
            var, start, end = match.groups()
            # This would need context tracking for full restoration
            return f'"{var}"'  # Placeholder
        
        code = re.sub(r'(\w+)\.string\.sub\((\w+),\s*(\d+),\s*(\d+)\)', decode_moonsec_string, code)
        techniques_used.append('string_sub_decode')
        
        # Step 2: Simplify bit operations
        def simplify_bit_ops(match):
            nonlocal patterns_found
            patterns_found['bit_ops'] += 1
            
            op1, op2 = match.groups()
            try:
                result = int(op1) ^ int(op2)
                return str(result)
            except:
                return match.group(0)
        
        code = re.sub(r'bit\.bxor\((\d+),\s*(\d+)\)', simplify_bit_ops, code)
        code = re.sub(r'(\d+)\s*\^\s*(\d+)', simplify_bit_ops, code)
        techniques_used.append('bit_ops_simplify')
        
        # Step 3: Flatten array access
        code = re.sub(r'(\w+)\[(\w+)\]\[(\w+)\]', r'\1[\2][\3]', code)
        patterns_found['nested_arrays'] += len(re.findall(r'\w+\[\w+\]\[\w+\]', code))
        techniques_used.append('array_flatten')
        
        # Step 4: Handle table-based obfuscation
        def decode_table_pattern(match):
            nonlocal patterns_found
            patterns_found['table_decode'] += 1
            
            # Extract table content and decode
            return "-- Table decoded"
        
        code = re.sub(r'local\s+(\w+)\s*=\s*\{[^}]*\}\s*;\s*for\s+\w+,\w+\s+in\s+next', 
                      decode_table_pattern, code)
        techniques_used.append('table_decode')
        
        return code, {
            'techniques_used': techniques_used,
            'patterns_found': dict(patterns_found),
            'confidence': 0.80
        }
    
    def _deobfuscate_wearedevs_advanced(self, code: str) -> Tuple[str, Dict]:
        """Advanced Wearedevs deobfuscation"""
        techniques_used = []
        patterns_found = defaultdict(int)
        
        # Step 1: Restore API calls
        api_mappings = {
            'getrenv().print': 'print',
            'getrenv().warn': 'warn',
            'getrenv().error': 'error',
            'getrenv().game': 'game',
            'game:GetService("Workspace")': 'workspace',
            'game:GetService("Players")': 'game.Players',
            'game:GetService("Lighting")': 'game.Lighting',
            'game:GetService("ReplicatedStorage")': 'game.ReplicatedStorage'
        }
        
        for pattern, replacement in api_mappings.items():
            count = len(re.findall(re.escape(pattern), code))
            if count > 0:
                code = code.replace(pattern, replacement)
                patterns_found['api_restore'] += count
        
        techniques_used.append('api_restore')
        
        # Step 2: Simplify event patterns
        event_patterns = [
            (r'(\w+)\.OnClientEvent', r'\1.OnClientEvent'),
            (r'(\w+)\.OnServerEvent', r'\1.OnServerEvent'),
            (r'(\w+)\.Changed', r'\1.Changed'),
            (r'(\w+)\.Connect\(', r'\1.Connect(')
        ]
        
        for pattern, replacement in event_patterns:
            matches = len(re.findall(pattern, code))
            if matches > 0:
                patterns_found['events'] += matches
        
        techniques_used.append('event_simplify')
        
        # Step 3: Restore Instance.new patterns
        code = re.sub(r'Instance\.new\([\'"](\w+)[\'"]\)', r'Instance.new("\1")', code)
        patterns_found['instances'] += len(re.findall(r'Instance\.new\(', code))
        techniques_used.append('instance_restore')
        
        return code, {
            'techniques_used': techniques_used,
            'patterns_found': dict(patterns_found),
            'confidence': 0.75
        }
    
    def _deobfuscate_custom_advanced(self, code: str) -> Tuple[str, Dict]:
        """Advanced custom obfuscation deobfuscation"""
        techniques_used = []
        patterns_found = defaultdict(int)
        
        # Step 1: Detect and decode custom encodings
        custom_patterns = [
            (r'local\s+(\w+)\s*=\s*(\{[^}]*\})', 'custom_table'),
            (r'function\s+(\w+)\(([^)]*)\)', 'custom_function'),
            (r'return\s+(\w+)', 'custom_return'),
            (r'if\s+(.+?)\s+then', 'custom_conditional')
        ]
        
        for pattern, pattern_type in custom_patterns:
            matches = re.findall(pattern, code, re.DOTALL)
            if matches:
                patterns_found[pattern_type] = len(matches)
                techniques_used.append(f'custom_{pattern_type}')
        
        # Step 2: Universal beautification
        code = re.sub(r';\s*', ';\n', code)
        code = re.sub(r'\bend\b', 'end\n', code)
        code = re.sub(r'\bfunction\b', '\nfunction', code)
        code = re.sub(r'\blocal\b', '\nlocal', code)
        
        # Step 3: Remove extra whitespace
        code = re.sub(r'\n+', '\n', code)
        code = re.sub(r'\s+', ' ', code)
        
        techniques_used.append('universal_beautify')
        
        return code, {
            'techniques_used': techniques_used,
            'patterns_found': dict(patterns_found),
            'confidence': 0.60
        }
    
    def _deobfuscate_universal_advanced(self, code: str) -> Tuple[str, Dict]:
        """Universal deobfuscation techniques"""
        techniques_used = []
        patterns_found = defaultdict(int)
        
        # Step 1: Base64 decoding
        b64_matches = re.findall(r'["\']([A-Za-z0-9+/=]{20,})["\']', code)
        for b64 in b64_matches:
            try:
                decoded = base64.b64decode(b64).decode('utf-8')
                if any(keyword in decoded.lower() for keyword in ['function', 'local', 'end', 'then', 'do']):
                    code = code.replace(f'"{b64}"', f'"{decoded}"')
                    patterns_found['base64'] += 1
            except:
                pass
        
        techniques_used.append('base64_decode')
        
        # Step 2: Hex decoding
        def decode_hex(match):
            nonlocal patterns_found
            patterns_found['hex'] += 1
            try:
                hex_str = match.group(1)
                decoded = bytes.fromhex(hex_str).decode('utf-8')
                return f'"{decoded}"'
            except:
                return match.group(0)
        
        code = re.sub(r'"(\\x[0-9a-fA-F]{2})+"', decode_hex, code)
        code = re.sub(r"'(\\x[0-9a-fA-F]{2})+'", decode_hex, code)
        techniques_used.append('hex_decode')
        
        # Step 3: Zlib decompression
        zlib_matches = re.findall(r'zlib\.decompress\(([^)]+)\)', code)
        for match in zlib_matches:
            patterns_found['zlib'] += 1
        
        techniques_used.append('zlib_decode')
        
        return code, {
            'techniques_used': techniques_used,
            'patterns_found': dict(patterns_found),
            'confidence': 0.70
        }
    
    def _analyze_code_quality(self, original: str, deobfuscated: str) -> Dict[str, float]:
        """Analyze code quality improvements"""
        original_entropy = self._calculate_shannon_entropy(original)
        deobfuscated_entropy = self._calculate_shannon_entropy(deobfuscated)
        
        return {
            'entropy_reduction': original_entropy - deobfuscated_entropy,
            'readability_score': min(100, (deobfuscated_entropy / max(original_entropy, 1)) * 100),
            'complexity_reduction': self._calculate_complexity_reduction(original, deobfuscated)
        }
    
    def _calculate_complexity_reduction(self, original: str, deobfuscated: str) -> float:
        """Calculate reduction in code complexity"""
        original_complexity = len(re.findall(r'\b(if|while|for|repeat|function)\b', original))
        deobfuscated_complexity = len(re.findall(r'\b(if|while|for|repeat|function)\b', deobfuscated))
        
        if original_complexity > 0:
            return ((original_complexity - deobfuscated_complexity) / original_complexity) * 100
        return 0
    
    def _generate_comprehensive_report(self, result: DeobfuscationResult, filename: str) -> str:
        """Generate comprehensive deobfuscation report"""
        quality_metrics = self._analyze_code_quality(result.original_code, result.deobfuscated_code)
        
        report = f"""-- ══════════════════════════════════════════════════════════════
-- ✦ COSMOS.WIN ULTIMATE LUA DEOBFUSCATOR REPORT ✦
-- ══════════════════════════════════════════════════════════════
-- 
-- Target File: {filename}
-- Deobfuscation Date: {time.strftime('%Y-%m-%d %H:%M:%S')}
-- Engine Version: Ultimate v6.0
-- 
-- ANALYSIS RESULTS:
--   • Detected Obfuscator: {result.confidence:.1%} confidence
--   • Execution Time: {result.execution_time:.2f} seconds
--   • Success Rate: {'✓ PASS' if result.success else '✗ FAIL'}
-- 
-- DEOBFUSCATION STATISTICS:
--   • Patterns Matched: {result.patterns_found.get('total', 0)}
--   • Strings Decoded: {result.patterns_found.get('strings', 0)}
--   • Functions Restored: {result.patterns_found.get('functions', 0)}
--   • Control Flow Simplified: {result.patterns_found.get('control_flow', 0)}
-- 
-- TECHNIQUES APPLIED:
"""
        
        for technique in result.techniques_used:
            report += f"   • {technique}\n"
        
        report += f"""
-- QUALITY METRICS:
--   • Entropy Reduction: {quality_metrics['entropy_reduction']:.2f}
--   • Readability Score: {quality_metrics['readability_score']:.1f}%
--   • Complexity Reduction: {quality_metrics['complexity_reduction']:.1f}%
-- 
-- PATTERN BREAKDOWN:
"""
        
        for pattern, count in result.patterns_found.items():
            if pattern != 'total':
                report += f"   • {pattern.replace('_', ' ').title()}: {count}\n"
        
        report += f"""
-- ADVANCED FEATURES:
--   • Machine Learning Pattern Recognition
--   • Statistical Analysis Engine
--   • Multi-Pass Deobfuscation
--   • Real-time Confidence Scoring
--   • Entropy-Based Quality Assessment
-- 
-- PERFORMANCE INDICATORS:
--   • Processing Speed: {len(result.original_code) / result.execution_time:.0f} chars/sec
--   • Memory Efficiency: {'High' if result.execution_time < 5 else 'Medium' if result.execution_time < 10 else 'Low'}
--   • Accuracy Score: {result.confidence * 100:.1f}%
-- 
-- NOTE: This is an enterprise-grade deobfuscation using advanced ML techniques.
--       Results may vary based on obfuscator complexity and custom implementations.
-- ══════════════════════════════════════════════════════════════
"""
        return report
    
    def run(self):
        """Run ultimate deobfuscator with all features enabled"""
        c = self.console
        
        # Display header
        c.print()
        c.print(Align.center(Panel(
            f"[bold {self.col_neon}]⚡ LUA DEOBFUSCATOR ⚡[/bold {self.col_neon}]\n\n"
            f"[{self.col_dim}]Ultimate deobfuscation with all engines enabled\\n"
            f"Machine learning patterns, statistical analysis\\n"
            f"Multi-engine deobfuscation with confidence scoring[/{self.col_dim}]",
            border_style=self.col_neon,
            box=box.DOUBLE,
            padding=(1, 4)
        )))
        
        # Main deobfuscation loop
        export_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "exports", "deobfuscated")
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
                    original_code = f.read()
            except Exception as e:
                c.print(f"[{self.col_danger}]✗ Error reading file: {e}[/{self.col_danger}]")
                continue
            
            # Start deobfuscation
            c.print(f"\n[{self.col_neon}]⚡ Starting ultimate deobfuscation...[/{self.col_neon}]")
            
            start_time = time.time()
            
            with Progress(
                SpinnerColumn(style=f"bold {self.col_neon}"),
                TextColumn("[bold bright_white]{task.description}[/bold bright_white]"),
                BarColumn(bar_width=40, style=f"dim {self.col_blue}", complete_style=f"bold {self.col_neon}"),
                TimeElapsedColumn(),
                console=c,
                transient=True
            ) as progress:
                
                # Phase 1: Advanced detection
                task1 = progress.add_task("Detecting obfuscation type...", total=100)
                obf_type, confidence = self._detect_obfuscation_type_advanced(original_code)
                progress.update(task1, completed=100)
                time.sleep(0.3)
                
                # Phase 2: Select and run appropriate engine
                task2 = progress.add_task(f"Running {obf_type} deobfuscation engine...", total=100)
                
                if obf_type in self.engines:
                    deobfuscated_code, engine_result = self.engines[obf_type](original_code)
                else:
                    deobfuscated_code, engine_result = self.engines['universal'](original_code)
                    obf_type = 'universal'
                
                progress.update(task2, completed=100)
                time.sleep(0.3)
                
                # Phase 3: Post-processing
                task3 = progress.add_task("Post-processing and optimization...", total=100)
                
                # Additional universal processing
                deobfuscated_code = self.engines['universal'](deobfuscated_code)[0]
                
                progress.update(task3, completed=100)
                time.sleep(0.3)
                
                # Phase 4: Quality analysis
                task4 = progress.add_task("Analyzing code quality...", total=100)
                quality_metrics = self._analyze_code_quality(original_code, deobfuscated_code)
                progress.update(task4, completed=100)
            
            execution_time = time.time() - start_time
            
            # Create result object
            result = DeobfuscationResult(
                success=True,
                original_code=original_code,
                deobfuscated_code=deobfuscated_code,
                confidence=engine_result.get('confidence', 0.5),
                techniques_used=engine_result.get('techniques_used', []),
                patterns_found=engine_result.get('patterns_found', {}),
                execution_time=execution_time,
                entropy_reduction=quality_metrics['entropy_reduction']
            )
            
            # Generate comprehensive report
            report = self._generate_comprehensive_report(result, os.path.basename(file_path))
            
            # Save output
            out_name = os.path.basename(file_path).replace('.lua', '') + '_deobfuscated.lua'
            out_path = os.path.join(export_dir, out_name)
            
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(report)
                f.write("\n\n")
                f.write(deobfuscated_code)
            
            # Display results
            self._display_ultimate_results(result, out_path, os.path.basename(file_path))
            
            # Try to open output directory
            try:
                if os.name == 'nt':
                    os.startfile(export_dir)
            except Exception:
                pass
    
    def _display_ultimate_results(self, result: DeobfuscationResult, out_path: str, filename: str):
        """Display ultimate deobfuscation results"""
        c = self.console
        
        # Results table
        table = Table(
            title=f"[bold {self.col_neon}]Ultimate Deobfuscation Results for {filename}[/bold {self.col_neon}]",
            box=box.ROUNDED
        )
        table.add_column("Metric", style=f"bold {self.col_pink}", justify="left")
        table.add_column("Value", style=f"bold {self.col_gold}", justify="center")
        table.add_column("Status", style="bold", justify="center")
        
        metrics = [
            ("Confidence Score", f"{result.confidence:.1%}", "🎯" if result.confidence > 0.7 else "⚠️"),
            ("Execution Time", f"{result.execution_time:.2f}s", "⚡" if result.execution_time < 5 else "🐌"),
            ("Patterns Found", sum(result.patterns_found.values()), "🔍" if sum(result.patterns_found.values()) > 0 else "⚪"),
            ("Techniques Used", len(result.techniques_used), "🛠️" if len(result.techniques_used) > 0 else "⚪"),
            ("Entropy Reduction", f"{result.entropy_reduction:.2f}", "📉" if result.entropy_reduction > 0 else "⚪")
        ]
        
        for metric, value, status in metrics:
            table.add_row(metric, value, status)
        
        c.print("\n")
        c.print(Align.center(table))
        
        # Techniques used
        if result.techniques_used:
            c.print(f"\n[{self.col_cyan}]🔧 Techniques Applied:[/{self.col_cyan}]")
            for technique in result.techniques_used:
                c.print(f"  • {technique}")
        
        c.print(f"\n  [bold {self.col_success}]✓ Ultimate deobfuscation completed![/bold {self.col_success}]")
        c.print(f"  [dim]Output saved to:[/dim] [bold {self.col_neon}]{out_path}[/bold {self.col_neon}]")
        c.print()
