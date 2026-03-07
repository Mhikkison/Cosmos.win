"""
Modern Matrix Rain
Professional Matrix-style falling characters animation with advanced features
"""

import os
import time
import random
import threading
import asyncio
from typing import List, Tuple, Optional
from rich.console import Console
from rich.panel import Panel
from rich.align import Align
from rich import box
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.table import Table
from rich.live import Live
from rich.layout import Layout

class ModernMatrixRain:
    def __init__(self, console: Console):
        self.console = console
        self.col_neon = "#00ffcc"
        self.col_success = "#00e676"
        self.col_warn = "#ffab00"
        self.col_danger = "#ff1744"
        self.col_pink = "#ff6ec7"
        self.col_purple = "#bb86fc"
        self.col_gold = "#ffd700"
        self.col_dim = "bright_black"
        self.col_green = "#00ff00"
        self.col_cyan = "#00ffff"
        
        self.running = False
        self.animation_thread = None
        
        # Enhanced character sets
        self.char_sets = {
            'classic': "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#$%^&*()_+-=[]{}|;:,.<>?",
            'japanese': "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ",
            'cyber': "░▒▓█▄▀■□▪▫●○◆◇◈◉◊○●◐◑◒◓◔◕◖◗◘◙◚◛◜◝◞◟◠◡◢◣◤◥◦◧◨◩◪◫◬◭◮◯",
            'binary': "01",
            'hex': "0123456789ABCDEF",
            'symbols': "!@#$%^&*()_+-=[]{}|;:,.<>?/~`",
            'glitch': "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#$%^&*()_+-=[]{}|;:,.<>?ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ░▒▓█▄▀■□▪▫●○◆◇◈◉◊○●◐◑◒◓◔◕◖◗◘◙◚◛◜◝◞◟◠◡◢◣◤◥◦◧◨◩◪◫◬◭◮◯"
        }
        
        # Animation effects
        self.effects = {
            'classic': {'speed': 0.1, 'density': 0.1, 'fade': True},
            'fast': {'speed': 0.05, 'density': 0.15, 'fade': False},
            'slow': {'speed': 0.2, 'density': 0.05, 'fade': True},
            'dense': {'speed': 0.1, 'density': 0.2, 'fade': True},
            'sparse': {'speed': 0.1, 'density': 0.05, 'fade': True},
            'glitch': {'speed': 0.03, 'density': 0.25, 'fade': False},
            'cyber': {'speed': 0.08, 'density': 0.12, 'fade': True},
            'binary': {'speed': 0.15, 'density': 0.1, 'fade': True}
        }
        
        # Color schemes
        self.color_schemes = {
            'classic': [(0, 255, 0), (0, 200, 0), (0, 150, 0), (0, 100, 0), (0, 50, 0)],
            'neon': [(0, 255, 255), (255, 0, 255), (255, 255, 0), (0, 255, 0), (255, 0, 0)],
            'ocean': [(0, 150, 255), (0, 200, 255), (0, 255, 200), (0, 255, 150), (0, 255, 100)],
            'fire': [(255, 0, 0), (255, 100, 0), (255, 200, 0), (255, 255, 0), (255, 255, 100)],
            'purple': [(255, 0, 255), (200, 0, 255), (150, 0, 255), (100, 0, 255), (50, 0, 255)],
            'matrix': [(0, 255, 0), (0, 200, 0), (0, 150, 0), (0, 100, 0), (0, 50, 0)]
        }
    
    def get_terminal_size(self) -> Tuple[int, int]:
        """Get terminal dimensions safely"""
        try:
            import shutil
            return shutil.get_terminal_size()
        except:
            return (80, 24)
    
    def clear_screen(self):
        """Clear console screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def create_matrix_column(self, height: int, char_set: str, effect: dict, color_scheme: List[Tuple[int, int, int]]) -> List[str]:
        """Create a single column of matrix characters"""
        column = []
        
        # Random starting position
        start_pos = random.randint(-height, 0)
        
        for y in range(height):
            if y < start_pos:
                column.append(' ')
            else:
                # Determine character and color
                if y - start_pos < len(color_scheme):
                    r, g, b = color_scheme[y - start_pos]
                    color = f"#{r:02x}{g:02x}{b:02x}"
                else:
                    color = f"#{color_scheme[-1][0]:02x}{color_scheme[-1][1]:02x}{color_scheme[-1][2]:02x}"
                
                char = random.choice(char_set)
                column.append(f"[{color}]{char}[/{color}]")
        
        return column
    
    def create_text_reveal(self, text: str, char_set: str, effect: dict) -> List[List[str]]:
        """Create text reveal effect"""
        width, height = self.get_terminal_size()
        lines = []
        
        # Calculate text position (centered)
        text_width = len(text)
        start_x = (width - text_width) // 2
        start_y = height // 2
        
        # Create initial matrix
        for y in range(height):
            line = []
            for x in range(width):
                if y == start_y and start_x <= x < start_x + text_width:
                    # Text character
                    char_index = x - start_x
                    if char_index < len(text):
                        line.append(f"[{self.col_green}]{text[char_index]}[/{self.col_green}]")
                    else:
                        line.append(f"[{self.col_green}]{random.choice(char_set)}[/{self.col_green}]")
                else:
                    # Matrix character
                    line.append(f"[dim {self.col_green}]{random.choice(char_set)}[/dim {self.col_green}]")
            lines.append(''.join(line))
        
        return lines
    
    def create_pattern_rain(self, pattern: str, effect: dict) -> List[List[str]]:
        """Create pattern-based rain"""
        width, height = self.get_terminal_size()
        lines = []
        
        patterns = {
            'diagonal': lambda x, y: (x + y) % 5 == 0,
            'spiral': lambda x, y: (x - width//2)**2 + (y - height//2)**2 < (min(width, height)//4)**2,
            'wave': lambda x, y: abs(x - width//2) < 5 or abs(y - height//2) < 3,
            'random': lambda x, y: random.random() < effect['density']
        }
        
        pattern_func = patterns.get(pattern, patterns['random'])
        
        for y in range(height):
            line = []
            for x in range(width):
                if pattern_func(x, y):
                    line.append(f"[{self.col_green}]█[/{self.col_green}]")
                else:
                    line.append(' ')
            lines.append(''.join(line))
        
        return lines
    
    def animate_matrix_rain(self, duration: int, char_set: str = 'classic', effect: str = 'classic', color_scheme: str = 'classic'):
        """Animate matrix rain with modern effects"""
        width, height = self.get_terminal_size()
        end_time = time.time() + duration
        
        # Get settings
        effect_settings = self.effects.get(effect, self.effects['classic'])
        colors = self.color_schemes.get(color_scheme, self.color_schemes['classic'])
        chars = self.char_sets.get(char_set, self.char_sets['classic'])
        
        # Initialize columns
        columns = []
        for _ in range(width):
            columns.append(self.create_matrix_column(height, chars, effect_settings, colors))
        
        try:
            while time.time() < end_time and self.running:
                # Update columns
                for i in range(width):
                    if random.random() < effect_settings['density']:
                        columns[i] = self.create_matrix_column(height, chars, effect_settings, colors)
                
                # Display frame
                self.console.clear()
                for y in range(height):
                    line = []
                    for x in range(width):
                        line.append(columns[x][y])
                    self.console.print(''.join(line))
                
                time.sleep(effect_settings['speed'])
                
        except KeyboardInterrupt:
            self.running = False
    
    def animate_text_reveal(self, text: str, duration: int, char_set: str = 'classic'):
        """Animate text reveal in matrix"""
        width, height = self.get_terminal_size()
        end_time = time.time() + duration
        
        chars = self.char_sets.get(char_set, self.char_sets['classic'])
        
        try:
            while time.time() < end_time and self.running:
                # Create text reveal
                lines = self.create_text_reveal(text, chars, self.effects['classic'])
                
                # Display
                self.console.clear()
                for line in lines:
                    self.console.print(line)
                
                time.sleep(0.1)
                
        except KeyboardInterrupt:
            self.running = False
    
    def animate_pattern_rain(self, pattern: str, duration: int):
        """Animate pattern-based rain"""
        end_time = time.time() + duration
        
        try:
            while time.time() < end_time and self.running:
                # Create pattern
                lines = self.create_pattern_rain(pattern, self.effects['dense'])
                
                # Display
                self.console.clear()
                for line in lines:
                    self.console.print(line)
                
                time.sleep(0.1)
                
        except KeyboardInterrupt:
            self.running = False
    
    def display_effect_options(self):
        """Display available effects and options"""
        # Character sets
        char_table = Table(
            title=f"[bold {self.col_purple}]📝 CHARACTER SETS 📝[/bold {self.col_purple}]",
            box=box.ROUNDED,
            show_header=True
        )
        char_table.add_column("Set", style=f"bold {self.col_cyan}")
        char_table.add_column("Description", style=f"bold {self.col_gold}")
        char_table.add_column("Best For", style=f"bold {self.col_pink}")
        
        char_sets_info = [
            ("Classic", "Standard ASCII + symbols", "Traditional Matrix"),
            ("Japanese", "Katakana characters", "Authentic Matrix"),
            ("Cyber", "Unicode blocks and shapes", "Modern cyberpunk"),
            ("Binary", "0s and 1s only", "Digital theme"),
            ("Hex", "Hexadecimal digits", "Programming theme"),
            ("Glitch", "Mixed characters", "Corrupted effect")
        ]
        
        for name, desc, best in char_sets_info:
            char_table.add_row(name, desc, best)
        
        # Effects
        effect_table = Table(
            title=f"[bold {self.col_purple}]⚡ ANIMATION EFFECTS ⚡[/bold {self.col_purple}]",
            box=box.ROUNDED,
            show_header=True
        )
        effect_table.add_column("Effect", style=f"bold {self.col_cyan}")
        effect_table.add_column("Speed", style=f"bold {self.col_gold}")
        effect_table.add_column("Density", style=f"bold {self.col_pink}")
        effect_table.add_column("Description", style=f"bold {self.col_dim}")
        
        effects_info = [
            ("Classic", "Normal", "Medium", "Traditional Matrix rain"),
            ("Fast", "Fast", "High", "Rapid falling characters"),
            ("Slow", "Slow", "Low", "Relaxed animation"),
            ("Dense", "Normal", "High", "Many characters"),
            ("Sparse", "Normal", "Low", "Few characters"),
            ("Glitch", "Very Fast", "Very High", "Corrupted digital effect")
        ]
        
        for name, speed, density, desc in effects_info:
            effect_table.add_row(name, speed, density, desc)
        
        # Color schemes
        color_table = Table(
            title=f"[bold {self.col_purple}]🎨 COLOR SCHEMES 🎨[/bold {self.col_purple}]",
            box=box.ROUNDED,
            show_header=True
        )
        color_table.add_column("Scheme", style=f"bold {self.col_cyan}")
        color_table.add_column("Colors", style=f"bold {self.col_gold}")
        color_table.add_column("Vibe", style=f"bold {self.col_pink}")
        
        color_schemes_info = [
            ("Classic", "Green gradient", "Original Matrix"),
            ("Neon", "Multi-colored", "Cyberpunk"),
            ("Ocean", "Blue gradient", "Underwater"),
            ("Fire", "Red-orange gradient", "Burning"),
            ("Purple", "Purple gradient", "Mystical")
        ]
        
        for name, colors, vibe in color_schemes_info:
            color_table.add_row(name, colors, vibe)
        
        self.console.print("\n")
        self.console.print(Align.center(char_table))
        self.console.print("\n")
        self.console.print(Align.center(effect_table))
        self.console.print("\n")
        self.console.print(Align.center(color_table))
    
    def run(self):
        """Run modern matrix rain"""
        c = self.console
        
        # Modern header
        c.print()
        c.print(Align.center(Panel(
            f"[bold {self.col_neon}]🌊 MODERN MATRIX RAIN 🌊[/bold {self.col_neon}]\n\n"
            f"[{self.col_dim}]Professional Matrix-style falling characters animation\\n"
            f"Multiple character sets, effects, colors, and patterns\\n"
            f"Modern UI with smooth animations and customizable options[/{self.col_dim}]",
            border_style=self.col_neon,
            box=box.ROUNDED,
            padding=(1, 4)
        )))
        
        while True:
            c.print(f"\n[{self.col_neon}]🌊 Matrix Rain Options:[/{self.col_neon}]")
            c.print(f"  1. Classic Matrix Rain")
            c.print(f"  2. Text Reveal Effect")
            c.print(f"  3. Pattern Rain")
            c.print(f"  4. Custom Animation")
            c.print(f"  5. Effect Showcase")
            c.print(f"  6. Quick Start (Classic)")
            
            choice = Prompt.ask(f"\n[{self.col_neon}]Select option (1-6)[/{self.col_neon}]")
            
            if choice == '1':
                # Classic Matrix Rain
                c.print(f"\n[{self.col_cyan}]Character Sets:[/{self.col_cyan}]")
                char_sets = list(self.char_sets.keys())
                for i, char_set in enumerate(char_sets, 1):
                    c.print(f"  {i}. {char_set.title()}")
                
                char_choice = Prompt.ask(f"\n[{self.col_neon}]Select character set (1-{len(char_sets)})[/{self.col_neon}]")
                
                try:
                    char_index = int(char_choice) - 1
                    if 0 <= char_index < len(char_sets):
                        selected_char_set = char_sets[char_index]
                    else:
                        c.print(f"[{self.col_danger}]✗ Invalid character set[/{self.col_danger}]")
                        continue
                except ValueError:
                    c.print(f"[{self.col_danger}]✗ Invalid input[/{self.col_danger}]")
                    continue
                
                c.print(f"\n[{self.col_cyan}]Effects:[/{self.col_cyan}]")
                effects = list(self.effects.keys())
                for i, effect in enumerate(effects, 1):
                    c.print(f"  {i}. {effect.title()}")
                
                effect_choice = Prompt.ask(f"\n[{self.col_neon}]Select effect (1-{len(effects)})[/{self.col_neon}]")
                
                try:
                    effect_index = int(effect_choice) - 1
                    if 0 <= effect_index < len(effects):
                        selected_effect = effects[effect_index]
                    else:
                        c.print(f"[{self.col_danger}]✗ Invalid effect[/{self.col_danger}]")
                        continue
                except ValueError:
                    c.print(f"[{self.col_danger}]✗ Invalid input[/{self.col_danger}]")
                    continue
                
                c.print(f"\n[{self.col_cyan}]Color Schemes:[/{self.col_cyan}]")
                color_schemes = list(self.color_schemes.keys())
                for i, scheme in enumerate(color_schemes, 1):
                    c.print(f"  {i}. {scheme.title()}")
                
                color_choice = Prompt.ask(f"\n[{self.col_neon}]Select color scheme (1-{len(color_schemes)})[/{self.col_neon}]")
                
                try:
                    color_index = int(color_choice) - 1
                    if 0 <= color_index < len(color_schemes):
                        selected_color = color_schemes[color_index]
                    else:
                        c.print(f"[{self.col_danger}]✗ Invalid color scheme[/{self.col_danger}]")
                        continue
                except ValueError:
                    c.print(f"[{self.col_danger}]✗ Invalid input[/{self.col_danger}]")
                    continue
                
                duration = Prompt.ask(f"\n[{self.col_neon}]Duration in seconds (default: 10)[/{self.col_neon}]") or "10"
                try:
                    duration = int(duration)
                    if duration <= 0:
                        c.print(f"[{self.col_danger}]✗ Duration must be positive[/{self.col_danger}]")
                        continue
                except ValueError:
                    c.print(f"[{self.col_danger}]✗ Invalid duration[/{self.col_danger}]")
                    continue
                
                c.print(f"\n[{self.col_success}]🌊 Starting Matrix Rain...[/{self.col_success}]")
                c.print(f"[{self.col_dim}]Press Ctrl+C to stop[/{self.col_dim}]")
                c.input(f"[{self.col_dim}]Press Enter to start...[/{self.col_dim}]")
                
                self.running = True
                self.animate_matrix_rain(duration, selected_char_set, selected_effect, selected_color)
                
            elif choice == '2':
                # Text Reveal Effect
                text = Prompt.ask(f"\n[{self.col_neon}]Enter text to reveal[/{self.col_neon}]")
                if not text:
                    c.print(f"[{self.col_danger}]✗ Text cannot be empty[/{self.col_danger}]")
                    continue
                
                c.print(f"\n[{self.col_cyan}]Character Sets:[/{self.col_cyan}]")
                char_sets = list(self.char_sets.keys())
                for i, char_set in enumerate(char_sets, 1):
                    c.print(f"  {i}. {char_set.title()}")
                
                char_choice = Prompt.ask(f"\n[{self.col_neon}]Select character set (1-{len(char_sets)})[/{self.col_neon}]")
                
                try:
                    char_index = int(char_choice) - 1
                    if 0 <= char_index < len(char_sets):
                        selected_char_set = char_sets[char_index]
                    else:
                        c.print(f"[{self.col_danger}]✗ Invalid character set[/{self.col_danger}]")
                        continue
                except ValueError:
                    c.print(f"[{self.col_danger}]✗ Invalid input[/{self.col_danger}]")
                    continue
                
                duration = Prompt.ask(f"\n[{self.col_neon}]Duration in seconds (default: 10)[/{self.col_neon}]") or "10"
                try:
                    duration = int(duration)
                    if duration <= 0:
                        c.print(f"[{self.col_danger}]✗ Duration must be positive[/{self.col_danger}]")
                        continue
                except ValueError:
                    c.print(f"[{self.col_danger}]✗ Invalid duration[/{self.col_danger}]")
                    continue
                
                c.print(f"\n[{self.col_success}]🌊 Starting Text Reveal...[/{self.col_success}]")
                c.print(f"[{self.col_dim}]Press Ctrl+C to stop[/{self.col_dim}]")
                c.input(f"[{self.col_dim}]Press Enter to start...[/{self.col_dim}]")
                
                self.running = True
                self.animate_text_reveal(text, duration, selected_char_set)
                
            elif choice == '3':
                # Pattern Rain
                c.print(f"\n[{self.col_cyan}]Available Patterns:[/{self.col_cyan}]")
                patterns = ['diagonal', 'spiral', 'wave', 'random']
                for i, pattern in enumerate(patterns, 1):
                    c.print(f"  {i}. {pattern.title()}")
                
                pattern_choice = Prompt.ask(f"\n[{self.col_neon}]Select pattern (1-4)[/{self.col_neon}]")
                
                try:
                    pattern_index = int(pattern_choice) - 1
                    if 0 <= pattern_index < len(patterns):
                        selected_pattern = patterns[pattern_index]
                    else:
                        c.print(f"[{self.col_danger}]✗ Invalid pattern[/{self.col_danger}]")
                        continue
                except ValueError:
                    c.print(f"[{self.col_danger}]✗ Invalid input[/{self.col_danger}]")
                    continue
                
                duration = Prompt.ask(f"\n[{self.col_neon}]Duration in seconds (default: 10)[/{self.col_neon}]") or "10"
                try:
                    duration = int(duration)
                    if duration <= 0:
                        c.print(f"[{self.col_danger}]✗ Duration must be positive[/{self.col_danger}]")
                        continue
                except ValueError:
                    c.print(f"[{self.col_danger}]✗ Invalid duration[/{self.col_danger}]")
                    continue
                
                c.print(f"\n[{self.col_success}]🌊 Starting Pattern Rain...[/{self.col_success}]")
                c.print(f"[{self.col_dim}]Press Ctrl+C to stop[/{self.col_dim}]")
                c.input(f"[{self.col_dim}]Press Enter to start...[/{self.col_dim}]")
                
                self.running = True
                self.animate_pattern_rain(selected_pattern, duration)
                
            elif choice == '4':
                # Custom Animation
                c.print(f"\n[{self.col_neon}]🎨 Custom Animation Creator 🎨[/{self.col_neon}]")
                c.print(f"[{self.col_dim}]Create your own matrix rain configuration[/{self.col_dim}]")
                
                # Get custom settings
                text = Prompt.ask(f"\n[{self.col_neon}]Enter text (optional, press Enter for none)[/{self.col_neon}]")
                
                if text:
                    # Text reveal mode
                    duration = Prompt.ask(f"[{self.col_neon}]Duration in seconds (default: 15)[/{self.col_neon}]") or "15"
                    try:
                        duration = int(duration)
                    except ValueError:
                        duration = 15
                    
                    c.print(f"\n[{self.col_success}]🌊 Starting Custom Text Reveal...[/{self.col_success}]")
                    c.print(f"[{self.col_dim}]Press Ctrl+C to stop[/{self.col_dim}]")
                    c.input(f"[{self.col_dim}]Press Enter to start...[/{self.col_dim}]")
                    
                    self.running = True
                    self.animate_text_reveal(text, duration, 'glitch')
                else:
                    # Matrix rain mode
                    duration = Prompt.ask(f"[{self.col_neon}]Duration in seconds (default: 20)[/{self.col_neon}]") or "20"
                    try:
                        duration = int(duration)
                    except ValueError:
                        duration = 20
                    
                    c.print(f"\n[{self.col_success}]🌊 Starting Custom Matrix Rain...[/{self.col_success}]")
                    c.print(f"[{self.col_dim}]Press Ctrl+C to stop[/{self.col_dim}]")
                    c.input(f"[{self.col_dim}]Press Enter to start...[/{self.col_dim}]")
                    
                    self.running = True
                    self.animate_matrix_rain(duration, 'glitch', 'glitch', 'neon')
                
            elif choice == '5':
                # Effect Showcase
                self.display_effect_options()
                
            elif choice == '6':
                # Quick Start
                c.print(f"\n[{self.col_success}]🌊 Starting Classic Matrix Rain...[/{self.col_success}]")
                c.print(f"[{self.col_dim}]Press Ctrl+C to stop[/{self.col_dim}]")
                c.input(f"[{self.col_dim}]Press Enter to start...[/{self.col_dim}]")
                
                self.running = True
                self.animate_matrix_rain(10, 'classic', 'classic', 'classic')
                
            else:
                c.print(f"[{self.col_danger}]✗ Invalid choice[/{self.col_danger}]")
                continue
            
            if not Confirm.ask(f"\n[{self.col_neon}]Run another animation? (y/n)[/{self.col_neon}]"):
                break
