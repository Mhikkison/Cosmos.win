"""
Modern ASCII Art Generator
Professional ASCII art generator with advanced features and modern UI
"""

import os
import time
import random
import textwrap
from typing import Dict, List, Tuple, Optional
from rich.console import Console
from rich.panel import Panel
from rich.align import Align
from rich import box
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich.layout import Layout

class ModernASCIIArtGenerator:
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
        self.col_cyan = "#4fc3f7"
        
        # Enhanced ASCII art fonts with more characters
        self.fonts = {
            'block': {
                'A': ['  █  ', ' █ █ ', '█████', '█   █', '█   █'],
                'B': ['████ ', '█   █', '████ ', '█   █', '████ '],
                'C': [' ████', '█    ', '█    ', '█    ', ' ████'],
                'D': ['████ ', '█   █', '█   █', '█   █', '████ '],
                'E': ['█████', '█    ', '███  ', '█    ', '█████'],
                'F': ['█████', '█    ', '███  ', '█    ', '█    '],
                'G': [' ████', '█    ', '█  ██', '█   █', ' ████'],
                'H': ['█   █', '█   █', '█████', '█   █', '█   █'],
                'I': ['█████', '  █  ', '  █  ', '  █  ', '█████'],
                'J': ['  ███', '    █', '    █', '█   █', ' ███ '],
                'K': ['█   █', '█  █ ', '███  ', '█  █ ', '█   █'],
                'L': ['█    ', '█    ', '█    ', '█    ', '█████'],
                'M': ['█   █', '██ ██', '█ █ █', '█   █', '█   █'],
                'N': ['█   █', '██  █', '█ █ █', '█  ██', '█   █'],
                'O': [' ███ ', '█   █', '█   █', '█   █', ' ███ '],
                'P': ['████ ', '█   █', '████ ', '█    ', '█    '],
                'Q': [' ███ ', '█   █', '█   █', '█  ██', ' ████'],
                'R': ['████ ', '█   █', '████ ', '█  █ ', '█   █'],
                'S': [' ████', '█    ', ' ███ ', '    █', '████ '],
                'T': ['█████', '  █  ', '  █  ', '  █  ', '  █  '],
                'U': ['█   █', '█   █', '█   █', '█   █', ' ███ '],
                'V': ['█   █', '█   █', '█   █', ' █ █ ', '  █  '],
                'W': ['█   █', '█   █', '█ █ █', '██ ██', '█   █'],
                'X': ['█   █', ' █ █ ', '  █  ', ' █ █ ', '█   █'],
                'Y': ['█   █', ' █ █ ', '  █  ', '  █  ', '  █  '],
                'Z': ['█████', '   █ ', '  █  ', ' █   ', '█████'],
                ' ': ['     ', '     ', '     ', '     ', '     '],
                '!': ['  █  ', '  █  ', '  █  ', '     ', '  █  '],
                '?': [' ███ ', '█   █', '  █  ', '     ', '  █  '],
                '.': ['     ', '     ', '     ', '     ', '  █  '],
                ',': ['     ', '     ', '     ', '  █  ', ' █   '],
                '0': [' ███ ', '█   █', '█   █', '█   █', ' ███ '],
                '1': ['  █  ', ' ██  ', '  █  ', '  █  ', '█████'],
                '2': [' ███ ', '█   █', '   █ ', '  █  ', '█████'],
                '3': [' ███ ', '█   █', '  ██ ', '█   █', ' ███ '],
                '4': ['█   █', '█   █', '█████', '    █', '    █'],
                '5': ['█████', '█    ', '████ ', '    █', '████ '],
                '6': [' ███ ', '█    ', '████ ', '█   █', ' ███ '],
                '7': ['█████', '    █', '   █ ', '  █  ', '  █  '],
                '8': [' ███ ', '█   █', ' ███ ', '█   █', ' ███ '],
                '9': [' ███ ', '█   █', ' ████', '    █', ' ███ '],
            },
            'simple': {
                'A': [' █ ', '███', '█ █', '█ █'],
                'B': ['██ ', '██ ', '███', '██ '],
                'C': ['███', '█  ', '█  ', '███'],
                'D': ['██ ', '██ ', '█ █', '██ '],
                'E': ['███', '██ ', '██ ', '███'],
                'F': ['███', '██ ', '██ ', '█  '],
                'G': ['███', '█  ', '███', '███'],
                'H': ['█ █', '███', '█ █', '█ █'],
                'I': ['███', ' █ ', ' █ ', '███'],
                'J': [' █ ', ' █ ', ' █ ', '██ '],
                'K': ['█ █', '██ ', '██ ', '█ █'],
                'L': ['█  ', '█  ', '█  ', '███'],
                'M': ['█ █', '███', '█ █', '█ █'],
                'N': ['██ ', '██ ', '█ █', '█ █'],
                'O': ['██ ', '█ █', '█ █', '██ '],
                'P': ['███', '█ █', '██ ', '█  '],
                'Q': ['██ ', '█ █', '███', '███'],
                'R': ['███', '█ █', '██ ', '█ █'],
                'S': ['███', '█  ', ' ██', '███'],
                'T': ['███', ' █ ', ' █ ', ' █ '],
                'U': ['█ █', '█ █', '█ █', '██ '],
                'V': ['█ █', '█ █', '█ █', ' █ '],
                'W': ['█ █', '█ █', '███', '█ █'],
                'X': ['█ █', ' █ ', ' █ ', '█ █'],
                'Y': ['█ █', ' █ ', ' █ ', ' █ '],
                'Z': ['███', '  █ ', ' █  ', '███'],
                ' ': ['   ', '   ', '   ', '   '],
                '!': ['█ ', '█ ', '█ ', '█ '],
                '?': ['██ ', ' █ ', '  ', '█ '],
                '.': ['   ', '   ', '   ', '█ '],
                ',': ['   ', '   ', '█ ', '█ '],
                '0': ['██ ', '█ █', '█ █', '██ '],
                '1': ['█ ', '██ ', ' █ ', '███'],
                '2': ['██ ', ' █ ', '  ', '███'],
                '3': ['██ ', '  ', ' ██', '██ '],
                '4': ['█ █', '█ █', '███', '  █'],
                '5': ['███', '██ ', '  ', '██ '],
                '6': ['██ ', '██ ', '███', '██ '],
                '7': ['███', '  ', '  ', '  '],
                '8': ['██ ', '██ ', '██ ', '██ '],
                '9': ['██ ', '███', '  ', '██ '],
            }
        }
        
        # Modern patterns and styles
        self.patterns = {
            'heart': ['❤️', '💙', '💚', '💛', '💜', '🧡'],
            'star': ['⭐', '✨', '💫', '⚡', '🌟'],
            'fire': ['🔥', '💥', '⚡', '🔥', '💥'],
            'diamond': ['💎', '💍', '✨', '💎', '🌟'],
            'cyber': ['▓', '▒', '░', '█', '▓'],
            'neon': ['◉', '◎', '●', '◉', '◎']
        }
        
        # Border styles
        self.border_styles = {
            'modern': box.ROUNDED,
            'classic': box.DOUBLE,
            'minimal': box.SIMPLE,
            'heavy': box.HEAVY,
            'ascii': box.ASCII
        }
    
    def get_terminal_size(self) -> Tuple[int, int]:
        """Get terminal dimensions safely"""
        try:
            import shutil
            return shutil.get_terminal_size()
        except:
            return (80, 24)
    
    def create_ascii_art(self, text: str, font: str = 'block') -> List[str]:
        """Create ASCII art from text"""
        if font not in self.fonts:
            font = 'block'
        
        # Convert to uppercase for better ASCII representation
        text = text.upper()
        font_data = self.fonts[font]
        
        # Initialize result lines
        result_lines = [[] for _ in range(5 if font == 'block' else 4)]
        
        # Process each character
        for char in text:
            if char in font_data:
                char_lines = font_data[char]
                for i, line in enumerate(char_lines):
                    result_lines[i].append(line)
            else:
                # Handle unsupported characters
                for i in range(len(result_lines)):
                    result_lines[i].append('     ' if font == 'block' else '   ')
        
        # Join lines
        return [''.join(line) for line in result_lines]
    
    def create_pattern_art(self, text: str, pattern: str = 'heart') -> List[str]:
        """Create pattern-based art"""
        if pattern not in self.patterns:
            pattern = 'heart'
        
        patterns = self.patterns[pattern]
        lines = []
        
        for char in text:
            if char == ' ':
                lines.append('  ')
            else:
                pattern_char = random.choice(patterns)
                lines.append(f'{pattern_char} ')
        
        # Create multiple lines for height
        result = []
        for _ in range(3):
            result.append(''.join(lines))
        
        return result
    
    def create_box_art(self, text: str, style: str = 'modern') -> List[str]:
        """Create boxed ASCII art"""
        if style not in self.border_styles:
            style = 'modern'
        
        box_chars = {
            'modern': {'h': '─', 'v': '│', 'tl': '╭', 'tr': '╮', 'bl': '╰', 'br': '╯'},
            'classic': {'h': '═', 'v': '║', 'tl': '╔', 'tr': '╗', 'bl': '╚', 'br': '╝'},
            'minimal': {'h': '-', 'v': '|', 'tl': '+', 'tr': '+', 'bl': '+', 'br': '+'},
            'heavy': {'h': '━', 'v': '┃', 'tl': '┏', 'tr': '┓', 'bl': '┗', 'br': '┛'},
            'ascii': {'h': '-', 'v': '|', 'tl': '+', 'tr': '+', 'bl': '+', 'br': '+'}
        }
        
        chars = box_chars[style]
        max_len = len(text)
        
        # Create box
        top = f"{chars['tl']}{chars['h'] * (max_len + 2)}{chars['tr']}"
        middle = f"{chars['v']} {text} {chars['v']}"
        bottom = f"{chars['bl']}{chars['h'] * (max_len + 2)}{chars['br']}"
        
        return [top, middle, bottom]
    
    def create_gradient_art(self, text: str) -> List[str]:
        """Create gradient ASCII art"""
        gradient_chars = ['░', '▒', '▓', '█']
        lines = []
        
        for i, char in enumerate(text):
            if char == ' ':
                lines.append('  ')
            else:
                # Use gradient based on position
                gradient_index = i % len(gradient_chars)
                lines.append(f'{gradient_chars[gradient_index]}{char} ')
        
        return [''.join(lines)]
    
    def create_3d_art(self, text: str) -> List[str]:
        """Create 3D ASCII art effect"""
        lines = []
        
        for char in text:
            if char == ' ':
                lines.append('   ')
            else:
                # Create 3D effect with shadows
                lines.append(f'{char}░')
        
        return [''.join(lines), ''.join([' ░' for _ in text])]
    
    def display_art_with_animation(self, art_lines: List[str], title: str = "ASCII Art"):
        """Display art with modern animation"""
        # Display title
        self.console.print(Align.center(Panel(
            f"[bold {self.col_neon}]🎨 {title} 🎨[/bold {self.col_neon}]",
            border_style=self.col_neon,
            box=box.ROUNDED
        )))
        
        # Animate display
        for i, line in enumerate(art_lines):
            # Create typing effect
            displayed_line = ""
            for char in line:
                displayed_line += char
                self.console.print(f"[{self.col_gold}]{displayed_line}[/{self.col_gold}]", end="\r")
                time.sleep(0.01)
            self.console.print()  # Move to next line
            time.sleep(0.05)
    
    def display_art_options(self):
        """Display available art options"""
        table = Table(
            title=f"[bold {self.col_purple}]🎨 ART STYLES 🎨[/bold {self.col_purple}]",
            box=box.ROUNDED,
            show_header=True
        )
        table.add_column("Style", style=f"bold {self.col_cyan}")
        table.add_column("Description", style=f"bold {self.col_gold}")
        table.add_column("Best For", style=f"bold {self.col_pink}")
        
        styles = [
            ("Block", "Large block letters", "Headers, titles"),
            ("Simple", "Compact letters", "Quick text"),
            ("Pattern", "Emoji patterns", "Fun, decorative"),
            ("Box", "Text in boxes", "Emphasis"),
            ("Gradient", "Gradient effect", "Modern look"),
            ("3D", "3D shadow effect", "Depth")
        ]
        
        for style, desc, best in styles:
            table.add_row(style, desc, best)
        
        self.console.print("\n")
        self.console.print(Align.center(table))
    
    def save_art_to_file(self, art_lines: List[str], filename: str, title: str = ""):
        """Save art to file with modern formatting"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                if title:
                    f.write(f"{title}\n")
                    f.write("=" * len(title) + "\n\n")
                
                for line in art_lines:
                    f.write(line + "\n")
                
                f.write("\n" + "=" * 50 + "\n")
                f.write("Generated by Cosmos.win Modern ASCII Art Generator\n")
            
            return True
        except Exception as e:
            return False
    
    def create_art_gallery(self, text: str) -> Dict[str, List[str]]:
        """Create multiple art styles for gallery"""
        gallery = {}
        
        # Generate different styles
        gallery['Block'] = self.create_ascii_art(text, 'block')
        gallery['Simple'] = self.create_ascii_art(text, 'simple')
        gallery['Heart Pattern'] = self.create_pattern_art(text, 'heart')
        gallery['Star Pattern'] = self.create_pattern_art(text, 'star')
        gallery['Modern Box'] = self.create_box_art(text, 'modern')
        gallery['Classic Box'] = self.create_box_art(text, 'classic')
        gallery['Gradient'] = self.create_gradient_art(text)
        gallery['3D Effect'] = self.create_3d_art(text)
        
        return gallery
    
    def display_gallery(self, gallery: Dict[str, List[str]]):
        """Display art gallery in columns"""
        panels = []
        
        for style, art_lines in gallery.items():
            # Create panel for each style
            art_text = '\n'.join(art_lines)
            panel = Panel(
                f"[{self.col_gold}]{art_text}[/{self.col_gold}]",
                title=f"[bold {self.col_cyan}]{style}[/bold {self.col_cyan}]",
                border_style=self.col_purple,
                box=box.ROUNDED,
                padding=(1, 2)
            )
            panels.append(panel)
        
        # Display in columns
        columns = Columns(panels, equal=True, expand=True)
        self.console.print("\n")
        self.console.print(Align.center(columns))
    
    def run(self):
        """Run modern ASCII art generator"""
        c = self.console
        
        # Modern header
        c.print()
        c.print(Align.center(Panel(
            f"[bold {self.col_neon}]🎨 MODERN ASCII ART GENERATOR 🎨[/bold {self.col_neon}]\n\n"
            f"[{self.col_dim}]Professional ASCII art with advanced features\\n"
            f"Multiple styles, patterns, animations, and export options\\n"
            f"Modern UI with gradient effects and smooth animations[/{self.col_dim}]",
            border_style=self.col_neon,
            box=box.ROUNDED,
            padding=(1, 4)
        )))
        
        while True:
            c.print(f"\n[{self.col_neon}]🎨 Art Creation Options:[/{self.col_neon}]")
            c.print(f"  1. Create ASCII Art")
            c.print(f"  2. Art Gallery")
            c.print(f"  3. Pattern Art")
            c.print(f"  4. Box Art")
            c.print(f"  5. Gradient Art")
            c.print(f"  6. 3D Art")
            c.print(f"  7. Style Showcase")
            c.print(f"  8. Batch Generator")
            
            choice = Prompt.ask(f"\n[{self.col_neon}]Select option (1-8)[/{self.col_neon}]")
            
            if choice == '1':
                # Create ASCII Art
                text = Prompt.ask(f"[{self.col_neon}]Enter text to convert[/{self.col_neon}]")
                if not text:
                    c.print(f"[{self.col_danger}]✗ Text cannot be empty[/{self.col_danger}]")
                    continue
                
                c.print(f"\n[{self.col_cyan}]Available fonts:[/{self.col_cyan}]")
                c.print(f"  1. Block (Large)")
                c.print(f"  2. Simple (Compact)")
                
                font_choice = Prompt.ask(f"\n[{self.col_neon}]Select font (1-2)[/{self.col_neon}]")
                font = 'block' if font_choice == '1' else 'simple'
                
                # Generate art with animation
                with Progress(
                    SpinnerColumn(style=f"bold {self.col_neon}"),
                    TextColumn("[bold bright_white]Generating ASCII art...[/bold bright_white]"),
                    BarColumn(bar_width=30, style=f"dim {self.col_dim}", complete_style=f"bold {self.col_neon}"),
                    console=c,
                    transient=True
                ) as progress:
                    task = progress.add_task("Creating art...", total=100)
                    
                    art_lines = self.create_ascii_art(text, font)
                    
                    for i in range(101):
                        progress.update(task, completed=i)
                        if i % 20 == 0:
                            time.sleep(0.05)
                
                # Display with animation
                self.display_art_with_animation(art_lines, f"{font.title()} ASCII Art")
                
                # Save option
                save = Confirm.ask(f"\n[{self.col_neon}]Save this art? (y/n)[/{self.col_neon}]")
                if save:
                    filename = Prompt.ask(f"[{self.col_neon}]Enter filename[/{self.col_neon}]") + '.txt'
                    
                    if self.save_art_to_file(art_lines, filename, f"{font.title()} ASCII Art: {text}"):
                        c.print(f"[{self.col_success}]✓ Saved to {filename}[/{self.col_success}]")
                    else:
                        c.print(f"[{self.col_danger}]✗ Error saving file[/{self.col_danger}]")
                
            elif choice == '2':
                # Art Gallery
                text = Prompt.ask(f"[{self.col_neon}]Enter text for gallery[/{self.col_neon}]")
                if not text:
                    c.print(f"[{self.col_danger}]✗ Text cannot be empty[/{self.col_danger}]")
                    continue
                
                with Progress(
                    SpinnerColumn(style=f"bold {self.col_neon}"),
                    TextColumn("[bold bright_white]Creating gallery...[/bold bright_white]"),
                    BarColumn(bar_width=30, style=f"dim {self.col_dim}", complete_style=f"bold {self.col_neon}"),
                    console=c,
                    transient=True
                ) as progress:
                    task = progress.add_task("Generating gallery...", total=100)
                    
                    gallery = self.create_art_gallery(text)
                    
                    for i in range(101):
                        progress.update(task, completed=i)
                        if i % 20 == 0:
                            time.sleep(0.05)
                
                self.display_gallery(gallery)
                
                # Save gallery
                save = Confirm.ask(f"\n[{self.col_neon}]Save gallery? (y/n)[/{self.col_neon}]")
                if save:
                    filename = Prompt.ask(f"[{self.col_neon}]Enter filename[/{self.col_neon}]") + '.txt'
                    
                    try:
                        with open(filename, 'w', encoding='utf-8') as f:
                            f.write(f"ASCII ART GALLERY: {text}\n")
                            f.write("=" * 50 + "\n\n")
                            
                            for style, art_lines in gallery.items():
                                f.write(f"{style}:\n")
                                f.write("-" * len(style) + "\n")
                                for line in art_lines:
                                    f.write(line + "\n")
                                f.write("\n")
                        
                        c.print(f"[{self.col_success}]✓ Gallery saved to {filename}[/{self.col_success}]")
                    except Exception as e:
                        c.print(f"[{self.col_danger}]✗ Error saving: {e}[/{self.col_danger}]")
                
            elif choice == '3':
                # Pattern Art
                text = Prompt.ask(f"[{self.col_neon}]Enter text for pattern art[/{self.col_neon}]")
                if not text:
                    c.print(f"[{self.col_danger}]✗ Text cannot be empty[/{self.col_danger}]")
                    continue
                
                c.print(f"\n[{self.col_cyan}]Available patterns:[/{self.col_cyan}]")
                patterns = list(self.patterns.keys())
                for i, pattern in enumerate(patterns, 1):
                    c.print(f"  {i}. {pattern.title()}")
                
                pattern_choice = Prompt.ask(f"\n[{self.col_neon}]Select pattern (1-{len(patterns)})[/{self.col_neon}]")
                
                try:
                    pattern_index = int(pattern_choice) - 1
                    if 0 <= pattern_index < len(patterns):
                        pattern = patterns[pattern_index]
                    else:
                        c.print(f"[{self.col_danger}]✗ Invalid pattern[/{self.col_danger}]")
                        continue
                except ValueError:
                    c.print(f"[{self.col_danger}]✗ Invalid input[/{self.col_danger}]")
                    continue
                
                art_lines = self.create_pattern_art(text, pattern)
                self.display_art_with_animation(art_lines, f"{pattern.title()} Pattern Art")
                
            elif choice == '4':
                # Box Art
                text = Prompt.ask(f"[{self.col_neon}]Enter text for box art[/{self.col_neon}]")
                if not text:
                    c.print(f"[{self.col_danger}]✗ Text cannot be empty[/{self.col_danger}]")
                    continue
                
                c.print(f"\n[{self.col_cyan}]Available box styles:[/{self.col_cyan}]")
                styles = list(self.border_styles.keys())
                for i, style in enumerate(styles, 1):
                    c.print(f"  {i}. {style.title()}")
                
                style_choice = Prompt.ask(f"\n[{self.col_neon}]Select style (1-{len(styles)})[/{self.col_neon}]")
                
                try:
                    style_index = int(style_choice) - 1
                    if 0 <= style_index < len(styles):
                        style = styles[style_index]
                    else:
                        c.print(f"[{self.col_danger}]✗ Invalid style[/{self.col_danger}]")
                        continue
                except ValueError:
                    c.print(f"[{self.col_danger}]✗ Invalid input[/{self.col_danger}]")
                    continue
                
                art_lines = self.create_box_art(text, style)
                self.display_art_with_animation(art_lines, f"{style.title()} Box Art")
                
            elif choice == '5':
                # Gradient Art
                text = Prompt.ask(f"[{self.col_neon}]Enter text for gradient art[/{self.col_neon}]")
                if not text:
                    c.print(f"[{self.col_danger}]✗ Text cannot be empty[/{self.col_danger}]")
                    continue
                
                art_lines = self.create_gradient_art(text)
                self.display_art_with_animation(art_lines, "Gradient Art")
                
            elif choice == '6':
                # 3D Art
                text = Prompt.ask(f"[{self.col_neon}]Enter text for 3D art[/{self.col_neon}]")
                if not text:
                    c.print(f"[{self.col_danger}]✗ Text cannot be empty[/{self.col_danger}]")
                    continue
                
                art_lines = self.create_3d_art(text)
                self.display_art_with_animation(art_lines, "3D Art")
                
            elif choice == '7':
                # Style Showcase
                self.display_art_options()
                
            elif choice == '8':
                # Batch Generator
                c.print(f"\n[{self.col_neon}]🔄 Batch Generator 🔄[/{self.col_neon}]")
                c.print(f"[{self.col_dim}]Generate multiple ASCII arts at once[/{self.col_dim}]")
                
                texts = []
                while True:
                    text = Prompt.ask(f"[{self.col_neon}]Enter text (or press Enter to finish)[/{self.col_neon}]")
                    if not text:
                        break
                    texts.append(text)
                
                if not texts:
                    c.print(f"[{self.col_danger}]✗ No texts entered[/{self.col_danger}]")
                    continue
                
                # Generate batch
                with Progress(
                    SpinnerColumn(style=f"bold {self.col_neon}"),
                    TextColumn("[bold bright_white]Generating batch...[/bold bright_white]"),
                    BarColumn(bar_width=40, style=f"dim {self.col_dim}", complete_style=f"bold {self.col_neon}"),
                    console=c,
                    transient=True
                ) as progress:
                    task = progress.add_task("Batch generation...", total=len(texts))
                    
                    for text in texts:
                        art_lines = self.create_ascii_art(text, 'block')
                        
                        # Display each
                        c.print(f"\n[{self.col_cyan}]📝 {text}[/{self.col_cyan}]")
                        for line in art_lines:
                            c.print(f"[{self.col_gold}]{line}[/{self.col_gold}]")
                        
                        progress.update(task, advance=1)
                        time.sleep(0.1)
                
                # Save batch
                save = Confirm.ask(f"\n[{self.col_neon}]Save batch? (y/n)[/{self.col_neon}]")
                if save:
                    filename = Prompt.ask(f"[{self.col_neon}]Enter filename[/{self.col_neon}]") + '.txt'
                    
                    try:
                        with open(filename, 'w', encoding='utf-8') as f:
                            f.write("BATCH ASCII ART GENERATION\n")
                            f.write("=" * 50 + "\n\n")
                            
                            for text in texts:
                                f.write(f"{text}:\n")
                                f.write("-" * len(text) + "\n")
                                art_lines = self.create_ascii_art(text, 'block')
                                for line in art_lines:
                                    f.write(line + "\n")
                                f.write("\n")
                        
                        c.print(f"[{self.col_success}]✓ Batch saved to {filename}[/{self.col_success}]")
                    except Exception as e:
                        c.print(f"[{self.col_danger}]✗ Error saving: {e}[/{self.col_danger}]")
                
            else:
                c.print(f"[{self.col_danger}]✗ Invalid choice[/{self.col_danger}]")
                continue
            
            if not Confirm.ask(f"\n[{self.col_neon}]Create more art? (y/n)[/{self.col_neon}]"):
                break
