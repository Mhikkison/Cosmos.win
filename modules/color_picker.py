"""
Color Picker Tool
Advanced color picker with hex/rgb conversion and color schemes
"""

import os
import random
import colorsys
from rich.console import Console
from rich.panel import Panel
from rich.align import Align
from rich import box
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.table import Table
from rich.columns import Columns

class ColorPicker:
    def __init__(self, console: Console):
        self.console = console
        self.col_neon = "#00ffcc"
        self.col_success = "#00e676"
        self.col_warn = "#ffab00"
        self.col_danger = "#ff1744"
        self.col_pink = "#ff6ec7"
        self.col_gold = "#ffd700"
        self.col_dim = "bright_black"
        
        # Color palettes
        self.color_palettes = {
            'web_safe': [
                "#000000", "#FFFFFF", "#FF0000", "#00FF00", "#0000FF",
                "#FFFF00", "#FF00FF", "#00FFFF", "#800000", "#008000",
                "#000080", "#808000", "#800080", "#008080", "#C0C0C0",
                "#808080", "#FFA500", "#A52A2A", "#800080", "#008080"
            ],
            'material': [
                "#F44336", "#E91E63", "#9C27B0", "#673AB7", "#3F51B5",
                "#2196F3", "#03A9F4", "#00BCD4", "#009688", "#4CAF50",
                "#8BC34A", "#CDDC39", "#FFEB3B", "#FFC107", "#FF9800",
                "#FF5722", "#795548", "#9E9E9E", "#607D8B", "#000000"
            ],
            'pastel': [
                "#FFB3BA", "#FFDFBA", "#FFFFBA", "#BAFFC9", "#BAE1FF",
                "#E0BBE4", "#D4A5A5", "#A8DADC", "#457B9D", "#1D3557",
                "#F1FAEE", "#A8DADC", "#457B9D", "#1D3557", "#E63946"
            ],
            'neon': [
                "#FF073A", "#0FFF50", "#01FFED", "#FF00FF", "#FFFF00",
                "#00FF00", "#FF1493", "#00CED1", "#FFD700", "#FF69B4",
                "#00FFFF", "#FF4500", "#32CD32", "#FF6347", "#4B0082"
            ]
        }
        
        # Color names mapping
        self.color_names = {
            '#FF0000': 'Red', '#00FF00': 'Lime', '#0000FF': 'Blue',
            '#FFFF00': 'Yellow', '#FF00FF': 'Magenta', '#00FFFF': 'Cyan',
            '#000000': 'Black', '#FFFFFF': 'White', '#808080': 'Gray',
            '#800000': 'Maroon', '#008000': 'Green', '#000080': 'Navy',
            '#808000': 'Olive', '#800080': 'Purple', '#008080': 'Teal',
            '#FFA500': 'Orange', '#A52A2A': 'Brown', '#FFC0CB': 'Pink'
        }
    
    def hex_to_rgb(self, hex_color: str) -> tuple:
        """Convert hex color to RGB"""
        hex_color = hex_color.lstrip('#')
        return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
    
    def rgb_to_hex(self, r: int, g: int, b: int) -> str:
        """Convert RGB to hex color"""
        return f"#{r:02X}{g:02X}{b:02X}"
    
    def hex_to_hsl(self, hex_color: str) -> tuple:
        """Convert hex color to HSL"""
        r, g, b = self.hex_to_rgb(hex_color)
        r, g, b = r/255.0, g/255.0, b/255.0
        
        max_val = max(r, g, b)
        min_val = min(r, g, b)
        l = (max_val + min_val) / 2
        
        if max_val == min_val:
            h = s = 0
        else:
            d = max_val - min_val
            s = d / (2 - max_val - min_val) if l > 0.5 else d / (max_val + min_val)
            
            if max_val == r:
                h = (g - b) / d + (6 if g < b else 0)
            elif max_val == g:
                h = (b - r) / d + 2
            else:
                h = (r - g) / d + 4
            
            h /= 12
        
        return (h * 360, s * 100, l * 100)
    
    def generate_color_scheme(self, base_color: str, scheme_type: str = 'complementary') -> list:
        """Generate color schemes based on base color"""
        r, g, b = self.hex_to_rgb(base_color)
        h, s, l = self.hex_to_hsl(base_color)
        
        schemes = {
            'complementary': [
                base_color,
                self.rgb_to_hex(*[int(c * 255) for c in colorsys.hsv_to_rgb((h/360 + 0.5) % 1, s/100, l/100)])
            ],
            'triadic': [
                base_color,
                self.rgb_to_hex(*[int(c * 255) for c in colorsys.hsv_to_rgb((h/360 + 0.33) % 1, s/100, l/100)]),
                self.rgb_to_hex(*[int(c * 255) for c in colorsys.hsv_to_rgb((h/360 + 0.67) % 1, s/100, l/100)])
            ],
            'analogous': [
                base_color,
                self.rgb_to_hex(*[int(c * 255) for c in colorsys.hsv_to_rgb((h/360 + 0.1) % 1, s/100, l/100)]),
                self.rgb_to_hex(*[int(c * 255) for c in colorsys.hsv_to_rgb((h/360 - 0.1) % 1, s/100, l/100)])
            ],
            'monochromatic': [
                base_color,
                self.rgb_to_hex(*[int(c * 255) for c in colorsys.hsv_to_rgb(h/360, s/100, min(l/100 + 0.2, 1))]),
                self.rgb_to_hex(*[int(c * 255) for c in colorsys.hsv_to_rgb(h/360, s/100, max(l/100 - 0.2, 0))])
            ]
        }
        
        return schemes.get(scheme_type, schemes['complementary'])
    
    def display_color_info(self, hex_color: str):
        """Display comprehensive color information"""
        r, g, b = self.hex_to_rgb(hex_color)
        h, s, l = self.hex_to_hsl(hex_color)
        
        # Create color display
        color_display = f"[on {hex_color}]{' ' * 20}[/on {hex_color}]"
        
        # Create info table
        table = Table(
            title=f"[bold {self.col_neon}]Color Information[/bold {self.col_neon}]",
            box=box.ROUNDED,
            show_header=True
        )
        
        table.add_column("Format", style=f"bold {self.col_pink}")
        table.add_column("Value", style=f"bold {self.col_gold}")
        
        table.add_row("HEX", hex_color.upper())
        table.add_row("RGB", f"rgb({r}, {g}, {b})")
        table.add_row("RGB Percent", f"rgb({r/255*100:.1f}%, {g/255*100:.1f}%, {b/255*100:.1f}%)")
        table.add_row("HSL", f"hsl({h:.1f}°, {s:.1f}%, {l:.1f}%)")
        table.add_row("HSV", f"hsv({h:.1f}°, {s:.1f}%, {l:.1f}%)")
        
        # Add color name if known
        color_name = self.color_names.get(hex_color.upper(), "Unknown")
        table.add_row("Name", color_name)
        
        # Display everything
        self.console.print(f"\n{color_display}")
        self.console.print("\n")
        self.console.print(Align.center(table))
    
    def display_color_scheme(self, colors: list, scheme_name: str):
        """Display color scheme"""
        self.console.print(f"\n[bold {self.col_neon}]🎨 {scheme_name.title()} Scheme:[/bold {self.col_neon}]")
        
        # Create color display
        color_row = ""
        for color in colors:
            color_row += f"[on {color}]{' ' * 15}[/on {color}] "
        
        self.console.print(color_row)
        
        # Create table with color info
        table = Table(box=box.ROUNDED)
        table.add_column("Color", style="bold")
        table.add_column("HEX", style=f"bold {self.col_gold}")
        table.add_column("RGB", style=f"bold {self.col_pink}")
        
        for color in colors:
            r, g, b = self.hex_to_rgb(color)
            table.add_row(
                f"[on {color}]{' ' * 8}[/on {color}]",
                color.upper(),
                f"({r}, {g}, {b})"
            )
        
        self.console.print("\n")
        self.console.print(Align.center(table))
    
    def random_color(self) -> str:
        """Generate random color"""
        return f"#{random.randint(0, 255):02X}{random.randint(0, 255):02X}{random.randint(0, 255):02X}"
    
    def run(self):
        """Run color picker tool"""
        c = self.console
        
        # Display header
        c.print()
        c.print(Align.center(Panel(
            f"[bold {self.col_neon}]🎮 COLOR PICKER 🎮[/bold {self.col_neon}]\n\n"
            f"[{self.col_dim}]Advanced color picker with hex/rgb conversion\\n"
            f"Color schemes, palettes, and color analysis\\n"
            f"Perfect for designers and developers[/{self.col_dim}]",
            border_style=self.col_neon,
            box=box.ROUNDED,
            padding=(1, 4)
        )))
        
        while True:
            c.print(f"\n[{self.col_neon}]🎨 Color options:[/{self.col_neon}]")
            c.print(f"  1. Pick Color by HEX")
            c.print(f"  2. Pick Color by RGB")
            c.print(f"  3. Random Color")
            c.print(f"  4. Browse Color Palettes")
            c.print(f"  5. Generate Color Scheme")
            c.print(f"  6. Color Converter")
            c.print(f"  7. Color Analysis")
            
            choice = Prompt.ask(f"\n[{self.col_neon}]Select option (1-7)[/{self.col_neon}]")
            
            if choice == '1':
                hex_color = Prompt.ask(f"[{self.col_neon}]Enter HEX color (e.g., #FF5733)[/{self.col_neon}]")
                if not hex_color.startswith('#'):
                    hex_color = '#' + hex_color
                
                if len(hex_color) == 7 and all(c in '0123456789ABCDEFabcdef' for c in hex_color[1:]):
                    self.display_color_info(hex_color)
                else:
                    c.print(f"[{self.col_danger}]✗ Invalid HEX color format[/{self.col_danger}]")
                
            elif choice == '2':
                try:
                    r = int(Prompt.ask(f"[{self.col_neon}]Enter Red (0-255)[/{self.col_neon}]"))
                    g = int(Prompt.ask(f"[{self.col_neon}]Enter Green (0-255)[/{self.col_neon}]"))
                    b = int(Prompt.ask(f"[{self.col_neon}]Enter Blue (0-255)[/{self.col_neon}]"))
                    
                    if 0 <= r <= 255 and 0 <= g <= 255 and 0 <= b <= 255:
                        hex_color = self.rgb_to_hex(r, g, b)
                        self.display_color_info(hex_color)
                    else:
                        c.print(f"[{self.col_danger}]✗ RGB values must be between 0 and 255[/{self.col_danger}]")
                except ValueError:
                    c.print(f"[{self.col_danger}]✗ Invalid RGB values[/{self.col_danger}]")
                
            elif choice == '3':
                with Progress(
                    SpinnerColumn(style=f"bold {self.col_neon}"),
                    TextColumn("[bold bright_white]Generating random color...[/bold bright_white]"),
                    BarColumn(bar_width=30, style=f"dim {self.col_dim}", complete_style=f"bold {self.col_neon}"),
                    console=c,
                    transient=True
                ) as progress:
                    task = progress.add_task("Randomizing...", total=100)
                    
                    for i in range(101):
                        progress.update(task, completed=i)
                        if i % 20 == 0:
                            import time
                            time.sleep(0.05)
                
                random_color = self.random_color()
                c.print(f"\n[{self.col_success}]✓ Random color generated: {random_color}[/{self.col_success}]")
                self.display_color_info(random_color)
                
            elif choice == '4':
                c.print(f"\n[{self.col_neon}]🎨 Available palettes:[/{self.col_neon}]")
                c.print(f"  1. Web Safe Colors")
                c.print(f"  2. Material Design")
                c.print(f"  3. Pastel Colors")
                c.print(f"  4. Neon Colors")
                
                palette_choice = Prompt.ask(f"\n[{self.col_neon}]Select palette (1-4)[/{self.col_neon}]")
                
                palettes_map = {'1': 'web_safe', '2': 'material', '3': 'pastel', '4': 'neon'}
                palette_name = palettes_map.get(palette_choice, 'web_safe')
                
                if palette_name in self.color_palettes:
                    colors = self.color_palettes[palette_name]
                    c.print(f"\n[bold {self.col_neon}]🎨 {palette_name.title().replace('_', ' ')} Palette:[/bold {self.col_neon}]")
                    
                    # Display colors in rows
                    for i in range(0, len(colors), 10):
                        row_colors = colors[i:i+10]
                        color_row = ""
                        for color in row_colors:
                            color_row += f"[on {color}]{' ' * 8}[/on {color}] "
                        c.print(color_row)
                    
                    # Select color from palette
                    select = Prompt.ask(f"\n[{self.col_neon}]Select a color number (1-{len(colors)}) or press Enter to skip[/{self.col_neon}]")
                    if select:
                        try:
                            index = int(select) - 1
                            if 0 <= index < len(colors):
                                self.display_color_info(colors[index])
                        except ValueError:
                            c.print(f"[{self.col_danger}]✗ Invalid selection[/{self.col_danger}]")
                
            elif choice == '5':
                base_color = Prompt.ask(f"[{self.col_neon}]Enter base HEX color (or 'random')[/{self.col_neon}]")
                if base_color.lower() == 'random':
                    base_color = self.random_color()
                elif not base_color.startswith('#'):
                    base_color = '#' + base_color
                
                c.print(f"\n[{self.col_neon}]🎨 Scheme types:[/{self.col_neon}]")
                c.print(f"  1. Complementary")
                c.print(f"  2. Triadic")
                c.print(f"  3. Analogous")
                c.print(f"  4. Monochromatic")
                
                scheme_choice = Prompt.ask(f"\n[{self.col_neon}]Select scheme type (1-4)[/{self.col_neon}]")
                
                schemes_map = {'1': 'complementary', '2': 'triadic', '3': 'analogous', '4': 'monochromatic'}
                scheme_name = schemes_map.get(scheme_choice, 'complementary')
                
                colors = self.generate_color_scheme(base_color, scheme_name)
                self.display_color_scheme(colors, scheme_name)
                
            elif choice == '6':
                c.print(f"\n[{self.col_neon}]🔄 Color Converter:[/{self.col_neon}]")
                convert_from = Prompt.ask(f"[{self.col_neon}]Convert from (hex/rgb/hsl)[/{self.col_neon}]").lower()
                convert_to = Prompt.ask(f"[{self.col_neon}]Convert to (hex/rgb/hsl)[/{self.col_neon}]").lower()
                
                if convert_from == 'hex':
                    hex_input = Prompt.ask(f"[{self.col_neon}]Enter HEX color[/{self.col_neon}]")
                    if not hex_input.startswith('#'):
                        hex_input = '#' + hex_input
                    
                    if convert_to == 'rgb':
                        r, g, b = self.hex_to_rgb(hex_input)
                        c.print(f"[{self.col_success}]✓ RGB: rgb({r}, {g}, {b})[/{self.col_success}]")
                    elif convert_to == 'hsl':
                        h, s, l = self.hex_to_hsl(hex_input)
                        c.print(f"[{self.col_success}]✓ HSL: hsl({h:.1f}°, {s:.1f}%, {l:.1f}%)[/{self.col_success}]")
                    else:
                        c.print(f"[{self.col_success}]✓ HEX: {hex_input.upper()}[/{self.col_success}]")
                
                elif convert_from == 'rgb':
                    try:
                        r = int(Prompt.ask(f"[{self.col_neon}]Enter Red (0-255)[/{self.col_neon}]"))
                        g = int(Prompt.ask(f"[{self.col_neon}]Enter Green (0-255)[/{self.col_neon}]"))
                        b = int(Prompt.ask(f"[{self.col_neon}]Enter Blue (0-255)[/{self.col_neon}]"))
                        
                        if 0 <= r <= 255 and 0 <= g <= 255 and 0 <= b <= 255:
                            hex_color = self.rgb_to_hex(r, g, b)
                            
                            if convert_to == 'hex':
                                c.print(f"[{self.col_success}]✓ HEX: {hex_color}[/{self.col_success}]")
                            elif convert_to == 'hsl':
                                h, s, l = self.hex_to_hsl(hex_color)
                                c.print(f"[{self.col_success}]✓ HSL: hsl({h:.1f}°, {s:.1f}%, {l:.1f}%)[/{self.col_success}]")
                            else:
                                c.print(f"[{self.col_success}]✓ RGB: rgb({r}, {g}, {b})[/{self.col_success}]")
                        else:
                            c.print(f"[{self.col_danger}]✗ RGB values must be between 0 and 255[/{self.col_danger}]")
                    except ValueError:
                        c.print(f"[{self.col_danger}]✗ Invalid RGB values[/{self.col_danger}]")
                
            elif choice == '7':
                hex_color = Prompt.ask(f"[{self.col_neon}]Enter HEX color for analysis[/{self.col_neon}]")
                if not hex_color.startswith('#'):
                    hex_color = '#' + hex_color
                
                if len(hex_color) == 7:
                    self.display_color_info(hex_color)
                    
                    # Additional analysis
                    r, g, b = self.hex_to_rgb(hex_color)
                    h, s, l = self.hex_to_hsl(hex_color)
                    
                    c.print(f"\n[bold {self.col_neon}]📊 Color Analysis:[/bold {self.col_neon}]")
                    
                    # Brightness analysis
                    brightness = (r * 299 + g * 587 + b * 114) / 1000
                    if brightness > 128:
                        brightness_desc = "Light"
                    else:
                        brightness_desc = "Dark"
                    c.print(f"  • Brightness: {brightness:.1f} ({brightness_desc})")
                    
                    # Saturation analysis
                    if s > 50:
                        saturation_desc = "Highly Saturated"
                    elif s > 25:
                        saturation_desc = "Moderately Saturated"
                    else:
                        saturation_desc = "Low Saturation"
                    c.print(f"  • Saturation: {saturation_desc}")
                    
                    # Color temperature
                    if r > b:
                        temp_desc = "Warm"
                    elif b > r:
                        temp_desc = "Cool"
                    else:
                        temp_desc = "Neutral"
                    c.print(f"  • Temperature: {temp_desc}")
                    
                    # Complementary color
                    comp_color = self.generate_color_scheme(hex_color, 'complementary')[1]
                    c.print(f"  • Complementary: {comp_color}")
                    
                else:
                    c.print(f"[{self.col_danger}]✗ Invalid HEX color format[/{self.col_danger}]")
                
            else:
                c.print(f"[{self.col_danger}]✗ Invalid choice[/{self.col_danger}]")
                continue
            
            if Prompt.ask(f"\n[{self.col_neon}]Continue with color picker? (y/n)[/{self.col_neon}]").lower() != 'y':
                break
