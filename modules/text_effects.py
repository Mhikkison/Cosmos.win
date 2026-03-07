"""
Text Effects Tool
Apply cool effects to text (rainbow, glow, etc)
"""

import os
import random
from rich.console import Console
from rich.panel import Panel
from rich.align import Align
from rich import box
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.text import Text

class TextEffects:
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
        
        # Effect colors
        self.rainbow_colors = ["#ff0000", "#ff7f00", "#ffff00", "#00ff00", "#0000ff", "#4b0082", "#9400d3"]
        self.neon_colors = ["#00ffcc", "#ff00ff", "#00ff00", "#ff0080", "#80ff00", "#00ffff"]
        self.fire_colors = ["#ff0000", "#ff4500", "#ff8c00", "#ffd700", "#ffff00"]
        self.ocean_colors = ["#000080", "#0000cd", "#0000ff", "#4169e1", "#87ceeb", "#00ffff"]
        self.sunset_colors = ["#ff0000", "#ff4500", "#ff6347", "#ff7f50", "#ffa500", "#ffd700"]
        
    def rainbow_effect(self, text: str) -> str:
        """Apply rainbow effect to text"""
        result = ""
        for i, char in enumerate(text):
            color = self.rainbow_colors[i % len(self.rainbow_colors)]
            result += f"[{color}]{char}[/{color}]"
        return result
    
    def neon_effect(self, text: str) -> str:
        """Apply neon glow effect to text"""
        result = ""
        for i, char in enumerate(text):
            color = self.neon_colors[i % len(self.neon_colors)]
            result += f"[bold {color}]{char}[/{color}]"
        return result
    
    def fire_effect(self, text: str) -> str:
        """Apply fire effect to text"""
        result = ""
        for i, char in enumerate(text):
            color = self.fire_colors[i % len(self.fire_colors)]
            result += f"[{color}]{char}[/{color}]"
        return result
    
    def ocean_effect(self, text: str) -> str:
        """Apply ocean effect to text"""
        result = ""
        for i, char in enumerate(text):
            color = self.ocean_colors[i % len(self.ocean_colors)]
            result += f"[italic {color}]{char}[/{color}]"
        return result
    
    def sunset_effect(self, text: str) -> str:
        """Apply sunset effect to text"""
        result = ""
        for i, char in enumerate(text):
            color = self.sunset_colors[i % len(self.sunset_colors)]
            result += f"[{color}]{char}[/{color}]"
        return result
    
    def matrix_effect(self, text: str) -> str:
        """Apply matrix effect to text"""
        result = ""
        for char in text:
            if char != ' ':
                result += f"[#00ff00]{char}[/#00ff00]"
            else:
                result += " "
        return result
    
    def glitch_effect(self, text: str) -> str:
        """Apply glitch effect to text"""
        result = ""
        for char in text:
            if char != ' ' and random.random() < 0.3:
                # Random glitch character
                glitch_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
                result += f"[#ff0000]{random.choice(glitch_chars)}[/#ff0000]"
            elif char != ' ' and random.random() < 0.6:
                result += f"[#ffffff]{char}[/#ffffff]"
            else:
                result += f"[#808080]{char}[/#808080]"
        return result
    
    def pulse_effect(self, text: str) -> str:
        """Apply pulsing effect to text"""
        result = ""
        for i, char in enumerate(text):
            if char != ' ':
                intensity = abs((i % 10) - 5) / 5.0
                if intensity > 0.7:
                    result += f"[bold #ff00ff]{char}[/#ff00ff]"
                elif intensity > 0.3:
                    result += f"[#ff00ff]{char}[/#ff00ff]"
                else:
                    result += f"[dim #ff00ff]{char}[/#ff00ff]"
            else:
                result += " "
        return result
    
    def wave_effect(self, text: str) -> str:
        """Apply wave effect to text"""
        result = ""
        wave_chars = "∼∽∾∿"
        for i, char in enumerate(text):
            if char != ' ':
                wave_char = wave_chars[i % len(wave_chars)]
                result += f"[#00ffff]{wave_char}{char}{wave_char}[/#00ffff]"
            else:
                result += "   "
        return result
    
    def cyber_effect(self, text: str) -> str:
        """Apply cyberpunk effect to text"""
        result = ""
        cyber_chars = "░▒▓█"
        for i, char in enumerate(text):
            if char != ' ':
                cyber_char = cyber_chars[i % len(cyber_chars)]
                result += f"[#00ff00]{cyber_char}[#00ffff]{char}[#00ff00]{cyber_char}[/#00ff00]"
            else:
                result += "   "
        return result
    
    def gradient_effect(self, text: str, start_color: str, end_color: str) -> str:
        """Apply gradient effect to text"""
        result = ""
        for i, char in enumerate(text):
            if char != ' ' and len(text) > 1:
                # Simple gradient simulation
                if i < len(text) // 2:
                    result += f"[{start_color}]{char}[/{start_color}]"
                else:
                    result += f"[{end_color}]{char}[/{end_color}]"
            else:
                result += char
        return result
    
    def bold_italic_effect(self, text: str) -> str:
        """Apply bold and italic effect"""
        return f"[bold italic {self.col_gold}]{text}[/bold italic {self.col_gold}]"
    
    def underline_effect(self, text: str) -> str:
        """Apply underline effect"""
        return f"[underline {self.col_cyan}]{text}[/underline {self.col_cyan}]"
    
    def strikethrough_effect(self, text: str) -> str:
        """Apply strikethrough effect"""
        return f"[strike {self.col_danger}]{text}[/strike {self.col_danger}]"
    
    def create_ascii_banner(self, text: str, effect_func) -> str:
        """Create ASCII banner with effect"""
        lines = []
        
        # Top border
        lines.append(f"[{self.col_gold}]{'═' * (len(text) + 4)}[/{self.col_gold}]")
        
        # Text line with effect
        effected_text = effect_func(text)
        lines.append(f"[{self.col_gold}]║ [/{self.col_gold}]{effected_text}[{self.col_gold}] ║[/{self.col_gold}]")
        
        # Bottom border
        lines.append(f"[{self.col_gold}]{'═' * (len(text) + 4)}[/{self.col_gold}]")
        
        return '\n'.join(lines)
    
    def create_box_effect(self, text: str, effect_func) -> str:
        """Create box effect around text"""
        lines = []
        
        # Top border
        lines.append(f"[{self.col_neon}]┌{'─' * (len(text) + 2)}┐[/{self.col_neon}]")
        
        # Text line
        effected_text = effect_func(text)
        lines.append(f"[{self.col_neon}]│ {effected_text} │[/{self.col_neon}]")
        
        # Bottom border
        lines.append(f"[{self.col_neon}]└{'─' * (len(text) + 2)}┘[/{self.col_neon}]")
        
        return '\n'.join(lines)
    
    def animate_text(self, text: str, effect_func, duration: int = 3):
        """Animate text effect"""
        import time
        
        start_time = time.time()
        while time.time() - start_time < duration:
            # Clear screen
            self.console.clear()
            
            # Display animated text
            effected_text = effect_func(text)
            self.console.print(Align.center(effected_text))
            
            time.sleep(0.1)
    
    def run(self):
        """Run text effects tool"""
        c = self.console
        
        # Display header
        c.print()
        c.print(Align.center(Panel(
            f"[bold {self.col_neon}]🎮 TEXT EFFECTS 🎮[/bold {self.col_neon}]\n\n"
            f"[{self.col_dim}]Apply cool effects to text (rainbow, glow, etc)\\n"
            f"Multiple effects with animations and styles\\n"
            f"Perfect for making text stand out[/{self.col_dim}]",
            border_style=self.col_neon,
            box=box.ROUNDED,
            padding=(1, 4)
        )))
        
        while True:
            c.print(f"\n[{self.col_neon}]✨ Available effects:[/{self.col_neon}]")
            c.print(f"  1. Rainbow Effect")
            c.print(f"  2. Neon Glow")
            c.print(f"  3. Fire Effect")
            c.print(f"  4. Ocean Effect")
            c.print(f"  5. Sunset Effect")
            c.print(f"  6. Matrix Effect")
            c.print(f"  7. Glitch Effect")
            c.print(f"  8. Pulse Effect")
            c.print(f"  9. Wave Effect")
            c.print(f"  10. Cyber Effect")
            c.print(f"  11. Gradient Effect")
            c.print(f"  12. Bold & Italic")
            c.print(f"  13. Underline")
            c.print(f"  14. Strikethrough")
            c.print(f"  15. ASCII Banner")
            c.print(f"  16. Box Effect")
            c.print(f"  17. Animate Text")
            c.print(f"  18. Random Mix")
            
            choice = Prompt.ask(f"\n[{self.col_neon}]Select effect (1-18)[/{self.col_neon}]")
            
            text = Prompt.ask(f"[{self.col_neon}]Enter text to apply effect[/{self.col_neon}]")
            
            if choice == '1':
                effected_text = self.rainbow_effect(text)
                c.print(f"\n{effected_text}")
                
            elif choice == '2':
                effected_text = self.neon_effect(text)
                c.print(f"\n{effected_text}")
                
            elif choice == '3':
                effected_text = self.fire_effect(text)
                c.print(f"\n{effected_text}")
                
            elif choice == '4':
                effected_text = self.ocean_effect(text)
                c.print(f"\n{effected_text}")
                
            elif choice == '5':
                effected_text = self.sunset_effect(text)
                c.print(f"\n{effected_text}")
                
            elif choice == '6':
                effected_text = self.matrix_effect(text)
                c.print(f"\n{effected_text}")
                
            elif choice == '7':
                effected_text = self.glitch_effect(text)
                c.print(f"\n{effected_text}")
                
            elif choice == '8':
                effected_text = self.pulse_effect(text)
                c.print(f"\n{effected_text}")
                
            elif choice == '9':
                effected_text = self.wave_effect(text)
                c.print(f"\n{effected_text}")
                
            elif choice == '10':
                effected_text = self.cyber_effect(text)
                c.print(f"\n{effected_text}")
                
            elif choice == '11':
                start_color = Prompt.ask(f"[{self.col_neon}]Start color (e.g., #ff0000)[/{self.col_neon}]")
                end_color = Prompt.ask(f"[{self.col_neon}]End color (e.g., #0000ff)[/{self.col_neon}]")
                effected_text = self.gradient_effect(text, start_color, end_color)
                c.print(f"\n{effected_text}")
                
            elif choice == '12':
                effected_text = self.bold_italic_effect(text)
                c.print(f"\n{effected_text}")
                
            elif choice == '13':
                effected_text = self.underline_effect(text)
                c.print(f"\n{effected_text}")
                
            elif choice == '14':
                effected_text = self.strikethrough_effect(text)
                c.print(f"\n{effected_text}")
                
            elif choice == '15':
                # Choose effect for banner
                c.print(f"[{self.col_neon}]Choose effect for banner:[/{self.col_neon}]")
                c.print(f"  1. Rainbow")
                c.print(f"  2. Neon")
                c.print(f"  3. Fire")
                c.print(f"  4. Matrix")
                
                banner_choice = Prompt.ask(f"[{self.col_neon}]Select (1-4)[/{self.col_neon}]")
                
                effects_map = {
                    '1': self.rainbow_effect,
                    '2': self.neon_effect,
                    '3': self.fire_effect,
                    '4': self.matrix_effect
                }
                
                effect_func = effects_map.get(banner_choice, self.rainbow_effect)
                banner = self.create_ascii_banner(text, effect_func)
                c.print(f"\n{banner}")
                
            elif choice == '16':
                # Choose effect for box
                c.print(f"[{self.col_neon}]Choose effect for box:[/{self.col_neon}]")
                c.print(f"  1. Ocean")
                c.print(f"  2. Sunset")
                c.print(f"  3. Pulse")
                c.print(f"  4. Wave")
                
                box_choice = Prompt.ask(f"[{self.col_neon}]Select (1-4)[/{self.col_neon}]")
                
                effects_map = {
                    '1': self.ocean_effect,
                    '2': self.sunset_effect,
                    '3': self.pulse_effect,
                    '4': self.wave_effect
                }
                
                effect_func = effects_map.get(box_choice, self.ocean_effect)
                box = self.create_box_effect(text, effect_func)
                c.print(f"\n{box}")
                
            elif choice == '17':
                # Animate text
                c.print(f"[{self.col_neon}]Choose animation effect:[/{self.col_neon}]")
                c.print(f"  1. Rainbow")
                c.print(f"  2. Neon")
                c.print(f"  3. Fire")
                c.print(f"  4. Matrix")
                
                anim_choice = Prompt.ask(f"[{self.col_neon}]Select (1-4)[/{self.col_neon}]")
                duration = Prompt.ask(f"[{self.col_neon}]Animation duration in seconds (default: 3)[/{self.col_neon}]") or "3"
                
                try:
                    duration = int(duration)
                except:
                    duration = 3
                
                effects_map = {
                    '1': self.rainbow_effect,
                    '2': self.neon_effect,
                    '3': self.fire_effect,
                    '4': self.matrix_effect
                }
                
                effect_func = effects_map.get(anim_choice, self.rainbow_effect)
                
                c.print(f"\n[{self.col_green}]Starting animation... Press Ctrl+C to stop[/{self.col_green}]")
                c.input(f"[{self.col_dim}]Press Enter to start...[/{self.col_dim}]")
                
                try:
                    self.animate_text(text, effect_func, duration)
                except KeyboardInterrupt:
                    c.print(f"\n[{self.col_warn}]Animation stopped by user[/{self.col_warn}]")
                
            elif choice == '18':
                # Random mix of effects
                effects = [
                    self.rainbow_effect,
                    self.neon_effect,
                    self.fire_effect,
                    self.ocean_effect,
                    self.matrix_effect,
                    self.glitch_effect,
                    self.pulse_effect
                ]
                
                c.print(f"\n[{self.col_neon}]🎲 Random Effect Mix:[/{self.col_neon}]")
                
                for i in range(3):
                    effect_func = random.choice(effects)
                    effected_text = effect_func(text)
                    c.print(f"\nEffect {i+1}: {effected_text}")
                    time.sleep(1)
                
            else:
                c.print(f"[{self.col_danger}]✗ Invalid choice[/{self.col_danger}]")
                continue
            
            # Save option
            save = Prompt.ask(f"\n[{self.col_neon}]Save effect to file? (y/n)[/{self.col_neon}]")
            if save.lower() == 'y':
                filename = Prompt.ask(f"[{self.col_neon}]Enter filename[/{self.col_neon}]") + '.txt'
                
                try:
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(f"TEXT EFFECT: {choice}\n")
                        f.write(f"TEXT: {text}\n")
                        f.write(f"RESULT:\n{effected_text if 'effected_text' in locals() else 'Effect applied'}")
                    
                    c.print(f"[{self.col_success}]✓ Saved to {filename}[/{self.col_success}]")
                except Exception as e:
                    c.print(f"[{self.col_danger}]✗ Error saving: {e}[/{self.col_danger}]")
            
            if Prompt.ask(f"\n[{self.col_neon}]Apply another effect? (y/n)[/{self.col_neon}]").lower() != 'y':
                break
