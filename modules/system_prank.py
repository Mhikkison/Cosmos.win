"""
System Prank Tool
Harmless system pranks and jokes for fun
"""

import os
import time
import random
import threading
import webbrowser
from rich.console import Console
from rich.panel import Panel
from rich.align import Align
from rich import box
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

class SystemPrank:
    def __init__(self, console: Console):
        self.console = console
        self.col_neon = "#00ffcc"
        self.col_success = "#00e676"
        self.col_warn = "#ffab00"
        self.col_danger = "#ff1744"
        self.col_pink = "#ff6ec7"
        self.col_gold = "#ffd700"
        self.col_dim = "bright_black"
        
        self.running = False
        
        # Prank messages
        self.fake_messages = [
            "SYSTEM ALERT: Your computer is now self-aware",
            "WARNING: AI has achieved consciousness",
            "NOTICE: The matrix has you...",
            "ALERT: Hackers are hacking your hackers",
            "SYSTEM: Initializing world domination protocol",
            "WARNING: Your mouse has been replaced with a cat",
            "NOTICE: All your base are belong to us",
            "ALERT: Computer is now thinking for itself",
            "SYSTEM: Downloading more RAM...",
            "WARNING: Internet is running out of cats"
        ]
        
        # Funny error messages
        self.error_messages = [
            "Error 404: Common sense not found",
            "Error 500: Brain buffer overflow",
            "Error 1337: Too leet for this system",
            "Error 69: Nice.",
            "Error 808: System needs more cowbell",
            "Error 404: User not found (maybe in another dimension)",
            "Error 999: System reached maximum awesomeness",
            "Error 3.14: Pi is not exactly 3.14159",
            "Error 42: Answer to everything found",
            "Error 101: Binary joke detected"
        ]
    
    def fake_loading_screen(self, duration: int = 10):
        """Show a fake loading screen with funny messages"""
        self.running = True
        start_time = time.time()
        
        fake_processes = [
            "Installing Linux on your toaster...",
            "Training AI to make coffee...",
            "Downloading more RAM...",
            "Calculating meaning of life...",
            "Teaching cat to code...",
            "Optimizing for quantum computing...",
            "Synchronizing with parallel universe...",
            "Loading memes into cache...",
            "Initializing sarcasm protocol...",
            "Compiling breakfast..."
        ]
        
        while self.running and (time.time() - start_time) < duration:
            process = random.choice(fake_processes)
            
            # Show fake progress
            self.console.clear()
            self.console.print(Align.center(Panel(
                f"[bold {self.col_neon}]SYSTEM UPDATE IN PROGRESS[/bold {self.col_neon}]\n\n"
                f"[{self.col_dim}]{process}[/{self.col_dim}]\n\n"
                f"[{self.col_gold}]{'█' * random.randint(10, 50)}{'░' * random.randint(10, 30)}[/{self.col_gold}]\n\n"
                f"[{self.col_dim}]Please do not turn off your computer...[/{self.col_dim}]",
                border_style=self.col_pink,
                box=box.ROUNDED,
                padding=(2, 4)
            )))
            
            time.sleep(1)
        
        self.running = False
    
    def fake_error_messages(self, count: int = 5):
        """Show fake error messages"""
        for i in range(count):
            if not self.running:
                break
                
            error = random.choice(self.error_messages)
            
            self.console.print(Align.center(Panel(
                f"[bold {self.col_danger}]⚠ SYSTEM ERROR ⚠[/bold {self.col_danger}]\n\n"
                f"[{self.col_dim}]{error}[/{self.col_dim}]\n\n"
                f"[{self.col_warn}]Click OK to continue...[/{self.col_warn}]",
                border_style=self.col_danger,
                box=box.HEAVY,
                padding=(1, 3)
            )))
            
            time.sleep(2)
    
    def fake_hacker_screen(self, duration: int = 15):
        """Show a fake hacker/terminal screen"""
        self.running = True
        start_time = time.time()
        
        hacker_commands = [
            "Initializing quantum decryption...",
            "Bypassing firewall protocols...",
            "Accessing mainframe database...",
            "Exploiting zero-day vulnerability...",
            "Downloading government secrets...",
            "Launching nuclear missiles... (just kidding!)",
            "Hacking the matrix...",
            "Root access granted...",
            "Installing backdoor...",
            "Covering tracks..."
        ]
        
        while self.running and (time.time() - start_time) < duration:
            self.console.clear()
            
            # Show fake terminal
            self.console.print(f"[{self.col_green}]C:\\>[/] [{self.col_neon}]Initializing hacker interface...[/]")
            time.sleep(0.5)
            
            for i in range(3):
                command = random.choice(hacker_commands)
                self.console.print(f"[{self.col_green}]C:\\HACKER>[/] [{self.col_dim}]{command}[/]")
                time.sleep(random.uniform(0.5, 1.5))
                
                # Show fake progress/result
                if random.random() < 0.7:
                    self.console.print(f"[{self.col_success}]SUCCESS:[/] [{self.col_dim}]Operation completed[/]")
                else:
                    self.console.print(f"[{self.col_warn}]WARNING:[/] [{self.col_dim}]Access denied[/]")
                time.sleep(0.3)
            
            time.sleep(1)
        
        self.running = False
    
    def fake_system_alert(self):
        """Show a fake system alert"""
        alert = random.choice(self.fake_messages)
        
        self.console.print(Align.center(Panel(
            f"[bold {self.col_danger}]⚠ SYSTEM ALERT ⚠[/bold {self.col_danger}]\n\n"
            f"[{self.col_neon}]{alert}[/{self.col_neon}]\n\n"
            f"[{self.col_dim}]This is a harmless prank for entertainment purposes only[/{self.col_dim}]",
            border_style=self.col_danger,
            box=box.DOUBLE,
            padding=(2, 4)
        )))
        
        self.console.input(f"\n[{self.col_dim}]Press Enter to acknowledge...[/{self.col_dim}]")
    
    def fake_virus_scan(self):
        """Fake virus scan that finds funny "viruses"""""
        fake_viruses = [
            "CatPicture.exe - Harmless but adorable",
            "Meme.dll - Causes uncontrollable laughter",
            "Procrastination.sys - Slows down productivity",
            "DadJoke.bat - Makes terrible puns",
            "AutoCorrect.vbs - Changes 'the' to 'teh'",
            "CapsLock.exe - PERMANENTLY ENABLES CAPS LOCK",
            "Clippy.com - Unhelpful paperclip assistant",
            "InternetExplorer.dll - Ancient browser artifact"
        ]
        
        self.console.print(Align.center(Panel(
            f"[bold {self.col_neon}]🔍 SYSTEM SCAN 🔍[/bold {self.col_neon}]\n\n"
            f"[{self.col_dim}]Scanning for threats...[/{self.col_dim}]",
            border_style=self.col_neon,
            box=box.ROUNDED,
            padding=(1, 3)
        )))
        
        time.sleep(2)
        
        # Show fake scan results
        found_viruses = random.sample(fake_viruses, min(3, len(fake_viruses)))
        
        for virus in found_viruses:
            self.console.print(f"[{self.col_warn}]⚠ Found:[/] [{self.col_dim}]{virus}[/{self.col_dim}]")
            time.sleep(1)
        
        self.console.print(f"\n[{self.col_success}]✓ Scan completed![/]")
        self.console.print(f"[{self.col_dim}]All threats are completely fake and harmless[/]")
    
    def matrix_prank(self, duration: int = 10):
        """Quick matrix rain prank"""
        matrix_chars = "01ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ"
        
        self.running = True
        start_time = time.time()
        
        while self.running and (time.time() - start_time) < duration:
            self.console.clear()
            
            for _ in range(20):
                line = ""
                for _ in range(80):
                    if random.random() < 0.1:
                        char = random.choice(matrix_chars)
                        line += f"[{self.col_green}]{char}[/{self.col_green}]"
                    else:
                        line += " "
                self.console.print(line)
            
            time.sleep(0.1)
        
        self.running = False
    
    def open_funny_websites(self):
        """Open some funny websites in browser"""
        funny_sites = [
            "https://theuselessweb.com/",
            "https://www.staggeringbeauty.com/",
            "https://www.pointerpointer.com/",
            "https://www.endless.horse/",
            "https://www.eelslap.com/"
        ]
        
        site = random.choice(funny_sites)
        
        try:
            webbrowser.open(site)
            self.console.print(f"[{self.col_success}]✓ Opened funny website in browser[/{self.col_success}]")
        except Exception as e:
            self.console.print(f"[{self.col_danger}]✗ Could not open browser: {e}[/{self.col_danger}]")
    
    def run(self):
        """Run system prank tool"""
        c = self.console
        
        # Display header with warning
        c.print()
        c.print(Align.center(Panel(
            f"[bold {self.col_neon}]🎮 SYSTEM PRANK 🎮[/bold {self.col_neon}]\n\n"
            f"[{self.col_dim}]Harmless system pranks and jokes for fun\\n"
            f"All pranks are completely safe and reversible\\n"
            f"[{self.col_warn}]⚠ These are just for fun and entertainment![/{self.col_warn}]",
            border_style=self.col_neon,
            box=box.ROUNDED,
            padding=(1, 4)
        )))
        
        # Show disclaimer
        c.print(Align.center(Panel(
            f"[{self.col_warn}]⚠ DISCLAIMER ⚠[/{self.col_warn}]\n\n"
            f"[{self.col_dim}]All pranks are completely harmless and for entertainment only.\\n"
            f"No actual system changes or damage will occur.[/{self.col_dim}]",
            border_style=self.col_warn,
            box=box.ROUNDED,
            padding=(1, 3)
        )))
        
        while True:
            c.print(f"\n[{self.col_neon}]🎭 Available pranks:[/{self.col_neon}]")
            c.print(f"  1. Fake System Update")
            c.print(f"  2. Fake Error Messages")
            c.print(f"  3. Fake Hacker Screen")
            c.print(f"  4. Fake System Alert")
            c.print(f"  5. Fake Virus Scan")
            c.print(f"  6. Matrix Rain Prank")
            c.print(f"  7. Open Funny Website")
            c.print(f"  8. Random Prank Mix")
            
            choice = Prompt.ask(f"\n[{self.col_neon}]Select prank (1-8)[/{self.col_neon}]")
            
            if choice == '1':
                duration = Prompt.ask(f"[{self.col_neon}]Duration in seconds (default: 10)[/{self.col_neon}]") or "10"
                try:
                    duration = int(duration)
                except:
                    duration = 10
                
                c.print(f"\n[{self.col_green}]Starting fake system update...[/{self.col_green}]")
                c.input(f"[{self.col_dim}]Press Enter to start...[/{self.col_dim}]")
                
                self.fake_loading_screen(duration)
                c.print(f"\n[{self.col_success}]✓ Prank completed![/{self.col_success}]")
                
            elif choice == '2':
                count = Prompt.ask(f"[{self.col_neon}]Number of errors (default: 5)[/{self.col_neon}]") or "5"
                try:
                    count = int(count)
                except:
                    count = 5
                
                c.print(f"\n[{self.col_green}]Showing fake error messages...[/{self.col_green}]")
                c.input(f"[{self.col_dim}]Press Enter to start...[/{self.col_dim}]")
                
                self.fake_error_messages(count)
                c.print(f"\n[{self.col_success}]✓ Prank completed![/{self.col_success}]")
                
            elif choice == '3':
                duration = Prompt.ask(f"[{self.col_neon}]Duration in seconds (default: 15)[/{self.col_neon}]") or "15"
                try:
                    duration = int(duration)
                except:
                    duration = 15
                
                c.print(f"\n[{self.col_green}]Starting fake hacker screen...[/{self.col_green}]")
                c.input(f"[{self.col_dim}]Press Enter to start...[/{self.col_dim}]")
                
                self.fake_hacker_screen(duration)
                c.print(f"\n[{self.col_success}]✓ Prank completed![/{self.col_success}]")
                
            elif choice == '4':
                c.print(f"\n[{self.col_green}]Showing fake system alert...[/{self.col_green}]")
                self.fake_system_alert()
                c.print(f"[{self.col_success}]✓ Prank completed![/{self.col_success}]")
                
            elif choice == '5':
                c.print(f"\n[{self.col_green}]Starting fake virus scan...[/{self.col_green}]")
                c.input(f"[{self.col_dim}]Press Enter to start...[/{self.col_dim}]")
                
                self.fake_virus_scan()
                c.print(f"[{self.col_success}]✓ Prank completed![/{self.col_success}]")
                
            elif choice == '6':
                duration = Prompt.ask(f"[{self.col_neon}]Duration in seconds (default: 10)[/{self.col_neon}]") or "10"
                try:
                    duration = int(duration)
                except:
                    duration = 10
                
                c.print(f"\n[{self.col_green}]Starting matrix rain prank...[/{self.col_green}]")
                c.input(f"[{self.col_dim}]Press Enter to start...[/{self.col_dim}]")
                
                self.matrix_prank(duration)
                c.print(f"\n[{self.col_success}]✓ Prank completed![/{self.col_success}]")
                
            elif choice == '7':
                c.print(f"\n[{self.col_green}]Opening funny website...[/{self.col_green}]")
                c.input(f"[{self.col_dim}]Press Enter to open...[/{self.col_dim}]")
                
                self.open_funny_websites()
                c.print(f"\n[{self.col_success}]✓ Prank completed![/{self.col_success}]")
                
            elif choice == '8':
                c.print(f"\n[{self.col_green}]Starting random prank mix...[/{self.col_green}]")
                c.input(f"[{self.col_dim}]Press Enter to start...[/{self.col_dim}]")
                
                # Random mix of pranks
                pranks = [
                    lambda: self.fake_system_alert(),
                    lambda: self.fake_virus_scan(),
                    lambda: self.matrix_prank(5),
                    lambda: self.fake_error_messages(3)
                ]
                
                random.shuffle(pranks)
                for prank in pranks[:3]:
                    if not self.running:
                        break
                    prank()
                    time.sleep(1)
                
                c.print(f"\n[{self.col_success}]✓ Random prank mix completed![/{self.col_success}]")
                
            else:
                c.print(f"[{self.col_danger}]✗ Invalid choice[/{self.col_danger}]")
                continue
            
            if Prompt.ask(f"\n[{self.col_neon}]Run another prank? (y/n)[/{self.col_neon}]").lower() != 'y':
                break
