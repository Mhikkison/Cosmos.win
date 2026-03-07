"""
Fake Error Generator
Generate realistic fake error messages for pranks
"""

import os
import random
import time
from rich.console import Console
from rich.panel import Panel
from rich.align import Align
from rich import box
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

class FakeErrorGenerator:
    def __init__(self, console: Console):
        self.console = console
        self.col_neon = "#00ffcc"
        self.col_success = "#00e676"
        self.col_warn = "#ffab00"
        self.col_danger = "#ff1744"
        self.col_pink = "#ff6ec7"
        self.col_gold = "#ffd700"
        self.col_dim = "bright_black"
        
        # Error templates
        self.error_templates = {
            'windows': {
                'critical': [
                    "CRITICAL_SYSTEM_ERROR",
                    "SYSTEM_SERVICE_EXCEPTION",
                    "KERNEL_SECURITY_CHECK_FAILURE",
                    "PAGE_FAULT_IN_NONPAGED_AREA",
                    "IRQL_NOT_LESS_OR_EQUAL"
                ],
                'warning': [
                    "Windows Resource Protection found corrupt files",
                    "A device driver is causing system instability",
                    "System Restore cannot create a restore point",
                    "Windows Update failed to install",
                    "Disk space is running low"
                ],
                'info': [
                    "Your Windows license will expire soon",
                    "Microsoft wants to track your browsing habits",
                    "Your computer is not genuine",
                    "Windows needs to restart to apply updates",
                    "System performance is below average"
                ]
            },
            'blue_screen': {
                'messages': [
                    "A problem has been detected and Windows has been shut down",
                    "Your PC ran into a problem and needs to restart",
                    "System has encountered a critical error",
                    "Windows protection error",
                    "Fatal system error"
                ],
                'codes': [
                    "0x0000007B",
                    "0x000000F4",
                    "0x00000050",
                    "0x000000D1",
                    "0x0000000A"
                ],
                'suggestions': [
                    "Check for viruses on your computer",
                    "Remove any newly installed hard drives",
                    "Check your hard drive to make sure it is properly configured",
                    "Try changing video adapters",
                    "Disable BIOS memory options such as caching or shadowing"
                ]
            },
            'programs': {
                'apps': [
                    "Microsoft Office",
                    "Adobe Photoshop",
                    "Google Chrome",
                    "Steam",
                    "Discord",
                    "Visual Studio Code",
                    "Spotify",
                    "Firefox"
                ],
                'errors': [
                    "has stopped working",
                    "encountered a problem and needs to close",
                    "is not responding",
                    "has crashed",
                    "failed to initialize",
                    "cannot access memory",
                    "has detected a compatibility issue",
                    "needs to be updated"
                ]
            },
            'funny': {
                'tech': [
                    "Error 404: Common sense not found",
                    "Error 500: Brain buffer overflow",
                    "Error 1337: Too leet for this system",
                    "Error 69: Nice.",
                    "Error 808: System needs more cowbell",
                    "Error 3.14: Pi is not exactly 3.14159",
                    "Error 42: Answer to everything found",
                    "Error 101: Binary joke detected"
                ],
                'user': [
                    "User error detected between keyboard and chair",
                    "Insufficient coffee detected",
                    "User has exceeded daily meme quota",
                    "User is too awesome for this system",
                    "User's brain needs defragmentation",
                    "User has achieved maximum productivity",
                    "User's sarcasm module is overloaded",
                    "User's patience buffer is empty"
                ]
            }
        }
        
        # Error codes
        self.error_codes = {
            'success': 0,
            'file_not_found': 2,
            'access_denied': 5,
            'invalid_handle': 6,
            'not_enough_memory': 8,
            'bad_format': 11,
            'invalid_data': 13,
            'drive_not_ready': 21,
            'write_protect': 19,
            'seek_error': 25,
            'not_ready': 21,
            'crc_error': 23,
            'bad_command': 22,
            'general_failure': 31
        }
    
    def generate_windows_error(self, error_type: str = 'critical') -> str:
        """Generate Windows-style error message"""
        if error_type not in self.error_templates['windows']:
            error_type = 'critical'
        
        title = random.choice(self.error_templates['windows'][error_type])
        messages = {
            'critical': [
                "A critical system error has occurred",
                "Windows has encountered a serious problem",
                "A system component has failed",
                "The system has become unstable"
            ],
            'warning': [
                "Windows has detected a potential problem",
                "A system warning has been triggered",
                "Windows needs your attention",
                "A maintenance issue requires action"
            ],
            'info': [
                "Windows has an important message",
                "System information requires your attention",
                "A notification from Windows",
                "System status update"
            ]
        }
        
        message = random.choice(messages.get(error_type, messages['critical']))
        error_code = random.choice(list(self.error_codes.values()))
        
        return f"{title}\n\n{message}\n\nError Code: 0x{error_code:08X}"
    
    def generate_blue_screen(self) -> str:
        """Generate blue screen of death"""
        message = random.choice(self.error_templates['blue_screen']['messages'])
        code = random.choice(self.error_templates['blue_screen']['codes'])
        suggestion = random.choice(self.error_templates['blue_screen']['suggestions'])
        
        return f"""{message}

STOP CODE: {code}

{suggestion}

Technical information:
*** STOP: {code} (0x{random.randint(1000000, 9999999):X}, 0x{random.randint(1000000, 9999999):X}, 0x{random.randint(1000000, 9999999):X}, 0x{random.randint(1000000, 9999999):X})

*** Memory Management - Address {random.randint(10000000, 99999999):X} at base {random.randint(10000000, 99999999):X}, DateStamp {random.randint(10000000, 99999999):X}"""
    
    def generate_program_error(self) -> str:
        """Generate application error message"""
        app = random.choice(self.error_templates['programs']['apps'])
        error = random.choice(self.error_templates['programs']['errors'])
        
        return f"{app} {error}\n\nWindows is searching for a solution to this problem..."
    
    def generate_funny_error(self) -> str:
        """Generate funny error message"""
        tech_error = random.choice(self.error_templates['funny']['tech'])
        user_error = random.choice(self.error_templates['funny']['user'])
        
        choice = random.choice(['tech', 'user'])
        
        if choice == 'tech':
            return f"TECHNICAL ERROR: {tech_error}"
        else:
            return f"USER ERROR: {user_error}"
    
    def generate_custom_error(self) -> str:
        """Generate completely custom error"""
        components = [
            random.choice(["FATAL", "CRITICAL", "WARNING", "INFO", "DEBUG"]),
            random.choice(["SYSTEM", "APPLICATION", "USER", "HARDWARE", "NETWORK"]),
            random.choice(["ERROR", "FAILURE", "EXCEPTION", "FAULT", "CRASH"])
        ]
        
        title = "_".join(components)
        
        messages = [
            "An unexpected condition has occurred",
            "The system has encountered an anomaly",
            "A non-standard situation was detected",
            "An irregular behavior has been observed",
            "The system state is inconsistent"
        ]
        
        message = random.choice(messages)
        code = random.randint(1000, 9999)
        
        return f"{title}\n\n{message}\n\nError Code: ERR{code}"
    
    def display_error(self, title: str, message: str, style: str = 'windows'):
        """Display error message with appropriate styling"""
        if style == 'blue_screen':
            # Blue screen style
            self.console.clear()
            self.console.print(f"[bold white on blue]{message}[/bold white on blue]")
            
        elif style == 'windows':
            # Windows dialog style
            color = self.col_danger if 'CRITICAL' in title or 'FATAL' in title else self.col_warn
            self.console.print(Align.center(Panel(
                f"[bold {color}]{title}[/bold {color}]\n\n"
                f"[{self.col_dim}]{message}[/{self.col_dim}]\n\n"
                f"[{self.col_neon}]┌─────────────────────────┐[/]\n"
                f"[{self.col_neon}]│         OK              │[/]\n"
                f"[{self.col_neon}]└─────────────────────────┘[/]",
                border_style=color,
                box=box.DOUBLE,
                padding=(2, 4)
            )))
            
        elif style == 'program':
            # Application error style
            self.console.print(Align.center(Panel(
                f"[bold {self.col_danger}]⚠ {title} ⚠[/bold {self.col_danger}]\n\n"
                f"[{self.col_dim}]{message}[/{self.col_dim}]",
                border_style=self.col_danger,
                box=box.HEAVY,
                padding=(1, 3)
            )))
            
        else:
            # Simple style
            self.console.print(Align.center(Panel(
                f"[bold {self.col_pink}]{title}[/bold {self.col_pink}]\n\n"
                f"[{self.col_dim}]{message}[/{self.col_dim}]",
                border_style=self.col_pink,
                box=box.ROUNDED,
                padding=(1, 3)
            )))
    
    def run(self):
        """Run fake error generator"""
        c = self.console
        
        # Display header
        c.print()
        c.print(Align.center(Panel(
            f"[bold {self.col_neon}]🎮 FAKE ERROR GENERATOR 🎮[/bold {self.col_neon}]\n\n"
            f"[{self.col_dim}]Generate realistic fake error messages for pranks\\n"
            f"Windows, Blue Screen, Application, and Funny errors\\n"
            f"[{self.col_warn}]⚠ All errors are completely fake and harmless![/{self.col_warn}]",
            border_style=self.col_neon,
            box=box.ROUNDED,
            padding=(1, 4)
        )))
        
        while True:
            c.print(f"\n[{self.col_neon}]💥 Error types:[/{self.col_neon}]")
            c.print(f"  1. Windows Critical Error")
            c.print(f"  2. Windows Warning")
            c.print(f"  3. Blue Screen of Death")
            c.print(f"  4. Application Crash")
            c.print(f"  5. Funny Tech Error")
            c.print(f"  6. Funny User Error")
            c.print(f"  7. Custom Random Error")
            c.print(f"  8. Error Mix (Multiple)")
            
            choice = Prompt.ask(f"\n[{self.col_neon}]Select error type (1-8)[/{self.col_neon}]")
            
            if choice == '1':
                error_msg = self.generate_windows_error('critical')
                self.display_error("CRITICAL SYSTEM ERROR", error_msg, 'windows')
                
            elif choice == '2':
                error_msg = self.generate_windows_error('warning')
                self.display_error("SYSTEM WARNING", error_msg, 'windows')
                
            elif choice == '3':
                error_msg = self.generate_blue_screen()
                self.display_error("BLUE SCREEN", error_msg, 'blue_screen')
                c.input(f"\n[{self.col_dim}]Press Enter to continue...[/{self.col_dim}]")
                
            elif choice == '4':
                error_msg = self.generate_program_error()
                self.display_error("APPLICATION ERROR", error_msg, 'program')
                
            elif choice == '5':
                error_msg = self.generate_funny_error()
                self.display_error("FUNNY ERROR", error_msg, 'funny')
                
            elif choice == '6':
                error_msg = self.generate_funny_error()
                self.display_error("USER ERROR", error_msg, 'funny')
                
            elif choice == '7':
                error_msg = self.generate_custom_error()
                self.display_error("SYSTEM ERROR", error_msg, 'custom')
                
            elif choice == '8':
                c.print(f"\n[{self.col_green}]Showing error mix...[/{self.col_green}]")
                c.input(f"[{self.col_dim}]Press Enter to start...[/{self.col_dim}]")
                
                # Show multiple errors
                errors = [
                    ("CRITICAL ERROR", self.generate_windows_error('critical'), 'windows'),
                    ("APPLICATION CRASH", self.generate_program_error(), 'program'),
                    ("FUNNY ERROR", self.generate_funny_error(), 'funny')
                ]
                
                for title, msg, style in errors:
                    self.display_error(title, msg, style)
                    time.sleep(2)
                    c.input(f"[{self.col_dim}]Press Enter for next error...[/{self.col_dim}]")
                
            else:
                c.print(f"[{self.col_danger}]✗ Invalid choice[/{self.col_danger}]")
                continue
            
            # Save option
            save = Prompt.ask(f"[{self.col_neon}]Save error to file? (y/n)[/{self.col_neon}]")
            if save.lower() == 'y':
                filename = Prompt.ask(f"[{self.col_neon}]Enter filename[/{self.col_neon}]") + '.txt'
                
                try:
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(f"FAKE ERROR MESSAGE\n")
                        f.write(f"{'='*50}\n\n")
                        f.write(f"{error_msg if 'error_msg' in locals() else 'Error message'}\n")
                        f.write(f"\n{'='*50}\n")
                        f.write("NOTE: This is a fake error message for entertainment purposes only")
                    
                    c.print(f"[{self.col_success}]✓ Saved to {filename}[/{self.col_success}]")
                except Exception as e:
                    c.print(f"[{self.col_danger}]✗ Error saving: {e}[/{self.col_danger}]")
            
            if Prompt.ask(f"\n[{self.col_neon}]Generate another error? (y/n)[/{self.col_neon}]").lower() != 'y':
                break
