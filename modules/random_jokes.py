"""
Random Jokes Tool
Display random programming jokes and fun content
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

class RandomJokes:
    def __init__(self, console: Console):
        self.console = console
        self.col_neon = "#00ffcc"
        self.col_success = "#00e676"
        self.col_warn = "#ffab00"
        self.col_danger = "#ff1744"
        self.col_pink = "#ff6ec7"
        self.col_gold = "#ffd700"
        self.col_dim = "bright_black"
        
        # Programming jokes
        self.programming_jokes = [
            {
                "setup": "Why do programmers prefer dark mode?",
                "punchline": "Because light attracts bugs!"
            },
            {
                "setup": "How many programmers does it take to change a light bulb?",
                "punchline": "None. It's a hardware problem!"
            },
            {
                "setup": "Why do Java developers wear glasses?",
                "punchline": "Because they don't C#!"
            },
            {
                "setup": "What's the best thing about a Boolean?",
                "punchline": "Even if you're wrong, you're only off by a bit!"
            },
            {
                "setup": "Why do programmers always mix up Halloween and Christmas?",
                "punchline": "Because Oct 31 equals Dec 25!"
            },
            {
                "setup": "A SQL query walks into a bar, walks up to two tables and asks...",
                "punchline": "'Can I join you?'"
            },
            {
                "setup": "Why was the JavaScript developer sad?",
                "punchline": "Because he didn't know how to 'null' his feelings!"
            },
            {
                "setup": "What do you call a programmer from Finland?",
                "punchline": "Nerdic!"
            },
            {
                "setup": "Why did the programmer quit his job?",
                "punchline": "Because he didn't get arrays!"
            },
            {
                "setup": "What's a programmer's favorite hangout place?",
                "punchline": "The Foo Bar!"
            }
        ]
        
        # Tech jokes
        self.tech_jokes = [
            {
                "setup": "Why was the computer cold?",
                "punchline": "It left its Windows open!"
            },
            {
                "setup": "What do you call a computer that sings?",
                "punchline": "A-Dell!"
            },
            {
                "setup": "Why was the smartphone wearing glasses?",
                "punchline": "It lost its contacts!"
            },
            {
                "setup": "What do you get when you cross a computer and a life insurance salesman?",
                "punchline": "A lot of hard drives!"
            },
            {
                "setup": "Why did the Wi-Fi network go to therapy?",
                "punchline": "It had too many connection issues!"
            }
        ]
        
        # One-liners
        self.one_liners = [
            "There are 10 types of people in the world: those who understand binary and those who don't.",
            "Debugging is like being a detective in a crime movie where you are also the murderer.",
            "The best thing about a boolean is even if you are wrong, you are only off by a bit.",
            "Programming is like writing a book. Except if you miss a single comma on page 126, the whole thing makes no sense.",
            "99 little bugs in the code, 99 bugs in the code, take one down, patch it around, 127 little bugs in the code.",
            "To understand recursion, you must first understand recursion.",
            "A programmer is told to 'go to hell', he finds the worst part of that statement is the 'go to'.",
            "The only thing more dangerous than a programmer with a screwdriver is a programmer with a soldering iron.",
            "Programming is the art of telling another human what one wants the computer to do.",
            "There are only two hard things in Computer Science: cache invalidation and naming things."
        ]
        
        # Developer excuses
        self.developer_excuses = [
            "It works on my machine.",
            "It's a feature, not a bug.",
            "That's a corner case.",
            "It must be a caching issue.",
            "The requirements changed.",
            "I didn't write that code.",
            "It's probably a network problem.",
            "The server is probably down.",
            "It works in production.",
            "I'll fix it in the next sprint.",
            "That's not in the scope.",
            "The user is using it wrong.",
            "It's a browser compatibility issue.",
            "The API must have changed.",
            "I was following the documentation.",
            "It's a race condition.",
            "The database is probably corrupted.",
            "Someone must have modified the config.",
            "It's a firewall issue.",
            "I need more RAM to debug this."
        ]
        
        # Code comments
        self.funny_comments = [
            "# I'm sorry.",
            "# TODO: Figure out what I was thinking here.",
            "# This code was written by someone who clearly hates themselves.",
            "# If this code works, it was written by Dick Cheney. If it doesn't, I don't know who wrote it.",
            "# Magic. Do not touch.",
            "# Dear future me. Please forgive me.",
            "# I'm not sure what I was thinking here, but it seemed like a good idea at the time.",
            "# This is why we need code reviews.",
            "# I was young and needed the money.",
            "# This code works on my machine.",
            "# If you're reading this, something went wrong.",
            "# TODO: Make this code less terrible.",
            "# WARNING: This code may cause spontaneous combustion.",
            "# This code is so bad it makes me want to cry.",
            "# I wrote this while I was drunk. Don't judge me.",
            "# This code is protected by the 'I don't know what I'm doing' license."
        ]
        
        # Programming quotes
        self.programming_quotes = [
            {
                "quote": "Any fool can write code that a computer can understand. Good programmers write code that humans can understand.",
                "author": "Martin Fowler"
            },
            {
                "quote": "First, solve the problem. Then, write the code.",
                "author": "John Johnson"
            },
            {
                "quote": "Experience is the name everyone gives to their mistakes.",
                "author": "Oscar Wilde"
            },
            {
                "quote": "In order to be irreplaceable, one must always be different.",
                "author": "Coco Chanel"
            },
            {
                "quote": "Java is to JavaScript what car is to carpet.",
                "author": "Chris Heilmann"
            },
            {
                "quote": "Knowledge is power.",
                "author": "Francis Bacon"
            },
            {
                "quote": "Sometimes it pays to stay in bed on Monday, rather than spending the rest of the week debugging Monday's code.",
                "author": "Dan Salomon"
            },
            {
                "quote": "Perfection is achieved not when there is nothing more to add, but rather when there is nothing more to take away.",
                "author": "Antoine de Saint-Exupery"
            },
            {
                "quote": "Code is like humor. When you have to explain it, it's bad.",
                "author": "Cory House"
            },
            {
                "quote": "Fix the cause, not the symptom.",
                "author": "Steve Maguire"
            }
        ]
    
    def display_joke(self, joke_type: str = "programming"):
        """Display a joke based on type"""
        if joke_type == "programming":
            joke = random.choice(self.programming_jokes)
            self.console.print(Align.center(Panel(
                f"[bold {self.col_gold}]🎭 Programming Joke 🎭[/bold {self.col_gold}]\n\n"
                f"[{self.col_neon}]{joke['setup']}[/{self.col_neon}]\n\n"
                f"[{self.col_pink}]...{joke['punchline']}...[/{self.col_pink}]",
                border_style=self.col_neon,
                box=box.ROUNDED,
                padding=(2, 4)
            )))
            
        elif joke_type == "tech":
            joke = random.choice(self.tech_jokes)
            self.console.print(Align.center(Panel(
                f"[bold {self.col_cyan}]💻 Tech Joke 💻[/bold {self.col_cyan}]\n\n"
                f"[{self.col_neon}]{joke['setup']}[/{self.col_neon}]\n\n"
                f"[{self.col_pink}]...{joke['punchline']}...[/{self.col_pink}]",
                border_style=self.col_cyan,
                box=box.ROUNDED,
                padding=(2, 4)
            )))
            
        elif joke_type == "one_liner":
            joke = random.choice(self.one_liners)
            self.console.print(Align.center(Panel(
                f"[bold {self.col_pink}]✨ One-Liner ✨[/bold {self.col_pink}]\n\n"
                f"[{self.col_neon}]{joke}[/{self.col_neon}]",
                border_style=self.col_pink,
                box=box.ROUNDED,
                padding=(2, 4)
            )))
            
        elif joke_type == "excuse":
            excuse = random.choice(self.developer_excuses)
            self.console.print(Align.center(Panel(
                f"[bold {self.col_warn}]🤷 Developer Excuse 🤷[/bold {self.col_warn}]\n\n"
                f"[{self.col_neon}]\"{excuse}\"[/{self.col_neon}]",
                border_style=self.col_warn,
                box=box.ROUNDED,
                padding=(2, 4)
            )))
            
        elif joke_type == "comment":
            comment = random.choice(self.funny_comments)
            self.console.print(Align.center(Panel(
                f"[bold {self.col_danger}]💬 Code Comment 💬[/bold {self.col_danger}]\n\n"
                f"[{self.col_dim}]{comment}[/{self.col_dim}]",
                border_style=self.col_danger,
                box=box.ROUNDED,
                padding=(2, 4)
            )))
            
        elif joke_type == "quote":
            quote = random.choice(self.programming_quotes)
            self.console.print(Align.center(Panel(
                f"[bold {self.col_success}]💡 Programming Quote 💡[/bold {self.col_success}]\n\n"
                f"[{self.col_neon}]\"{quote['quote']}\"[/{self.col_neon}]\n\n"
                f"[{self.col_dim}]— {quote['author']}[/{self.col_dim}]",
                border_style=self.col_success,
                box=box.ROUNDED,
                padding=(2, 4)
            )))
    
    def joke_battle(self, rounds: int = 3):
        """Joke battle with different categories"""
        categories = ["programming", "tech", "one_liner"]
        
        self.console.print(Align.center(Panel(
            f"[bold {self.col_neon}]🤣 JOKE BATTLE 🤣[/bold {self.col_neon}]\n\n"
            f"[{self.col_dim}]Get ready for {rounds} rounds of jokes![/{self.col_dim}]",
            border_style=self.col_neon,
            box=box.ROUNDED,
            padding=(1, 3)
        )))
        
        time.sleep(2)
        
        for round_num in range(1, rounds + 1):
            category = random.choice(categories)
            
            self.console.print(f"\n[bold {self.col_gold}]Round {round_num}: {category.title()}[/bold {self.col_gold}]")
            self.console.input(f"[{self.col_dim}]Press Enter for the joke...[/{self.col_dim}]")
            
            self.display_joke(category)
            
            if round_num < rounds:
                self.console.input(f"[{self.col_dim}]Press Enter for next round...[/{self.col_dim}]")
                self.console.clear()
    
    def random_joke_session(self, count: int = 5):
        """Display random jokes from all categories"""
        all_categories = ["programming", "tech", "one_liner", "excuse", "comment", "quote"]
        
        self.console.print(Align.center(Panel(
            f"[bold {self.col_neon}]🎲 RANDOM JOKE SESSION 🎲[/bold {self.col_neon}]\n\n"
            f"[{self.col_dim}]Get ready for {count} random jokes![/{self.col_dim}]",
            border_style=self.col_neon,
            box=box.ROUNDED,
            padding=(1, 3)
        )))
        
        time.sleep(2)
        
        for i in range(1, count + 1):
            category = random.choice(all_categories)
            
            self.console.print(f"\n[bold {self.col_gold}]Joke {i} of {count}[/bold {self.col_gold}]")
            self.console.input(f"[{self.col_dim}]Press Enter for the joke...[/{self.col_dim}]")
            
            self.display_joke(category)
            
            if i < count:
                self.console.input(f"[{self.col_dim}]Press Enter for next joke...[/{self.col_dim}]")
                self.console.clear()
    
    def run(self):
        """Run random jokes tool"""
        c = self.console
        
        # Display header
        c.print()
        c.print(Align.center(Panel(
            f"[bold {self.col_neon}]🎮 RANDOM JOKES 🎮[/bold {self.col_neon}]\n\n"
            f"[{self.col_dim}]Display random programming jokes and fun content\\n"
            f"Programming jokes, tech humor, one-liners, quotes\\n"
            f"Perfect for a coding break![/{self.col_dim}]",
            border_style=self.col_neon,
            box=box.ROUNDED,
            padding=(1, 4)
        )))
        
        while True:
            c.print(f"\n[{self.col_neon}]🎭 Joke categories:[/{self.col_neon}]")
            c.print(f"  1. Programming Jokes")
            c.print(f"  2. Tech Jokes")
            c.print(f"  3. One-Liners")
            c.print(f"  4. Developer Excuses")
            c.print(f"  5. Funny Code Comments")
            c.print(f"  6. Programming Quotes")
            c.print(f"  7. Joke Battle")
            c.print(f"  8. Random Session")
            c.print(f"  9. Random Single Joke")
            
            choice = Prompt.ask(f"\n[{self.col_neon}]Select category (1-9)[/{self.col_neon}]")
            
            if choice == '1':
                self.display_joke("programming")
                
            elif choice == '2':
                self.display_joke("tech")
                
            elif choice == '3':
                self.display_joke("one_liner")
                
            elif choice == '4':
                self.display_joke("excuse")
                
            elif choice == '5':
                self.display_joke("comment")
                
            elif choice == '6':
                self.display_joke("quote")
                
            elif choice == '7':
                rounds = Prompt.ask(f"[{self.col_neon}]Number of rounds (default: 3)[/{self.col_neon}]") or "3"
                try:
                    rounds = int(rounds)
                    if rounds > 0:
                        self.joke_battle(rounds)
                    else:
                        c.print(f"[{self.col_danger}]✗ Rounds must be positive[/{self.col_danger}]")
                except ValueError:
                    c.print(f"[{self.col_danger}]✗ Invalid number[/{self.col_danger}]")
                
            elif choice == '8':
                count = Prompt.ask(f"[{self.col_neon}]Number of jokes (default: 5)[/{self.col_neon}]") or "5"
                try:
                    count = int(count)
                    if count > 0:
                        self.random_joke_session(count)
                    else:
                        c.print(f"[{self.col_danger}]✗ Count must be positive[/{self.col_danger}]")
                except ValueError:
                    c.print(f"[{self.col_danger}]✗ Invalid number[/{self.col_danger}]")
                
            elif choice == '9':
                # Show loading animation
                with Progress(
                    SpinnerColumn(style=f"bold {self.col_neon}"),
                    TextColumn("[bold bright_white]Finding the perfect joke...[/bold bright_white]"),
                    BarColumn(bar_width=30, style=f"dim {self.col_dim}", complete_style=f"bold {self.col_neon}"),
                    console=c,
                    transient=True
                ) as progress:
                    task = progress.add_task("Searching...", total=100)
                    
                    for i in range(101):
                        progress.update(task, completed=i)
                        if i % 20 == 0:
                            time.sleep(0.1)
                
                all_categories = ["programming", "tech", "one_liner", "excuse", "comment", "quote"]
                category = random.choice(all_categories)
                self.display_joke(category)
                
            else:
                c.print(f"[{self.col_danger}]✗ Invalid choice[/{self.col_danger}]")
                continue
            
            # Save joke option
            save = Prompt.ask(f"\n[{self.col_neon}]Save this joke? (y/n)[/{self.col_neon}]")
            if save.lower() == 'y':
                filename = Prompt.ask(f"[{self.col_neon}]Enter filename[/{self.col_neon}]") + '.txt'
                
                try:
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(f"RANDOM JOKE\n")
                        f.write(f"{'='*50}\n\n")
                        f.write(f"Category: {category if 'category' in locals() else 'Unknown'}\n\n")
                        f.write(f"{joke if 'joke' in locals() else 'Joke content'}\n")
                        f.write(f"\n{'='*50}\n")
                        f.write("Generated by Cosmos.win Random Jokes Tool")
                    
                    c.print(f"[{self.col_success}]✓ Saved to {filename}[/{self.col_success}]")
                except Exception as e:
                    c.print(f"[{self.col_danger}]✗ Error saving: {e}[/{self.col_danger}]")
            
            if Prompt.ask(f"\n[{self.col_neon}]Want another joke? (y/n)[/{self.col_neon}]").lower() != 'y':
                break
