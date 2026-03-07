"""
System Info Tool
Show detailed system information in a beautiful way
"""

import os
import platform
import psutil
import time
import socket
from rich.console import Console
from rich.panel import Panel
from rich.align import Align
from rich import box
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.table import Table
from rich.tree import Tree
from rich.columns import Columns

class SystemInfo:
    def __init__(self, console: Console):
        self.console = console
        self.col_neon = "#00ffcc"
        self.col_success = "#00e676"
        self.col_warn = "#ffab00"
        self.col_danger = "#ff1744"
        self.col_pink = "#ff6ec7"
        self.col_gold = "#ffd700"
        self.col_dim = "bright_black"
        self.col_cyan = "#4fc3f7"
        
    def get_system_overview(self) -> dict:
        """Get basic system overview"""
        return {
            'platform': platform.system(),
            'platform_release': platform.release(),
            'platform_version': platform.version(),
            'architecture': platform.machine(),
            'processor': platform.processor(),
            'hostname': socket.gethostname(),
            'python_version': platform.python_version()
        }
    
    def get_cpu_info(self) -> dict:
        """Get CPU information"""
        return {
            'name': platform.processor(),
            'cores': psutil.cpu_count(logical=False),
            'threads': psutil.cpu_count(logical=True),
            'usage_percent': psutil.cpu_percent(interval=1),
            'frequency': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None,
            'load_avg': os.getloadavg() if hasattr(os, 'getloadavg') else None
        }
    
    def get_memory_info(self) -> dict:
        """Get memory information"""
        virtual = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        return {
            'virtual': {
                'total': virtual.total,
                'available': virtual.available,
                'used': virtual.used,
                'percent': virtual.percent
            },
            'swap': {
                'total': swap.total,
                'used': swap.used,
                'free': swap.free,
                'percent': swap.percent
            }
        }
    
    def get_disk_info(self) -> list:
        """Get disk information"""
        disks = []
        partitions = psutil.disk_partitions()
        
        for partition in partitions:
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disks.append({
                    'device': partition.device,
                    'mountpoint': partition.mountpoint,
                    'fstype': partition.fstype,
                    'total': usage.total,
                    'used': usage.used,
                    'free': usage.free,
                    'percent': (usage.used / usage.total) * 100
                })
            except PermissionError:
                continue
        
        return disks
    
    def get_network_info(self) -> dict:
        """Get network information"""
        net_io = psutil.net_io_counters()
        net_addrs = psutil.net_if_addrs()
        net_stats = psutil.net_if_stats()
        
        return {
            'hostname': socket.gethostname(),
            'ip_address': socket.gethostbyname(socket.gethostname()),
            'io_counters': {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv
            },
            'interfaces': list(net_addrs.keys())
        }
    
    def get_process_info(self) -> list:
        """Get top processes information"""
        processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        # Sort by CPU usage and get top 10
        processes.sort(key=lambda x: x.get('cpu_percent', 0), reverse=True)
        return processes[:10]
    
    def get_boot_time(self) -> dict:
        """Get boot time information"""
        boot_time = psutil.boot_time()
        uptime = time.time() - boot_time
        
        return {
            'boot_time': boot_time,
            'uptime_seconds': uptime,
            'uptime_days': uptime / 86400,
            'uptime_hours': uptime / 3600
        }
    
    def format_bytes(self, bytes_value: int) -> str:
        """Format bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} PB"
    
    def format_uptime(self, seconds: float) -> str:
        """Format uptime to human readable format"""
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        minutes = int((seconds % 3600) // 60)
        
        if days > 0:
            return f"{days}d {hours}h {minutes}m"
        elif hours > 0:
            return f"{hours}h {minutes}m"
        else:
            return f"{minutes}m"
    
    def create_system_table(self, title: str, data: dict, color: str) -> Table:
        """Create a table for system information"""
        table = Table(
            title=f"[bold {color}]{title}[/bold {color}]",
            box=box.ROUNDED,
            show_header=True
        )
        
        table.add_column("Property", style=f"bold {self.col_cyan}", justify="left")
        table.add_column("Value", style=f"bold {color}", justify="right")
        
        for key, value in data.items():
            if value is not None:
                formatted_key = key.replace('_', ' ').title()
                table.add_row(formatted_key, str(value))
        
        return table
    
    def create_progress_bar(self, percentage: float, color: str) -> str:
        """Create a progress bar"""
        filled = int(percentage / 10)
        bar = "█" * filled + "░" * (10 - filled)
        return f"[{color}]{bar}[/{color}] {percentage:.1f}%"
    
    def run(self):
        """Run system info tool"""
        c = self.console
        
        # Display header
        c.print()
        c.print(Align.center(Panel(
            f"[bold {self.col_neon}]🎮 SYSTEM INFO 🎮[/bold {self.col_neon}]\n\n"
            f"[{self.col_dim}]Show detailed system information\\n"
            f"Hardware, software, network, and performance stats\\n"
            f"Real-time system monitoring[/{self.col_dim}]",
            border_style=self.col_neon,
            box=box.ROUNDED,
            padding=(1, 4)
        )))
        
        while True:
            c.print(f"\n[{self.col_neon}]📊 Information categories:[/{self.col_neon}]")
            c.print(f"  1. System Overview")
            c.print(f"  2. CPU Information")
            c.print(f"  3. Memory Information")
            c.print(f"  4. Disk Information")
            c.print(f"  5. Network Information")
            c.print(f"  6. Top Processes")
            c.print(f"  7. Boot & Uptime")
            c.print(f"  8. Full System Report")
            c.print(f"  9. Real-time Monitoring")
            
            choice = Prompt.ask(f"\n[{self.col_neon}]Select category (1-9)[/{self.col_neon}]")
            
            if choice == '1':
                # System Overview
                with Progress(
                    SpinnerColumn(style=f"bold {self.col_neon}"),
                    TextColumn("[bold bright_white]Gathering system info...[/bold bright_white]"),
                    BarColumn(bar_width=30, style=f"dim {self.col_dim}", complete_style=f"bold {self.col_neon}"),
                    console=c,
                    transient=True
                ) as progress:
                    task = progress.add_task("Collecting data...", total=100)
                    
                    for i in range(101):
                        progress.update(task, completed=i)
                        if i % 20 == 0:
                            time.sleep(0.1)
                
                overview = self.get_system_overview()
                table = self.create_system_table("System Overview", overview, self.col_gold)
                c.print("\n")
                c.print(Align.center(table))
                
            elif choice == '2':
                # CPU Information
                with Progress(
                    SpinnerColumn(style=f"bold {self.col_neon}"),
                    TextColumn("[bold bright_white]Analyzing CPU...[/bold bright_white]"),
                    BarColumn(bar_width=30, style=f"dim {self.col_dim}", complete_style=f"bold {self.col_neon}"),
                    console=c,
                    transient=True
                ) as progress:
                    task = progress.add_task("Analyzing...", total=100)
                    
                    for i in range(101):
                        progress.update(task, completed=i)
                        if i % 20 == 0:
                            time.sleep(0.1)
                
                cpu_info = self.get_cpu_info()
                
                # CPU table
                cpu_table = Table(
                    title=f"[bold {self.col_pink}]CPU Information[/bold {self.col_pink}]",
                    box=box.ROUNDED
                )
                cpu_table.add_column("Property", style=f"bold {self.col_cyan}")
                cpu_table.add_column("Value", style=f"bold {self.col_pink}")
                
                cpu_table.add_row("Processor", cpu_info['name'])
                cpu_table.add_row("Physical Cores", str(cpu_info['cores']))
                cpu_table.add_row("Logical Threads", str(cpu_info['threads']))
                cpu_table.add_row("Usage", self.create_progress_bar(cpu_info['usage_percent'], self.col_pink))
                
                if cpu_info['frequency']:
                    freq = cpu_info['frequency']
                    cpu_table.add_row("Current Frequency", f"{freq['current']:.2f} MHz")
                    cpu_table.add_row("Min Frequency", f"{freq['min']:.2f} MHz")
                    cpu_table.add_row("Max Frequency", f"{freq['max']:.2f} MHz")
                
                c.print("\n")
                c.print(Align.center(cpu_table))
                
            elif choice == '3':
                # Memory Information
                with Progress(
                    SpinnerColumn(style=f"bold {self.col_neon}"),
                    TextColumn("[bold bright_white]Analyzing memory...[/bold bright_white]"),
                    BarColumn(bar_width=30, style=f"dim {self.col_dim}", complete_style=f"bold {self.col_neon}"),
                    console=c,
                    transient=True
                ) as progress:
                    task = progress.add_task("Analyzing...", total=100)
                    
                    for i in range(101):
                        progress.update(task, completed=i)
                        if i % 20 == 0:
                            time.sleep(0.1)
                
                mem_info = self.get_memory_info()
                
                # Memory table
                mem_table = Table(
                    title=f"[bold {self.col_cyan}]Memory Information[/bold {self.col_cyan}]",
                    box=box.ROUNDED
                )
                mem_table.add_column("Type", style=f"bold {self.col_cyan}")
                mem_table.add_column("Total", style=f"bold {self.col_gold}")
                mem_table.add_column("Used", style=f"bold {self.col_pink}")
                mem_table.add_column("Free", style=f"bold {self.col_success}")
                mem_table.add_column("Usage", style="bold")
                
                # Virtual memory
                virt = mem_info['virtual']
                mem_table.add_row(
                    "Virtual Memory",
                    self.format_bytes(virt['total']),
                    self.format_bytes(virt['used']),
                    self.format_bytes(virt['available']),
                    self.create_progress_bar(virt['percent'], self.col_pink)
                )
                
                # Swap memory
                swap = mem_info['swap']
                mem_table.add_row(
                    "Swap Memory",
                    self.format_bytes(swap['total']),
                    self.format_bytes(swap['used']),
                    self.format_bytes(swap['free']),
                    self.create_progress_bar(swap['percent'], self.col_warn)
                )
                
                c.print("\n")
                c.print(Align.center(mem_table))
                
            elif choice == '4':
                # Disk Information
                with Progress(
                    SpinnerColumn(style=f"bold {self.col_neon}"),
                    TextColumn("[bold bright_white]Scanning disks...[/bold bright_white]"),
                    BarColumn(bar_width=30, style=f"dim {self.col_dim}", complete_style=f"bold {self.col_neon}"),
                    console=c,
                    transient=True
                ) as progress:
                    task = progress.add_task("Scanning...", total=100)
                    
                    for i in range(101):
                        progress.update(task, completed=i)
                        if i % 20 == 0:
                            time.sleep(0.1)
                
                disks = self.get_disk_info()
                
                # Disk table
                disk_table = Table(
                    title=f"[bold {self.col_success}]Disk Information[/bold {self.col_success}]",
                    box=box.ROUNDED
                )
                disk_table.add_column("Device", style=f"bold {self.col_cyan}")
                disk_table.add_column("Mount", style=f"bold {self.col_gold}")
                disk_table.add_column("Type", style=f"bold {self.col_pink}")
                disk_table.add_column("Total", style=f"bold {self.col_success}")
                disk_table.add_column("Used", style=f"bold {self.col_warn}")
                disk_table.add_column("Free", style=f"bold {self.col_neon}")
                disk_table.add_column("Usage", style="bold")
                
                for disk in disks:
                    disk_table.add_row(
                        disk['device'],
                        disk['mountpoint'],
                        disk['fstype'],
                        self.format_bytes(disk['total']),
                        self.format_bytes(disk['used']),
                        self.format_bytes(disk['free']),
                        self.create_progress_bar(disk['percent'], self.col_warn)
                    )
                
                c.print("\n")
                c.print(Align.center(disk_table))
                
            elif choice == '5':
                # Network Information
                with Progress(
                    SpinnerColumn(style=f"bold {self.col_neon}"),
                    TextColumn("[bold bright_white]Analyzing network...[/bold bright_white]"),
                    BarColumn(bar_width=30, style=f"dim {self.col_dim}", complete_style=f"bold {self.col_neon}"),
                    console=c,
                    transient=True
                ) as progress:
                    task = progress.add_task("Analyzing...", total=100)
                    
                    for i in range(101):
                        progress.update(task, completed=i)
                        if i % 20 == 0:
                            time.sleep(0.1)
                
                net_info = self.get_network_info()
                
                # Network table
                net_table = Table(
                    title=f"[bold {self.col_purple}]Network Information[/bold {self.col_purple}]",
                    box=box.ROUNDED
                )
                net_table.add_column("Property", style=f"bold {self.col_cyan}")
                net_table.add_column("Value", style=f"bold {self.col_purple}")
                
                net_table.add_row("Hostname", net_info['hostname'])
                net_table.add_row("IP Address", net_info['ip_address'])
                net_table.add_row("Bytes Sent", self.format_bytes(net_info['io_counters']['bytes_sent']))
                net_table.add_row("Bytes Received", self.format_bytes(net_info['io_counters']['bytes_recv']))
                net_table.add_row("Packets Sent", f"{net_info['io_counters']['packets_sent']:,}")
                net_table.add_row("Packets Received", f"{net_info['io_counters']['packets_recv']:,}")
                
                c.print("\n")
                c.print(Align.center(net_table))
                
                # Interfaces
                c.print(f"\n[bold {self.col_purple}]Network Interfaces:[/bold {self.col_purple}]")
                for interface in net_info['interfaces']:
                    c.print(f"  • {interface}")
                
            elif choice == '6':
                # Top Processes
                with Progress(
                    SpinnerColumn(style=f"bold {self.col_neon}"),
                    TextColumn("[bold bright_white]Scanning processes...[/bold bright_white]"),
                    BarColumn(bar_width=30, style=f"dim {self.col_dim}", complete_style=f"bold {self.col_neon}"),
                    console=c,
                    transient=True
                ) as progress:
                    task = progress.add_task("Scanning...", total=100)
                    
                    for i in range(101):
                        progress.update(task, completed=i)
                        if i % 20 == 0:
                            time.sleep(0.1)
                
                processes = self.get_process_info()
                
                # Process table
                proc_table = Table(
                    title=f"[bold {self.col_warn}]Top 10 Processes by CPU Usage[/bold {self.col_warn}]",
                    box=box.ROUNDED
                )
                proc_table.add_column("PID", style=f"bold {self.col_cyan}")
                proc_table.add_column("Name", style=f"bold {self.col_gold}")
                proc_table.add_column("CPU %", style=f"bold {self.col_pink}")
                proc_table.add_column("Memory %", style=f"bold {self.col_success}")
                
                for proc in processes:
                    proc_table.add_row(
                        str(proc['pid']),
                        proc['name'][:20],
                        f"{proc.get('cpu_percent', 0):.1f}%",
                        f"{proc.get('memory_percent', 0):.1f}%"
                    )
                
                c.print("\n")
                c.print(Align.center(proc_table))
                
            elif choice == '7':
                # Boot & Uptime
                with Progress(
                    SpinnerColumn(style=f"bold {self.col_neon}"),
                    TextColumn("[bold bright_white]Calculating uptime...[/bold bright_white]"),
                    BarColumn(bar_width=30, style=f"dim {self.col_dim}", complete_style=f"bold {self.col_neon}"),
                    console=c,
                    transient=True
                ) as progress:
                    task = progress.add_task("Calculating...", total=100)
                    
                    for i in range(101):
                        progress.update(task, completed=i)
                        if i % 20 == 0:
                            time.sleep(0.1)
                
                boot_info = self.get_boot_time()
                
                # Boot table
                boot_table = Table(
                    title=f"[bold {self.col_neon}]Boot & Uptime Information[/bold {self.col_neon}]",
                    box=box.ROUNDED
                )
                boot_table.add_column("Property", style=f"bold {self.col_cyan}")
                boot_table.add_column("Value", style=f"bold {self.col_neon}")
                
                import datetime
                boot_time_str = datetime.datetime.fromtimestamp(boot_info['boot_time']).strftime('%Y-%m-%d %H:%M:%S')
                
                boot_table.add_row("Boot Time", boot_time_str)
                boot_table.add_row("Uptime", self.format_uptime(boot_info['uptime_seconds']))
                boot_table.add_row("Uptime Days", f"{boot_info['uptime_days']:.1f} days")
                boot_table.add_row("Uptime Hours", f"{boot_info['uptime_hours']:.1f} hours")
                
                c.print("\n")
                c.print(Align.center(boot_table))
                
            elif choice == '8':
                # Full System Report
                c.print(f"\n[{self.col_neon}]📊 Generating full system report...[/{self.col_neon}]")
                
                with Progress(
                    SpinnerColumn(style=f"bold {self.col_neon}"),
                    TextColumn("[bold bright_white]Collecting all data...[/bold bright_white]"),
                    BarColumn(bar_width=40, style=f"dim {self.col_dim}", complete_style=f"bold {self.col_neon}"),
                    console=c,
                    transient=True
                ) as progress:
                    task = progress.add_task("Generating report...", total=100)
                    
                    # Collect all data
                    for i in range(101):
                        progress.update(task, completed=i)
                        if i % 10 == 0:
                            time.sleep(0.05)
                
                # Display all tables
                overview = self.get_system_overview()
                cpu_info = self.get_cpu_info()
                mem_info = self.get_memory_info()
                disks = self.get_disk_info()
                net_info = self.get_network_info()
                boot_info = self.get_boot_time()
                
                # Create columns for better layout
                c.print("\n")
                c.print(Align.center(f"[bold {self.col_gold}]🖥️ SYSTEM REPORT 🖥️[/bold {self.col_gold}]"))
                
                # System Overview
                overview_table = self.create_system_table("System Overview", overview, self.col_gold)
                c.print("\n")
                c.print(Align.center(overview_table))
                
                # CPU & Memory side by side
                cpu_table = self.create_system_table("CPU Info", {
                    'Processor': cpu_info['name'],
                    'Cores': cpu_info['cores'],
                    'Threads': cpu_info['threads'],
                    'Usage': f"{cpu_info['usage_percent']:.1f}%"
                }, self.col_pink)
                
                mem_table = self.create_system_table("Memory Info", {
                    'Total RAM': self.format_bytes(mem_info['virtual']['total']),
                    'Used RAM': self.format_bytes(mem_info['virtual']['used']),
                    'Free RAM': self.format_bytes(mem_info['virtual']['available']),
                    'RAM Usage': f"{mem_info['virtual']['percent']:.1f}%"
                }, self.col_cyan)
                
                columns = Columns([cpu_table, mem_table], equal=True)
                c.print("\n")
                c.print(Align.center(columns))
                
            elif choice == '9':
                # Real-time Monitoring
                c.print(f"\n[{self.col_neon}]📡 Starting real-time monitoring...[/{self.col_neon}]")
                c.print(f"[{self.col_dim}]Press Ctrl+C to stop monitoring[/{self.col_dim}]")
                c.input(f"[{self.col_dim}]Press Enter to start...[/{self.col_dim}]")
                
                try:
                    while True:
                        c.clear()
                        
                        # Get current stats
                        cpu_usage = psutil.cpu_percent()
                        memory = psutil.virtual_memory()
                        disk_io = psutil.disk_io_counters()
                        net_io = psutil.net_io_counters()
                        
                        # Create real-time display
                        c.print(Align.center(f"[bold {self.col_neon}]🔴 LIVE SYSTEM MONITOR 🔴[/bold {self.col_neon}]"))
                        c.print(f"\n[bold {self.col_pink}]CPU Usage:[/bold {self.col_pink}] {self.create_progress_bar(cpu_usage, self.col_pink)}")
                        c.print(f"[bold {self.col_cyan}]Memory Usage:[/bold {self.col_cyan}] {self.create_progress_bar(memory.percent, self.col_cyan)}")
                        c.print(f"[bold {self.col_success}]Disk Read:[/bold {self.col_success}] {self.format_bytes(disk_io.read_bytes)}")
                        c.print(f"[bold {self.col_warn}]Disk Write:[/bold {self.col_warn}] {self.format_bytes(disk_io.write_bytes)}")
                        c.print(f"[bold {self.col_purple}]Network Sent:[/bold {self.col_purple}] {self.format_bytes(net_io.bytes_sent)}")
                        c.print(f"[bold {self.col_gold}]Network Received:[/bold {self.col_gold}] {self.format_bytes(net_io.bytes_recv)}")
                        
                        time.sleep(1)
                        
                except KeyboardInterrupt:
                    c.print(f"\n[{self.col_warn}]Monitoring stopped by user[/{self.col_warn}]")
                
            else:
                c.print(f"[{self.col_danger}]✗ Invalid choice[/{self.col_danger}]")
                continue
            
            # Save report option
            if choice in ['1', '2', '3', '4', '5', '6', '7', '8']:
                save = Prompt.ask(f"\n[{self.col_neon}]Save system report? (y/n)[/{self.col_neon}]")
                if save.lower() == 'y':
                    filename = Prompt.ask(f"[{self.col_neon}]Enter filename[/{self.col_neon}]") + '.txt'
                    
                    try:
                        with open(filename, 'w', encoding='utf-8') as f:
                            f.write("SYSTEM INFORMATION REPORT\n")
                            f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                            f.write("="*50 + "\n\n")
                            
                            # Add all collected data
                            if choice == '8':
                                f.write("FULL SYSTEM REPORT\n")
                                f.write(f"System: {overview}\n")
                                f.write(f"CPU: {cpu_info}\n")
                                f.write(f"Memory: {mem_info}\n")
                                f.write(f"Disks: {disks}\n")
                                f.write(f"Network: {net_info}\n")
                                f.write(f"Boot: {boot_info}\n")
                        
                        c.print(f"[{self.col_success}]✓ Report saved to {filename}[/{self.col_success}]")
                    except Exception as e:
                        c.print(f"[{self.col_danger}]✗ Error saving: {e}[/{self.col_danger}]")
            
            if Prompt.ask(f"\n[{self.col_neon}]View another category? (y/n)[/{self.col_neon}]").lower() != 'y':
                break
