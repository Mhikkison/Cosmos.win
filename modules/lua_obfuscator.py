import os
import re
import random
import string
import base64
from rich.panel import Panel
from rich.align import Align
from rich import box
from rich.prompt import Prompt
from rich.console import Console

class LuaObfuscator:
    def __init__(self, console: Console):
        self.console = console
        self.col_neon = "#00ffcc"
        self.col_dim = "bright_black"

    def _generate_junk_name(self, length=12):
        # Generate chaotic variable names like IlIlIllI
        chars = ["I", "l", "O", "0"]
        name = random.choice(["I", "O", "l"]) # Must start with letter
        for _ in range(length - 1):
            name += random.choice(chars)
        return name

    def _encrypt_string(self, match):
        raw_str = match.group(1) or match.group(2)
        if not raw_str: return '""'
        
        # Convert string to math-based byte array
        bytes_list = []
        for char in raw_str:
            val = ord(char)
            # Obfuscate the value with simple math: (val + 10) - 10
            offset = random.randint(5, 50)
            obf_val = f"({val + offset}-{offset})"
            bytes_list.append(obf_val)
            
        return "string.char(" + ",".join(bytes_list) + ")"

    def _obfuscate(self, source: str) -> str:
        # 1. Remove comments (basic -- comments, doesn't handle multi-line [[ ]] perfectly but good enough for generic scripts)
        source = re.sub(r'--.*$', '', source, flags=re.MULTILINE)
        
        # 2. Encrypt Strings (matches "string" and 'string')
        # This regex avoids matching inside already encoded things mostly
        source = re.sub(r'"([^"\\]*(\\.[^"\\]*)*)"', self._encrypt_string, source)
        source = re.sub(r"'([^'\\]*(\\.[^'\\]*)*)'", self._encrypt_string, source)

        # 3. Minify (remove extra spaces and newlines)
        lines = [line.strip() for line in source.split('\n') if line.strip()]
        minified = " ".join(lines)
        
        # 4. Wrap payload in a base64 loadstring executor wrapper
        b64_payload = base64.b64encode(minified.encode('utf-8')).decode('utf-8')
        
        func_name = self._generate_junk_name(16)
        decode_func = self._generate_junk_name(12)
        
        # A generic wrapper that decrypts base64 and executes it
        wrapper = f"""
local {decode_func} = function(str)
    local b = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    str = string.gsub(str, '[^'..b..'=]', '')
    return (str:gsub('.', function(x)
        if (x == '=') then return '' end
        local r,f='',(b:find(x)-1)
        for i=6,1,-1 do r=r..(f%2^i-f%2^(i-1)>0 and '1' or '0') end
        return r;
    end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
        if (#x ~= 8) then return '' end
        local c=0
        for i=1,8 do c=c+(x:sub(i,i)=='1' and 2^(8-i) or 0) end
        return string.char(c)
    end))
end

local {func_name} = loadstring({decode_func}("{b64_payload}"))
if {func_name} then {func_name}() end
"""
        return wrapper.strip()

    def run(self):
        c = self.console
        c.print()
        c.print(Align.center(Panel(
            f"[bold {self.col_neon}]✦ LUA OBFUSCATOR ✦[/bold {self.col_neon}]\n\n"
            f"[{self.col_dim}]Obfuscate and pack raw Lua source scripts (e.g. Roblox, FiveM).\n"
            f"Generates highly unreadable, executable Lua code.[/{self.col_dim}]",
            border_style=self.col_neon,
            box=box.ROUNDED,
            padding=(1, 4)
        )))
        c.print()
        
        export_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "exports")
        os.makedirs(export_dir, exist_ok=True)

        while True:
            file_path = Prompt.ask(f"  [{self.col_neon}]Path to Lua source file (or 'q' to quit)[/{self.col_neon}]").strip()
            
            if file_path.lower() == 'q':
                break
                
            if not file_path:
                continue
                
            file_path = file_path.strip('"').strip("'").strip()
            
            if not os.path.isfile(file_path):
                c.print("  [bold red]✗ File not found.[/bold red]\n")
                continue
                
            c.print(f"\n  [dim]Obfuscating {os.path.basename(file_path)}...[/dim]")
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    source = f.read()
                    
                obfuscated = self._obfuscate(source)
                
                out_name = os.path.basename(file_path).replace('.lua', '') + '_obfuscated.lua'
                out_path = os.path.join(export_dir, out_name)
                
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write("-- Obfuscated by Cosmos.win Lua Packer\n")
                    f.write(obfuscated)
                    
                c.print(f"  [bold green]✓ Script successfully obfuscated. Exported to:[/bold green] {out_path}")
                try:
                    if os.name == 'nt':
                        os.startfile(export_dir)
                except Exception:
                    pass
                c.print()
                    
            except Exception as e:
                c.print(f"  [bold red]✗ Unexpected error: {e}[/bold red]\n")
                
        c.input(f"\n  [{self.col_dim}]Press Enter to return...[/{self.col_dim}]")
