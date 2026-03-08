<div align="center">
  <img src="https://raw.githubusercontent.com/Catppuccin/catppuccin/main/assets/logos/exports/1544x1544_circle.png" width="120" height="auto" />
  <h1>Cosmos.win ✦</h1>
  <p><strong>Multi-Tools by @limoons</strong></p>
  
  <p>
    <img src="https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white" />
    <img src="https://img.shields.io/badge/Release-v6.0.0-ff69b4" />
    <img src="https://img.shields.io/badge/Status-BETA-00ffcc" />
    <img src="https://img.shields.io/badge/Platform-Windows-0078d7?logo=windows&logoColor=white" />
  </p>
  <p><i>An advanced, hyper-stylized Cybersecurity & Reverse Engineering Terminal.</i></p>
</div>

<br/>

## ✦ Overview
**Cosmos.win** is a premium, all-in-one terminal toolkit designed for cybersecurity researchers, reverse engineers, and power users. Featuring a stunning neon-themed CLI/TUI powered by `rich`, Cosmos provides **52 advanced modules** ranging from network scanning and malware analysis to powerful native decompilation tools.

With its robust architecture, Cosmos combines cloud APIs (VirusTotal, AbuseIPDB, Shodan) with incredibly powerful **100% Offline Native Engines** for completely autonomous analysis.

---

## 🚀 Key Features

### 💻 BETA: Decompilers & Reverse Engineering
The crown jewel of Version 6.0.0. A completely automated, hassle-free Reverse Engineering suite built right into your terminal.

-   **Java Decompiler (CFR)**: Magically extracts highly-readable Java source code from compiled `.class` and `.jar` payloads. Features auto-installation of the Java Environment via Winget if missing.
-   **Lua Decompiler (Unluac)**: Specifically targets compiled Lua 5.1/5.2 scripts (`.luac`). Perfect for analyzing game exploits.
-   **Native Lua Obfuscator**: A custom-built, Python-native engine to pack, encrypt, and scramble raw Lua source code (ideal for Roblox / FiveM testing). Features variable minification, string-to-math encoding, and Base64 wrapping.
-   **Native Lua Deobfuscator**: The counter-measure. Features Constant Folding (evaluates math/hex back to strings), automatic Base64 Payload Extraction, and heuristic code beautification.
-   **Python Disassembler**: Disassemble `.pyc` Python binaries back into raw, readable native Bytecode instructions natively.
-   **Strings Extractor**: Slices through any compiled `.exe`, DLL, or memory dump to extract hidden human-readable ASCII/Unicode strings. 

*➜ All Decompiler tools feature automatic syntax highlighting, pagination, and instant export to disk with automatic File Explorer integration.*

### 🛡️ Threat Detection & Removal
-   **Luckyware Scanner**: Detects malware signatures on running processes combining local heuristics and the VirusTotal API.
-   **Ransomware Remover**: Identifies and quarantines suspicious encryption behaviors.
-   **Rootkit & Keylogger Detectors**: Deep system scans to find hidden hooks and stealth persistence.

### 🌐 Network & Intelligence
-   **DNS Blocker**: Modify your hosts to sinkhole telemetry, trackers, and ads.
-   **Packet Sniffer & TCP Tools**: Live protocol decodes, ARP scans, and device fingerprinting.
-   **Threat Intel Lookup**: Aggregate reputation scores from AbuseIPDB, OTX, Shodan, and SecurityTrails.

### ⚙️ System Hardening & Privacy
-   **System Hardening**: Apply CIS benchmark configurations, fix misconfigurations, and disable telemetry.
-   **Password & Privacy Auditors**: Check saved browser credentials against HIBP, clean tracks, and inspect Wifi keys.
-   **Exploit Patcher**: Scans OS for vulnerable CVEs and provides mitigation steps.

---

## 📀 Installation

**1. Clone the repository**
```bash
git clone https://github.com/limoons/Cosmos.win.git
cd Cosmos.win
```

**2. Install dependencies**
```bash
pip install -r requirements.txt
```
*(Core dependencies include: `rich`, `requests`, `psutil`, `pywin32`, `cryptography`, `wmi`, `scapy`, `dnspython`...)*

**3. Run the application**
```bash
python main.py
```
*(It is highly recommended to run Cosmos.win inside **Windows Terminal** for proper font-ligatures and rendering).*

*(Edit : If you want to use Cosmos as a binary file, use my [PyInstaller Batch Builder](https://github.com/limoondev/PyInstaller-Batch-Reimagined))*

---

## 🔑 Access Control System
Cosmos incorporates a secure internal licensing system. To generate a session key:
1. Launch `main.py`.
2. Select **[2] Generate License Key**.
3. A mandatory 10-minute cryptographic generation puzzle will run. **Do not close the window**.
4. Once completed, your unique key will be displayed and is valid for exactly 24 hours.

---

## 📸 Screenshots
*(Add screenshots of your hyper-stylized boot sequence, main dashboard, and decompilers here!)*
- `assets/boot_sequence.jpg`
- `assets/lua_obfuscator.jpg`
- `assets/threat_intel.jpg`

---

## ⚖️ Disclaimer
Cosmos.win is developed for **educational and defensive purposes only**. The developers are not responsible for any misuse, damage, or illegal activities conducted using this toolset. Always obtain explicit permission before analyzing networks, binaries, or infrastructure you do not own.

<br/>

<div align="center">
  <b>Made with ✦ by @limoons</b>
</div>


