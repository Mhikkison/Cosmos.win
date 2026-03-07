#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════╗
║               CosmosV2-Win  Build Script                  ║
║                   by @limoonsfn                           ║
╠═══════════════════════════════════════════════════════════╣
║  Name    : CosmosV2-Win                                   ║
║  Author  : Limoon's                                       ║
║  Version : 1.1.2                                          ║
╚═══════════════════════════════════════════════════════════╝

Builds a standalone .exe using PyInstaller.
Run:  python build.py
"""

import os
import sys
import shutil
import subprocess
import time

# ── Build Configuration ──────────────────────────────────────────────────
APP_NAME        = "CosmosV11"
APP_AUTHOR      = "Limoons"
APP_VERSION     = "6.0.1"
APP_CREDIT      = "by @limoonsfn"
ENTRY_POINT     = "main.py"
ICON_PATH       = "assets/icon.ico"  # Set to "assets/icon.ico" if you have one
ONE_FILE        = True
CONSOLE         = True  # True = console app (required for terminal UI)

# Directories / files to include as data
DATA_INCLUDES   = [
    ("modules", "modules"),
    ("utils", "utils"),
]

# Hidden imports that PyInstaller might miss
HIDDEN_IMPORTS  = [
    "rich",
    "rich.console",
    "rich.panel",
    "rich.table",
    "rich.align",
    "rich.text",
    "rich.layout",
    "rich.live",
    "rich.progress",
    "rich.prompt",
    "rich.traceback",
    "rich.columns",
    "rich.box",
    "rich.cells",
    "rich._unicode_data",
    "psutil",
    "colorama",
    "pyfiglet",
    "dns",
    "dns.resolver",
    "cryptography",
    "cryptography.hazmat.primitives.ciphers",
    "cryptography.hazmat.primitives",
    "cryptography.hazmat.backends",
    "requests",
    "prompt_toolkit",
]

# Collect ALL submodules from these packages (catches dynamic imports like
# rich._unicode_data.unicode17-0-0 that PyInstaller misses)
COLLECT_SUBMODULES = [
    "rich",
    "rich._unicode_data",
]

# Extra PyInstaller flags
EXTRA_FLAGS     = [
    "--clean",
    "--noconfirm",
]

# ── Version Info (Windows .exe metadata) ─────────────────────────────────
VERSION_INFO_TEMPLATE = """
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=({major}, {minor}, {patch}, 0),
    prodvers=({major}, {minor}, {patch}, 0),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo(
      [
        StringTable(
          u'040904B0',
          [
            StringStruct(u'CompanyName', u'{author}'),
            StringStruct(u'FileDescription', u'{name} - Cybersecurity Terminal {credit}'),
            StringStruct(u'FileVersion', u'{version}'),
            StringStruct(u'InternalName', u'{name}'),
            StringStruct(u'LegalCopyright', u'(c) {author} {credit}'),
            StringStruct(u'OriginalFilename', u'{name}.exe'),
            StringStruct(u'ProductName', u'{name}'),
            StringStruct(u'ProductVersion', u'{version}'),
          ]
        )
      ]
    ),
    VarFileInfo([VarStruct(u'Translation', [1033, 1200])])
  ]
)
"""


def banner():
    """Print build banner."""
    print()
    print("\033[96m" + "=" * 60 + "\033[0m")
    print("\033[96m" + f"  {APP_NAME} v{APP_VERSION}".center(60) + "\033[0m")
    print("\033[96m" + f"  {APP_CREDIT}".center(60) + "\033[0m")
    print("\033[96m" + f"  Author: {APP_AUTHOR}".center(60) + "\033[0m")
    print("\033[96m" + "=" * 60 + "\033[0m")
    print()


def check_pyinstaller():
    """Ensure PyInstaller is installed."""
    try:
        import PyInstaller
        print(f"\033[92m[OK]\033[0m PyInstaller {PyInstaller.__version__} found")
        return True
    except ImportError:
        print("\033[93m[!]\033[0m PyInstaller not found. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
        print("\033[92m[OK]\033[0m PyInstaller installed")
        return True


def check_requirements():
    """Install requirements.txt if present."""
    req_file = os.path.join(os.path.dirname(__file__), "requirements.txt")
    if os.path.isfile(req_file):
        print("\033[94m[*]\033[0m Installing requirements...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "-r", req_file],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        print("\033[92m[OK]\033[0m Requirements installed")


def generate_version_file():
    """Generate a PyInstaller version-info file for Windows .exe metadata."""
    parts = APP_VERSION.split(".")
    major = int(parts[0]) if len(parts) > 0 else 1
    minor = int(parts[1]) if len(parts) > 1 else 0
    patch = int(parts[2]) if len(parts) > 2 else 0

    content = VERSION_INFO_TEMPLATE.format(
        major=major, minor=minor, patch=patch,
        name=APP_NAME, author=APP_AUTHOR,
        version=APP_VERSION, credit=APP_CREDIT,
    )

    version_file = os.path.join(os.path.dirname(__file__), "version_info.txt")
    with open(version_file, "w", encoding="utf-8") as f:
        f.write(content.strip())

    print(f"\033[92m[OK]\033[0m Version info generated (v{APP_VERSION})")
    return version_file


def build():
    """Run PyInstaller to create the executable."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    entry = os.path.join(base_dir, ENTRY_POINT)

    if not os.path.isfile(entry):
        print(f"\033[91m[ERROR]\033[0m Entry point not found: {entry}")
        sys.exit(1)

    # Generate version info
    version_file = generate_version_file()

    # Build the PyInstaller command
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name", APP_NAME,
    ]

    if ONE_FILE:
        cmd.append("--onefile")

    if CONSOLE:
        cmd.append("--console")
    else:
        cmd.append("--windowed")

    if ICON_PATH and os.path.isfile(os.path.join(base_dir, ICON_PATH)):
        cmd.extend(["--icon", os.path.join(base_dir, ICON_PATH)])

    # Add version info
    cmd.extend(["--version-file", version_file])

    # Add data includes
    separator = ";" if sys.platform == "win32" else ":"
    for src, dst in DATA_INCLUDES:
        src_path = os.path.join(base_dir, src)
        if os.path.exists(src_path):
            cmd.extend(["--add-data", f"{src_path}{separator}{dst}"])
            print(f"\033[94m[*]\033[0m Including data: {src} -> {dst}")

    # Add hidden imports
    for imp in HIDDEN_IMPORTS:
        cmd.extend(["--hidden-import", imp])

    # Collect all submodules for packages with dynamic imports
    for pkg in COLLECT_SUBMODULES:
        cmd.extend(["--collect-submodules", pkg])
        print(f"\033[94m[*]\033[0m Collecting submodules: {pkg}")

    # Add extra flags
    cmd.extend(EXTRA_FLAGS)

    # Add entry point
    cmd.append(entry)

    print()
    print(f"\033[94m[*]\033[0m Building {APP_NAME} v{APP_VERSION} {APP_CREDIT}...")
    print(f"\033[94m[*]\033[0m Author: {APP_AUTHOR}")
    print(f"\033[94m[*]\033[0m Mode: {'OneFile' if ONE_FILE else 'Directory'}")
    print(f"\033[94m[*]\033[0m Console: {CONSOLE}")
    print()

    start = time.time()
    result = subprocess.run(cmd, cwd=base_dir)
    elapsed = time.time() - start

    if result.returncode == 0:
        # Find the output
        if ONE_FILE:
            ext = ".exe" if sys.platform == "win32" else ""
            output = os.path.join(base_dir, "dist", f"{APP_NAME}{ext}")
        else:
            output = os.path.join(base_dir, "dist", APP_NAME)

        print()
        print("\033[92m" + "=" * 60 + "\033[0m")
        print("\033[92m" + "  BUILD SUCCESSFUL".center(60) + "\033[0m")
        print("\033[92m" + "=" * 60 + "\033[0m")
        print()
        print(f"  \033[96mName:\033[0m     {APP_NAME}")
        print(f"  \033[96mVersion:\033[0m  {APP_VERSION}")
        print(f"  \033[96mAuthor:\033[0m   {APP_AUTHOR}")
        print(f"  \033[96mCredit:\033[0m   {APP_CREDIT}")
        print(f"  \033[96mOutput:\033[0m   {output}")

        if os.path.isfile(output):
            size_mb = os.path.getsize(output) / (1024 * 1024)
            print(f"  \033[96mSize:\033[0m     {size_mb:.1f} MB")

        print(f"  \033[96mTime:\033[0m     {elapsed:.1f}s")
        print()

        # Cleanup version info file
        if os.path.isfile(version_file):
            os.remove(version_file)

    else:
        print()
        print("\033[91m" + "=" * 60 + "\033[0m")
        print("\033[91m" + "  BUILD FAILED".center(60) + "\033[0m")
        print("\033[91m" + "=" * 60 + "\033[0m")
        print(f"\n  \033[91mPyInstaller exited with code {result.returncode}\033[0m")
        print("  Check the output above for errors.")
        sys.exit(1)


def clean():
    """Remove build artifacts."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    for folder in ["build", "dist", "__pycache__"]:
        path = os.path.join(base_dir, folder)
        if os.path.isdir(path):
            shutil.rmtree(path)
            print(f"\033[93m[*]\033[0m Removed {folder}/")

    spec_file = os.path.join(base_dir, f"{APP_NAME}.spec")
    if os.path.isfile(spec_file):
        os.remove(spec_file)
        print(f"\033[93m[*]\033[0m Removed {APP_NAME}.spec")

    version_file = os.path.join(base_dir, "version_info.txt")
    if os.path.isfile(version_file):
        os.remove(version_file)
        print(f"\033[93m[*]\033[0m Removed version_info.txt")


if __name__ == "__main__":
    banner()

    if len(sys.argv) > 1 and sys.argv[1] == "clean":
        print("\033[94m[*]\033[0m Cleaning build artifacts...\n")
        clean()
        print("\n\033[92m[OK]\033[0m Clean complete.")
        sys.exit(0)

    # Pre-flight checks
    check_pyinstaller()
    check_requirements()
    print()

    # Build
    build()