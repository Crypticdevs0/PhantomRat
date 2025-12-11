#!/usr/bin/env python3
"""
Quick test script for PhantomRAT
"""

import sys
import os
import json
import pathlib

def check_files():
    """Check if required files exist"""
    required_files = [
        'phantomrat_c2.py',
        'phantomrat_main.py',
        'malleable_profile.json',
        'requirements.txt'
    ]
    
    print("[*] Checking required files...")
    missing = []
    for file in required_files:
        if os.path.exists(file):
            print(f"  ✓ {file}")
        else:
            print(f"  ✗ {file} - MISSING")
            missing.append(file)
    
    return len(missing) == 0

def check_config():
    """Check configuration"""
    print("\n[*] Checking configuration...")

    try:
        with open('malleable_profile.json', 'r') as f:
            config = json.load(f)

        c2_server = config.get('c2', {}).get('primary', '')
        if c2_server:
            print(f"  ✓ C2 Server: {c2_server}")
        else:
            print("  ⚠ C2 Server not configured in malleable_profile.json")

        telegram_cfg = config.get('notifications', {}).get('telegram', {})
        bot_token = telegram_cfg.get('bot_token', '') or os.environ.get('TELEGRAM_BOT_TOKEN', '')
        chat_id = telegram_cfg.get('chat_id', '') or os.environ.get('TELEGRAM_CHAT_ID', '')
        if bot_token and chat_id and 'YOUR_BOT_TOKEN' not in bot_token and 'YOUR_CHAT_ID' not in chat_id:
            print("  ✓ Telegram notifications configured")
        else:
            print("  ✗ Telegram bot token/chat ID missing or placeholder")
            return False

        return True
    except Exception as e:
        print(f"  ✗ Error reading config: {e}")
        return False


def check_credentials():
    """Ensure dashboard credentials are customized"""
    print("\n[*] Checking dashboard credentials...")
    default_password = 'phantomrat'
    env_password = os.environ.get('PHANTOM_ADMIN_PASSWORD', '')
    cred_path = pathlib.Path('phantom_admin.json')

    if env_password:
        if env_password != default_password:
            print("  ✓ Admin password provided via environment")
            return True
        print("  ✗ Admin password uses default value")
        return False

    if cred_path.exists():
        try:
            data = json.loads(cred_path.read_text())
            stored_password = data.get('password', '')
            if stored_password and stored_password != default_password:
                print("  ✓ Admin credential file present with non-default password")
                return True
        except Exception as e:
            print(f"  ✗ Error reading credential file: {e}")
            return False

    print("  ✗ No admin password configured; set PHANTOM_ADMIN_PASSWORD or create phantom_admin.json")
    return False

def check_dependencies():
    """Check Python dependencies"""
    print("\n[*] Checking dependencies...")

    missing = []

    try:
        import flask
        print(f"  ✓ Flask: {flask.__version__}")
    except ImportError:
        print("  ✗ Flask - MISSING")
        missing.append("flask")

    try:
        import requests
        print(f"  ✓ requests: {requests.__version__}")
    except ImportError:
        print("  ✗ requests - MISSING")
        missing.append("requests")

    try:
        import cryptography
        print(f"  ✓ cryptography: {cryptography.__version__}")
    except ImportError:
        print("  ✗ cryptography - MISSING")
        missing.append("cryptography")

    try:
        import psutil
        print(f"  ✓ psutil: {psutil.__version__}")
    except ImportError:
        print("  ✗ psutil - MISSING")
        missing.append("psutil")

    if missing:
        print(f"\n[-] Missing dependencies: {', '.join(missing)}")
        return False

    return True

def main():
    """Run all checks"""
    print("=" * 60)
    print("PHANTOMRAT QUICK CHECK")
    print("=" * 60)
    
    checks = [
        ("Files", check_files),
        ("Config", check_config),
        ("Credentials", check_credentials),
        ("Dependencies", check_dependencies)
    ]
    
    all_passed = True
    for name, check_func in checks:
        try:
            if check_func():
                print(f"\n[+] {name} check: PASSED")
            else:
                print(f"\n[-] {name} check: FAILED")
                all_passed = False
        except Exception as e:
            print(f"\n[!] {name} check ERROR: {e}")
            all_passed = False
    
    print("\n" + "=" * 60)
    if all_passed:
        print("[+] All checks passed! PhantomRAT is ready.")
        print("\nTo start:")
        print("  python run.py --mode both --host 127.0.0.1 --port 8000")
        print("\nAccess dashboard: http://127.0.0.1:8000")
    else:
        print("[-] Some checks failed. Please fix the issues above.")
    
    return all_passed

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
