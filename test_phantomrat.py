#!/usr/bin/env python3
"""
Quick test script for PhantomRAT
"""

import sys
import os
import json

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
        
        return True
    except Exception as e:
        print(f"  ✗ Error reading config: {e}")
        return False

def check_dependencies():
    """Check Python dependencies"""
    print("\n[*] Checking dependencies...")
    
    try:
        import flask
        print(f"  ✓ Flask: {flask.__version__}")
    except ImportError:
        print("  ✗ Flask - MISSING")
    
    try:
        import requests
        print(f"  ✓ requests: {requests.__version__}")
    except ImportError:
        print("  ✗ requests - MISSING")
    
    try:
        import cryptography
        print(f"  ✓ cryptography: {cryptography.__version__}")
    except ImportError:
        print("  ✗ cryptography - MISSING")
    
    try:
        import psutil
        print(f"  ✓ psutil: {psutil.__version__}")
    except ImportError:
        print("  ✗ psutil - MISSING")
    
    return True

def main():
    """Run all checks"""
    print("=" * 60)
    print("PHANTOMRAT QUICK CHECK")
    print("=" * 60)
    
    checks = [
        ("Files", check_files),
        ("Config", check_config),
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
