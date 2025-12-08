import os
import base64

def list_files(path):
    try:
        return os.listdir(path)
    except:
        return []

def download_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        return base64.b64encode(data).decode()
    except:
        return None

def upload_file(file_path, data):
    try:
        decoded = base64.b64decode(data)
        with open(file_path, 'wb') as f:
            f.write(decoded)
        return True
    except:
        return False