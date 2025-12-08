import os
import ctypes
import platform

def elevate_privileges():
    if platform.system() == 'Windows':
        try:
            ctypes.windll.shell32.ShellExecuteW(None, "runas", "python", " ".join(sys.argv), None, 1)
        except:
            pass  # Already elevated or failed
    else:
        # Linux: try sudo or setuid
        os.setuid(0)  # Assume running as root