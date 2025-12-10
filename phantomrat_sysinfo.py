
import platform
import os
import sys
import psutil
import socket
import uuid
import json
import hashlib
import datetime
import time
import subprocess
import re
import logging
from typing import Dict, List, Any, Optional
import winreg  # Windows only
import getpass

logger = logging.getLogger(__name__)

class EnhancedSystemInfo:
    """
    Enhanced system information collection with detailed profiling
    """
    
    def __init__(self):
        self.system_data = {}
        self.collection_time = None
        self.cache_duration = 300  # Cache for 5 minutes
        self.cache = {}
        self.cache_timestamp = {}
        
    def get_comprehensive_info(self) -> Dict[str, Any]:
        """
        Get comprehensive system information
        """
        self.collection_time = datetime.datetime.now()
        
        self.system_data = {
            'timestamp': self.collection_time.isoformat(),
            'basic_info': self._get_basic_info(),
            'hardware_info': self._get_hardware_info(),
            'software_info': self._get_software_info(),
            'network_info': self._get_network_info(),
            'security_info': self._get_security_info(),
            'user_info': self._get_user_info(),
            'process_info': self._get_process_info(),
            'performance_info': self._get_performance_info(),
            'environment_info': self._get_environment_info(),
            'antivirus_info': self._get_antivirus_info(),
            'forensic_artifacts': self._get_forensic_artifacts(),
            'risk_assessment': self._calculate_risk_assessment()
        }
        
        # Calculate hash for data integrity
        data_str = json.dumps(self.system_data, sort_keys=True)
        self.system_data['integrity_hash'] = hashlib.sha256(data_str.encode()).hexdigest()
        
        return self.system_data
    
    def _get_basic_info(self) -> Dict[str, Any]:
        """Get basic system information"""
        return {
            'hostname': socket.gethostname(),
            'fqdn': socket.getfqdn(),
            'operating_system': platform.system(),
            'os_release': platform.release(),
            'os_version': platform.version(),
            'architecture': platform.machine(),
            'processor': platform.processor(),
            'boot_time': datetime.datetime.fromtimestamp(psutil.boot_time()).isoformat(),
            'uptime': time.time() - psutil.boot_time(),
            'timezone': time.tzname,
            'locale': locale.getlocale() if hasattr(locale, 'getlocale') else 'unknown'
        }
    
    def _get_hardware_info(self) -> Dict[str, Any]:
        """Get detailed hardware information"""
        info = {
            'cpu': self._get_cpu_info(),
            'memory': self._get_memory_info(),
            'disks': self._get_disk_info(),
            'network_interfaces': self._get_interface_info(),
            'battery': self._get_battery_info() if hasattr(psutil, 'sensors_battery') else None,
            'sensors': self._get_sensor_info(),
            'usb_devices': self._get_usb_info()
        }
        
        # GPU information (if available)
        try:
            info['gpu'] = self._get_gpu_info()
        except:
            info['gpu'] = None
        
        return info
    
    def _get_cpu_info(self) -> Dict[str, Any]:
        """Get CPU information"""
        return {
            'physical_cores': psutil.cpu_count(logical=False),
            'logical_cores': psutil.cpu_count(logical=True),
            'cpu_percent': psutil.cpu_percent(interval=1, percpu=True),
            'cpu_freq': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None,
            'cpu_stats': psutil.cpu_stats()._asdict(),
            'cpu_times': psutil.cpu_times_percent(interval=1)._asdict()
        }
    
    def _get_memory_info(self) -> Dict[str, Any]:
        """Get memory information"""
        virtual = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        return {
            'virtual': {
                'total': virtual.total,
                'available': virtual.available,
                'percent': virtual.percent,
                'used': virtual.used,
                'free': virtual.free,
                'active': getattr(virtual, 'active', None),
                'inactive': getattr(virtual, 'inactive', None),
                'buffers': getattr(virtual, 'buffers', None),
                'cached': getattr(virtual, 'cached', None),
                'shared': getattr(virtual, 'shared', None)
            },
            'swap': {
                'total': swap.total,
                'used': swap.used,
                'free': swap.free,
                'percent': swap.percent,
                'sin': swap.sin,
                'sout': swap.sout
            }
        }
    
    def _get_disk_info(self) -> List[Dict[str, Any]]:
        """Get disk information"""
        disks = []
        
        for partition in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disk_info = {
                    'device': partition.device,
                    'mountpoint': partition.mountpoint,
                    'fstype': partition.fstype,
                    'opts': partition.opts,
                    'total': usage.total,
                    'used': usage.used,
                    'free': usage.free,
                    'percent': usage.percent
                }
                
                # Get disk I/O statistics
                try:
                    disk_io = psutil.disk_io_counters(perdisk=True)
                    if partition.device in disk_io:
                        disk_info['io_stats'] = disk_io[partition.device]._asdict()
                except:
                    pass
                
                disks.append(disk_info)
            except:
                continue
        
        return disks
    
    def _get_interface_info(self) -> List[Dict[str, Any]]:
        """Get network interface information"""
        interfaces = []
        
        for name, addrs in psutil.net_if_addrs().items():
            interface_info = {
                'name': name,
                'addresses': [],
                'stats': None
            }
            
            for addr in addrs:
                interface_info['addresses'].append({
                    'family': str(addr.family),
                    'address': addr.address,
                    'netmask': addr.netmask,
                    'broadcast': addr.broadcast,
                    'ptp': addr.ptp
                })
            
            # Get interface statistics
            try:
                stats = psutil.net_if_stats()
                if name in stats:
                    interface_info['stats'] = {
                        'isup': stats[name].isup,
                        'duplex': str(stats[name].duplex),
                        'speed': stats[name].speed,
                        'mtu': stats[name].mtu
                    }
            except:
                pass
            
            interfaces.append(interface_info)
        
        return interfaces
    
    def _get_battery_info(self) -> Optional[Dict[str, Any]]:
        """Get battery information"""
        try:
            battery = psutil.sensors_battery()
            if battery:
                return {
                    'percent': battery.percent,
                    'secsleft': battery.secsleft,
                    'power_plugged': battery.power_plugged
                }
        except:
            pass
        return None
    
    def _get_sensor_info(self) -> Dict[str, Any]:
        """Get sensor information"""
        sensors = {}
        
        # Temperature sensors
        try:
            if hasattr(psutil, 'sensors_temperatures'):
                temps = psutil.sensors_temperatures()
                if temps:
                    sensors['temperatures'] = temps
        except:
            pass
        
        # Fan speeds
        try:
            if hasattr(psutil, 'sensors_fans'):
                fans = psutil.sensors_fans()
                if fans:
                    sensors['fans'] = fans
        except:
            pass
        
        return sensors
    
    def _get_usb_info(self) -> List[Dict[str, Any]]:
        """Get USB device information"""
        usb_devices = []
        
        if platform.system() == 'Windows':
            # Windows USB device detection
            try:
                import winreg as reg
                key = reg.OpenKey(reg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Enum\USB")
                
                for i in range(0, reg.QueryInfoKey(key)[0]):
                    try:
                        subkey_name = reg.EnumKey(key, i)
                        subkey = reg.OpenKey(key, subkey_name)
                        
                        device_info = {
                            'id': subkey_name,
                            'description': reg.QueryValueEx(subkey, 'DeviceDesc')[0] if reg.QueryValueEx(subkey, 'DeviceDesc') else None,
                            'class': reg.QueryValueEx(subkey, 'Class')[0] if reg.QueryValueEx(subkey, 'Class') else None,
                            'driver': reg.QueryValueEx(subkey, 'Driver')[0] if reg.QueryValueEx(subkey, 'Driver') else None
                        }
                        
                        usb_devices.append(device_info)
                        reg.CloseKey(subkey)
                    except:
                        continue
                
                reg.CloseKey(key)
            except:
                pass
        
        elif platform.system() == 'Linux':
            # Linux USB device detection
            try:
                import glob
                for usb in glob.glob('/sys/bus/usb/devices/*'):
                    try:
                        vendor = product = ''
                        
                        vendor_file = os.path.join(usb, 'idVendor')
                        product_file = os.path.join(usb, 'idProduct')
                        
                        if os.path.exists(vendor_file):
                            with open(vendor_file, 'r') as f:
                                vendor = f.read().strip()
                        
                        if os.path.exists(product_file):
                            with open(product_file, 'r') as f:
                                product = f.read().strip()
                        
                        if vendor or product:
                            usb_devices.append({
                                'path': usb,
                                'vendor': vendor,
                                'product': product,
                                'busnum': self._read_file(os.path.join(usb, 'busnum')),
                                'devnum': self._read_file(os.path.join(usb, 'devnum'))
                            })
                    except:
                        continue
            except:
                pass
        
        return usb_devices
    
    def _read_file(self, path: str) -> Optional[str]:
        """Helper to read file safely"""
        try:
            with open(path, 'r') as f:
                return f.read().strip()
        except:
            return None
    
    def _get_gpu_info(self) -> List[Dict[str, Any]]:
        """Get GPU information"""
        gpus = []
        
        if platform.system() == 'Windows':
            try:
                # Try using wmic for GPU info
                result = subprocess.run(
                    ['wmic', 'path', 'win32_videocontroller', 'get', 'name,adapterram,driverversion', '/format:list'],
                    capture_output=True, text=True, encoding='utf-8', errors='ignore'
                )
                
                lines = result.stdout.split('\n')
                current_gpu = {}
                
                for line in lines:
                    line = line.strip()
                    if line.startswith('Name='):
                        current_gpu['name'] = line.split('=', 1)[1]
                    elif line.startswith('AdapterRAM='):
                        current_gpu['memory'] = line.split('=', 1)[1]
                    elif line.startswith('DriverVersion='):
                        current_gpu['driver_version'] = line.split('=', 1)[1]
                        
                        if current_gpu:
                            gpus.append(current_gpu)
                            current_gpu = {}
                
            except:
                pass
        
        elif platform.system() == 'Linux':
            try:
                # Try lspci for GPU info
                result = subprocess.run(
                    ['lspci', '-nn', '-v'],
                    capture_output=True, text=True
                )
                
                current_gpu = {}
                in_gpu_section = False
                
                for line in result.stdout.split('\n'):
                    if 'VGA compatible controller' in line or '3D controller' in line:
                        if current_gpu:
                            gpus.append(current_gpu)
                        current_gpu = {'description': line.strip()}
                        in_gpu_section = True
                    elif in_gpu_section and line.strip().startswith('Kernel driver in use:'):
                        current_gpu['driver'] = line.split(':')[1].strip()
                    elif in_gpu_section and line.strip() == '':
                        if current_gpu:
                            gpus.append(current_gpu)
                        current_gpu = {}
                        in_gpu_section = False
                
                if current_gpu:
                    gpus.append(current_gpu)
                    
            except:
                pass
        
        return gpus
    
    def _get_software_info(self) -> Dict[str, Any]:
        """Get software information"""
        return {
            'python_version': {
                'version': platform.python_version(),
                'implementation': platform.python_implementation(),
                'compiler': platform.python_compiler(),
                'build': platform.python_build()
            },
            'installed_packages': self._get_installed_packages(),
            'running_services': self._get_running_services(),
            'scheduled_tasks': self._get_scheduled_tasks(),
            'startup_programs': self._get_startup_programs(),
            'browsers': self._get_browser_info()
        }
    
    def _get_installed_packages(self) -> List[Dict[str, str]]:
        """Get installed packages"""
        packages = []
        
        # Python packages
        try:
            import pkg_resources
            for dist in pkg_resources.working_set:
                packages.append({
                    'name': dist.key,
                    'version': dist.version,
                    'location': dist.location,
                    'type': 'python'
                })
        except:
            pass
        
        # System packages (platform specific)
        if platform.system() == 'Windows':
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
                
                for i in range(0, winreg.QueryInfoKey(key)[0]):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        subkey = winreg.OpenKey(key, subkey_name)
                        
                        name = None
                        version = None
                        
                        try:
                            name = winreg.QueryValueEx(subkey, 'DisplayName')[0]
                            version = winreg.QueryValueEx(subkey, 'DisplayVersion')[0]
                        except:
                            pass
                        
                        if name:
                            packages.append({
                                'name': name,
                                'version': version,
                                'type': 'windows'
                            })
                        
                        winreg.CloseKey(subkey)
                    except:
                        continue
                
                winreg.CloseKey(key)
            except:
                pass
        
        elif platform.system() == 'Linux':
            # Try different package managers
            package_commands = [
                ('dpkg', ['dpkg', '-l']),
                ('rpm', ['rpm', '-qa']),
                ('pacman', ['pacman', '-Q']),
                ('apk', ['apk', 'info'])
            ]
            
            for pkg_type, cmd in package_commands:
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            if line.strip():
                                packages.append({
                                    'name': line.strip(),
                                    'type': pkg_type
                                })
                        break
                except:
                    continue
        
        return packages
    
    def _get_running_services(self) -> List[Dict[str, Any]]:
        """Get running services"""
        services = []
        
        try:
            for service in psutil.win_service_iter() if platform.system() == 'Windows' else []:
                services.append({
                    'name': service.name(),
                    'display_name': service.display_name(),
                    'status': service.status(),
                    'pid': service.pid()
                })
        except:
            # Linux services
            try:
                result = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=running'],
                                      capture_output=True, text=True)
                for line in result.stdout.split('\n')[1:]:  # Skip header
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 5:
                            services.append({
                                'name': parts[0],
                                'status': parts[3],
                                'type': 'systemd'
                            })
            except:
                pass
        
        return services
    
    def _get_scheduled_tasks(self) -> List[Dict[str, Any]]:
        """Get scheduled tasks"""
        tasks = []
        
        if platform.system() == 'Windows':
            try:
                import win32com.client
                scheduler = win32com.client.Dispatch('Schedule.Service')
                scheduler.Connect()
                
                folders = [scheduler.GetFolder('\\')]
                while folders:
                    folder = folders.pop(0)
                    folders += list(folder.GetFolders(0))
                    
                    for task in folder.GetTasks(0):
                        task_info = {
                            'name': task.Name,
                            'path': task.Path,
                            'enabled': task.Enabled,
                            'state': task.State,
                            'last_run_time': str(task.LastRunTime) if task.LastRunTime else None,
                            'next_run_time': str(task.NextRunTime) if task.NextRunTime else None
                        }
                        tasks.append(task_info)
                        
            except:
                pass
        
        elif platform.system() == 'Linux':
            # Check crontab
            try:
                # User crontab
                result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if line.strip() and not line.startswith('#'):
                            tasks.append({
                                'type': 'cron',
                                'user': getpass.getuser(),
                                'schedule': line.strip(),
                                'source': 'user_crontab'
                            })
                
                # System crontab
                for cron_file in ['/etc/crontab', '/etc/cron.d/*', '/etc/cron.hourly/*',
                                 '/etc/cron.daily/*', '/etc/cron.weekly/*', '/etc/cron.monthly/*']:
                    try:
                        import glob
                        for file in glob.glob(cron_file):
                            try:
                                with open(file, 'r') as f:
                                    content = f.read()
                                    tasks.append({
                                        'type': 'cron',
                                        'file': file,
                                        'content': content[:500],  # First 500 chars
                                        'source': 'system_cron'
                                    })
                            except:
                                pass
                    except:
                        pass
                        
            except:
                pass
        
        return tasks
    
    def _get_startup_programs(self) -> List[Dict[str, Any]]:
        """Get startup programs"""
        startup_programs = []
        
        if platform.system() == 'Windows':
            # Registry startup locations
            startup_locations = [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce")
            ]
            
            for root, path in startup_locations:
                try:
                    key = winreg.OpenKey(root, path)
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            startup_programs.append({
                                'name': name,
                                'command': value,
                                'location': f"{'HKCU' if root == winreg.HKEY_CURRENT_USER else 'HKLM'}\\{path}",
                                'type': 'registry'
                            })
                            i += 1
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except:
                    pass
            
            # Startup folder
            startup_folder = os.path.join(os.environ['APPDATA'], 
                                         'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
            if os.path.exists(startup_folder):
                for item in os.listdir(startup_folder):
                    startup_programs.append({
                        'name': item,
                        'path': os.path.join(startup_folder, item),
                        'type': 'startup_folder'
                    })
        
        elif platform.system() == 'Linux':
            # Linux startup locations
            startup_locations = [
                '/etc/rc.local',
                '/etc/init.d/',
                '~/.config/autostart/',
                '~/.bashrc',
                '~/.profile',
                '/etc/profile',
                '/etc/profile.d/'
            ]
            
            for location in startup_locations:
                expanded = os.path.expanduser(location)
                if os.path.exists(expanded):
                    if os.path.isfile(expanded):
                        try:
                            with open(expanded, 'r') as f:
                                content = f.read(1000)  # First 1000 chars
                                startup_programs.append({
                                    'file': location,
                                    'content_preview': content,
                                    'type': 'startup_file'
                                })
                        except:
                            pass
                    elif os.path.isdir(expanded):
                        try:
                            for item in os.listdir(expanded):
                                startup_programs.append({
                                    'file': os.path.join(location, item),
                                    'type': 'startup_script'
                                })
                        except:
                            pass
        
        return startup_programs
    
    def _get_browser_info(self) -> Dict[str, Any]:
        """Get browser information"""
        browsers = {}
        
        # Common browser paths
        browser_paths = {
            'chrome': [
                os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Google', 'Chrome'),
                os.path.expanduser('~/.config/google-chrome'),
                '/Applications/Google Chrome.app'
            ],
            'firefox': [
                os.path.join(os.environ.get('APPDATA', ''), 'Mozilla', 'Firefox'),
                os.path.expanduser('~/.mozilla/firefox'),
                '/Applications/Firefox.app'
            ],
            'edge': [
                os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Microsoft', 'Edge'),
                os.path.expanduser('~/.config/microsoft-edge'),
                '/Applications/Microsoft Edge.app'
            ]
        }
        
        for browser_name, paths in browser_paths.items():
            for path in paths:
                if os.path.exists(path):
                    browsers[browser_name] = {
                        'installed': True,
                        'path': path,
                        'profiles': self._get_browser_profiles(path)
                    }
                    break
            else:
                browsers[browser_name] = {'installed': False}
        
        return browsers
    
    def _get_browser_profiles(self, browser_path: str) -> List[str]:
        """Get browser profiles"""
        profiles = []
        
        try:
            if 'chrome' in browser_path.lower() or 'edge' in browser_path.lower():
                # Chrome/Edge profiles
                user_data = os.path.join(browser_path, 'User Data')
                if os.path.exists(user_data):
                    for item in os.listdir(user_data):
                        if item.startswith('Profile') or item == 'Default':
                            profiles.append(item)
            
            elif 'firefox' in browser_path.lower():
                # Firefox profiles
                profiles_ini = os.path.join(browser_path, 'profiles.ini')
                if os.path.exists(profiles_ini):
                    with open(profiles_ini, 'r') as f:
                        for line in f:
                            if line.startswith('Path='):
                                profiles.append(line.split('=', 1)[1].strip())
        except:
            pass
        
        return profiles
    
    def _get_network_info(self) -> Dict[str, Any]:
        """Get network information"""
        return {
            'connections': self._get_network_connections(),
            'dns_servers': self._get_dns_servers(),
            'arp_table': self._get_arp_table(),
            'routing_table': self._get_routing_table(),
            'firewall_status': self._get_firewall_status(),
            'proxy_settings': self._get_proxy_settings()
        }
    
    def _get_network_connections(self) -> List[Dict[str, Any]]:
        """Get network connections"""
        connections = []
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                connection_info = {
                    'fd': conn.fd,
                    'family': str(conn.family),
                    'type': str(conn.type),
                    'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status,
                    'pid': conn.pid
                }
                
                # Try to get process name
                if conn.pid:
                    try:
                        process = psutil.Process(conn.pid)
                        connection_info['process_name'] = process.name()
                        connection_info['process_cmdline'] = ' '.join(process.cmdline())
                    except:
                        pass
                
                connections.append(connection_info)
        except:
            pass
        
        return connections
    
    def _get_dns_servers(self) -> List[str]:
        """Get DNS servers"""
        dns_servers = []
        
        try:
            if platform.system() == 'Windows':
                import ctypes
                import ctypes.wintypes
                
                class DNS_CACHE_ENTRY(ctypes.Structure):
                    pass
                
                DNS_CACHE_ENTRY._fields_ = [
                    ('next', ctypes.POINTER(DNS_CACHE_ENTRY)),
                    ('name', ctypes.c_wchar_p),
                    ('data', ctypes.c_void_p),
                    ('type', ctypes.c_uint),
                    ('flags', ctypes.c_uint),
                    ('ttl', ctypes.c_ulong),
                    ('timeout', ctypes.c_ulong)
                ]
                
                DnsGetCacheDataTable = ctypes.windll.dnsapi.DnsGetCacheDataTable
                DnsGetCacheDataTable.argtypes = [ctypes.POINTER(ctypes.POINTER(DNS_CACHE_ENTRY))]
                DnsGetCacheDataTable.restype = ctypes.c_ulong
                
                DnsFree = ctypes.windll.dnsapi.DnsFree
                DnsFree.argtypes = [ctypes.POINTER(DNS_CACHE_ENTRY), ctypes.c_int]
                DnsFree.restype = ctypes.c_void_p
                
                entry_ptr = ctypes.POINTER(DNS_CACHE_ENTRY)()
                result = DnsGetCacheDataTable(ctypes.byref(entry_ptr))
                
                if result == 0:  # ERROR_SUCCESS
                    entry = entry_ptr.contents
                    while entry:
                        if entry.name:
                            dns_servers.append(entry.name)
                        if entry.next:
                            entry = entry.next.contents
                        else:
                            break
                    
                    DnsFree(entry_ptr, 0)
                    
            elif platform.system() == 'Linux':
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        if line.startswith('nameserver'):
                            dns_servers.append(line.split()[1])
        except:
            pass
        
        return dns_servers
    
    def _get_arp_table(self) -> List[Dict[str, str]]:
        """Get ARP table"""
        arp_table = []
        
        try:
            if platform.system() == 'Windows':
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
                for line in result.stdout.split('\n')[3:]:  # Skip header
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 3:
                            arp_table.append({
                                'ip': parts[0],
                                'mac': parts[1],
                                'type': parts[2]
                            })
            elif platform.system() == 'Linux':
                with open('/proc/net/arp', 'r') as f:
                    lines = f.readlines()[1:]  # Skip header
                    for line in lines:
                        parts = line.split()
                        if len(parts) >= 6:
                            arp_table.append({
                                'ip': parts[0],
                                'hw_type': parts[1],
                                'flags': parts[2],
                                'mac': parts[3],
                                'mask': parts[4],
                                'device': parts[5]
                            })
        except:
            pass
        
        return arp_table
    
    def _get_routing_table(self) -> List[Dict[str, Any]]:
        """Get routing table"""
        routes = []
        
        try:
            if platform.system() == 'Windows':
                result = subprocess.run(['route', 'print'], capture_output=True, text=True)
                lines = result.stdout.split('\n')
                start_index = -1
                
                for i, line in enumerate(lines):
                    if 'Network Destination' in line and 'Netmask' in line:
                        start_index = i + 2
                        break
                
                if start_index > 0:
                    for line in lines[start_index:]:
                        if line.strip() and not line.startswith('='):
                            parts = line.split()
                            if len(parts) >= 5:
                                routes.append({
                                    'destination': parts[0],
                                    'netmask': parts[1],
                                    'gateway': parts[2],
                                    'interface': parts[3],
                                    'metric': parts[4] if len(parts) > 4 else None
                                })
            
            elif platform.system() == 'Linux':
                with open('/proc/net/route', 'r') as f:
                    lines = f.readlines()[1:]  # Skip header
                    for line in lines:
                        parts = line.split()
                        if len(parts) >= 3:
                            routes.append({
                                'interface': parts[0],
                                'destination': hex(int(parts[1], 16)),
                                'gateway': hex(int(parts[2], 16)),
                                'flags': parts[3],
                                'refcnt': parts[4],
                                'use': parts[5],
                                'metric': parts[6],
                                'mask': hex(int(parts[7], 16))
                            })
        except:
            pass
        
        return routes
    
    def _get_firewall_status(self) -> Dict[str, Any]:
        """Get firewall status"""
        status = {'enabled': False, 'profiles': {}}
        
        try:
            if platform.system() == 'Windows':
                import win32com.client
                firewall = win32com.client.Dispatch('HNetCfg.FwMgr')
                status['enabled'] = firewall.LocalPolicy.CurrentProfile.FirewallEnabled
                
                # Get profile status
                for profile_name in ['Domain', 'Private', 'Public']:
                    profile = getattr(firewall.LocalPolicy.CurrentProfile, f'{profile_name}Profile')
                    status['profiles'][profile_name.lower()] = {
                        'enabled': profile.FirewallEnabled,
                        'inbound_blocked': not profile.DefaultInboundAction,
                        'outbound_blocked': not profile.DefaultOutboundAction
                    }
            
            elif platform.system() == 'Linux':
                # Check iptables
                try:
                    result = subprocess.run(['iptables', '-L'], capture_output=True, text=True)
                    status['enabled'] = len(result.stdout.strip()) > 0
                    status['rules_count'] = len([l for l in result.stdout.split('\n') if not l.startswith('#') and l.strip()])
                except:
                    pass
                
                # Check firewalld
                try:
                    result = subprocess.run(['firewall-cmd', '--state'], capture_output=True, text=True)
                    status['firewalld'] = 'running' in result.stdout.lower()
                except:
                    pass
        except:
            pass
        
        return status
    
    def _get_proxy_settings(self) -> Dict[str, Any]:
        """Get proxy settings"""
        proxy_settings = {}
        
        try:
            if platform.system() == 'Windows':
                import winreg
                
                proxy_keys = [
                    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"),
                    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
                ]
                
                for root, path in proxy_keys:
                    try:
                        key = winreg.OpenKey(root, path)
                        
                        try:
                            proxy_enable = winreg.QueryValueEx(key, 'ProxyEnable')[0]
                            proxy_settings['enabled'] = bool(proxy_enable)
                        except:
                            pass
                        
                        try:
                            proxy_server = winreg.QueryValueEx(key, 'ProxyServer')[0]
                            proxy_settings['server'] = proxy_server
                        except:
                            pass
                        
                        try:
                            proxy_override = winreg.QueryValueEx(key, 'ProxyOverride')[0]
                            proxy_settings['override'] = proxy_override
                        except:
                            pass
                        
                        winreg.CloseKey(key)
                    except:
                        pass
                    
                    if proxy_settings:
                        break
            
            elif platform.system() == 'Linux':
                # Check environment variables
                for var in ['http_proxy', 'https_proxy', 'ftp_proxy', 'all_proxy']:
                    value = os.environ.get(var) or os.environ.get(var.upper())
                    if value:
                        proxy_settings[var] = value
                
                # Check GNOME/KDE settings
                for config_file in ['~/.config/kioslaverc', '~/.gconf/system/proxy/%gconf.xml']:
                    try:
                        with open(os.path.expanduser(config_file), 'r') as f:
                            content = f.read()
                            if 'Proxy' in content:
                                proxy_settings['desktop_config'] = config_file
                    except:
                        pass
        except:
            pass
        
        return proxy_settings
    
    def _get_security_info(self) -> Dict[str, Any]:
        """Get security information"""
        return {
            'users': self._get_users(),
            'groups': self._get_groups(),
            'privileges': self._get_privileges(),
            'audit_policies': self._get_audit_policies(),
            'logon_sessions': self._get_logon_sessions(),
            'security_products': self._get_security_products()
        }
    
    def _get_users(self) -> List[Dict[str, Any]]:
        """Get system users"""
        users = []
        
        try:
            if platform.system() == 'Windows':
                import win32net
                users_info, _, _ = win32net.NetUserEnum(None, 0)
                
                for user in users_info:
                    users.append({
                        'name': user['name'],
                        'full_name': user.get('full_name', ''),
                        'comment': user.get('comment', ''),
                        'flags': user.get('flags', 0),
                        'last_logon': user.get('last_logon', 0),
                        'bad_password_count': user.get('bad_pw_count', 0)
                    })
            
            elif platform.system() == 'Linux':
                with open('/etc/passwd', 'r') as f:
                    for line in f:
                        parts = line.strip().split(':')
                        if len(parts) >= 7:
                            users.append({
                                'name': parts[0],
                                'uid': parts[2],
                                'gid': parts[3],
                                'gecos': parts[4],
                                'home': parts[5],
                                'shell': parts[6]
                            })
        except:
            pass
        
        return users
    
    def _get_groups(self) -> List[Dict[str, Any]]:
        """Get system groups"""
        groups = []
        
        try:
            if platform.system() == 'Windows':
                import win32net
                groups_info, _, _ = win32net.NetLocalGroupEnum(None, 0)
                
                for group in groups_info:
                    groups.append({
                        'name': group['name'],
                        'comment': group.get('comment', '')
                    })
            
            elif platform.system() == 'Linux':
                with open('/etc/group', 'r') as f:
                    for line in f:
                        parts = line.strip().split(':')
                        if len(parts) >= 4:
                            groups.append({
                                'name': parts[0],
                                'password': parts[1],
                                'gid': parts[2],
                                'members': parts[3].split(',') if parts[3] else []
                            })
        except:
            pass
        
        return groups
    
    def _get_privileges(self) -> List[Dict[str, Any]]:
        """Get user privileges"""
        privileges = []
        
        try:
            if platform.system() == 'Windows':
                import win32security
                import win32process
                
                # Get current process token
                process = win32process.GetCurrentProcess()
                token = win32security.OpenProcessToken(process, win32security.TOKEN_QUERY)
                
                # Get privileges
                privs = win32security.GetTokenInformation(token, win32security.TokenPrivileges)
                
                for priv_luid, priv_attr in privs:
                    priv_name = win32security.LookupPrivilegeName(None, priv_luid)
                    privileges.append({
                        'name': priv_name,
                        'enabled': bool(priv_attr & win32security.SE_PRIVILEGE_ENABLED),
                        'attributes': priv_attr
                    })
        except:
            pass
        
        return privileges
    
    def _get_audit_policies(self) -> Dict[str, Any]:
        """Get audit policies"""
        audit_policies = {}
        
        try:
            if platform.system() == 'Windows':
                import win32security
                
                # Get audit policy
                policy = win32security.LsaQueryInformationPolicy(
                    win32security.LsaOpenPolicy(None, win32security.POLICY_VIEW_AUDIT_INFORMATION),
                    win32security.PolicyAuditEventsInformation
                )
                
                audit_policies = {
                    'auditing_enabled': policy['AuditingMode'] != 0,
                    'audit_events': policy['EventAuditingOptions']
                }
        except:
            pass
        
        return audit_policies
    
    def _get_logon_sessions(self) -> List[Dict[str, Any]]:
        """Get logon sessions"""
        sessions = []
        
        try:
            if platform.system() == 'Windows':
                import win32security
                
                # Get logon sessions
                sessions_list = win32security.LsaEnumerateLogonSessions()
                
                for session in sessions_list:
                    try:
                        session_data = win32security.LsaGetLogonSessionData(session)
                        
                        sessions.append({
                            'username': session_data['UserName'],
                            'logon_domain': session_data['LogonDomain'],
                            'authentication_package': session_data['AuthenticationPackage'],
                            'logon_type': session_data['LogonType'],
                            'session': session_data['Session'],
                            'logon_time': str(session_data['LogonTime']),
                            'logon_server': session_data['LogonServer'],
                            'dns_domain_name': session_data['DnsDomainName']
                        })
                    except:
                        continue
        except:
            pass
        
        return sessions
    
    def _get_security_products(self) -> List[Dict[str, Any]]:
        """Get security products (antivirus, firewall, etc.)"""
        products = []
        
        try:
            if platform.system() == 'Windows':
                # WMI query for security products
                import wmi
                
                c = wmi.WMI()
                
                # Antivirus products
                for av in c.Win32_Product(Description="%antivirus%") or []:
                    products.append({
                        'type': 'antivirus',
                        'name': av.Name,
                        'version': av.Version,
                        'vendor': av.Vendor,
                        'install_date': av.InstallDate
                    })
                
                # Firewall products
                for fw in c.Win32_Product(Description="%firewall%") or []:
                    products.append({
                        'type': 'firewall',
                        'name': fw.Name,
                        'version': fw.Version,
                        'vendor': fw.Vendor
                    })
        except:
            pass
        
        return products
    
    def _get_user_info(self) -> Dict[str, Any]:
        """Get current user information"""
        user_info = {
            'username': getpass.getuser(),
            'home_directory': os.path.expanduser('~'),
            'user_id': os.getuid() if hasattr(os, 'getuid') else None,
            'group_id': os.getgid() if hasattr(os, 'getgid') else None,
            'effective_user_id': os.geteuid() if hasattr(os, 'geteuid') else None,
            'effective_group_id': os.getegid() if hasattr(os, 'getegid') else None,
            'environment_variables': dict(os.environ),
            'recent_files': self._get_recent_files(),
            'clipboard_history': self._get_clipboard_history()
        }
        
        # Get user privileges
        try:
            if platform.system() == 'Windows':
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                user_info['is_administrator'] = is_admin
            else:
                user_info['is_administrator'] = os.geteuid() == 0
        except:
            user_info['is_administrator'] = False
        
        return user_info
    
    def _get_recent_files(self) -> List[str]:
        """Get recent files"""
        recent_files = []
        
        try:
            if platform.system() == 'Windows':
                recent_path = os.path.join(os.environ['APPDATA'], 'Microsoft', 'Windows', 'Recent')
                if os.path.exists(recent_path):
                    for item in os.listdir(recent_path)[:50]:  # Limit to 50
                        recent_files.append(item)
        except:
            pass
        
        return recent_files
    
    def _get_clipboard_history(self) -> List[str]:
        """Get clipboard history (limited)"""
        clipboard = []
        
        try:
            import pyperclip
            content = pyperclip.paste()
            if content and len(content) < 1000:  # Limit size
                clipboard.append(content[:500])  # First 500 chars
        except:
            pass
        
        return clipboard
    
    def _get_process_info(self) -> Dict[str, Any]:
        """Get process information"""
        processes = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 
                                           'memory_percent', 'create_time', 'status',
                                           'cmdline', 'exe', 'cwd', 'connections',
                                           'open_files', 'threads', 'nice', 'ionice']):
                try:
                    proc_info = proc.info
                    
                    # Add additional information
                    with proc.oneshot():
                        proc_info['cpu_times'] = proc.cpu_times()._asdict()
                        proc_info['memory_info'] = proc.memory_info()._asdict()
                        proc_info['io_counters'] = proc.io_counters()._asdict() if proc.io_counters() else None
                        proc_info['num_threads'] = proc.num_threads()
                        proc_info['num_handles'] = proc.num_handles() if hasattr(proc, 'num_handles') else None
                    
                    processes.append(proc_info)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                
                # Limit to 100 processes for performance
                if len(processes) >= 100:
                    break
        except:
            pass
        
        # Sort by memory usage
        processes.sort(key=lambda x: x.get('memory_percent', 0), reverse=True)
        
        return {
            'total_processes': len(processes),
            'processes': processes[:50]  # Return top 50 by memory
        }
    
    def _get_performance_info(self) -> Dict[str, Any]:
        """Get performance information"""
        return {
            'cpu_percent': psutil.cpu_percent(interval=1, percpu=True),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_io': psutil.disk_io_counters()._asdict() if psutil.disk_io_counters() else None,
            'network_io': psutil.net_io_counters()._asdict() if psutil.net_io_counters() else None,
            'load_average': os.getloadavg() if hasattr(os, 'getloadavg') else None,
            'swap_percent': psutil.swap_memory().percent
        }
    
    def _get_environment_info(self) -> Dict[str, Any]:
        """Get environment information"""
        return {
            'python_path': sys.path,
            'working_directory': os.getcwd(),
            'temp_directory': os.environ.get('TEMP') or os.environ.get('TMP') or '/tmp',
            'system_path': os.environ.get('PATH', '').split(os.pathsep),
            'processor_architecture': platform.architecture()[0],
            'machine': platform.machine(),
            'node': platform.node(),
            'platform': platform.platform()
        }
       
   def _get_antivirus_info(self) -> Dict[str, Any]:
        """Get antivirus information"""
        av_info = {'detected': [], 'products': []}
        
        # Common antivirus process names
        av_processes = [
            ('avast', 'Avast'), ('avg', 'AVG'), ('avguard', 'Avira'),
            ('bdagent', 'Bitdefender'), ('kav', 'Kaspersky'),
            ('mcafee', 'McAfee'), ('msmpeng', 'Windows Defender'),
            ('norton', 'Norton'), ('symantec', 'Symantec'),
            ('trend micro', 'Trend Micro'), ('eset', 'ESET'),
            ('malwarebytes', 'Malwarebytes'), ('crowdstrike', 'CrowdStrike'),
            ('carbon black', 'Carbon Black'), ('sentinelone', 'SentinelOne')
        ]
        
        try:
            # Check running processes
            for proc in psutil.process_iter(['name']):
                proc_name = proc.info['name'].lower()
                for av_keyword, av_name in av_processes:
                    if av_keyword in proc_name:
                        av_info['detected'].append({
                            'name': av_name,
                            'process': proc_name,
                            'pid': proc.pid
                        })
                        break
            
            # Windows-specific AV detection
            if platform.system() == 'Windows':
                # Check Windows Security Center
                try:
                    import win32com.client
                    wmi = win32com.client.GetObject("winmgmts:")
                    
                    # Antivirus products
                    for item in wmi.InstancesOf("AntiVirusProduct"):
                        av_info['products'].append({
                            'name': item.displayName,
                            'state': item.productState,
                            'timestamp': item.timestamp
                        })
                    
                    # Firewall products
                    for item in wmi.InstancesOf("FirewallProduct"):
                        av_info['products'].append({
                            'name': item.displayName,
                            'state': item.productState,
                            'type': 'firewall'
                        })
                except:
                    pass
                
                # Check registry for antivirus
                try:
                    import winreg
                    av_keys = [
                        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
                    ]
                    
                    for root, base_path in av_keys:
                        try:
                            key = winreg.OpenKey(root, base_path)
                            for i in range(winreg.QueryInfoKey(key)[0]):
                                try:
                                    subkey_name = winreg.EnumKey(key, i)
                                    subkey = winreg.OpenKey(key, subkey_name)
                                    
                                    try:
                                        display_name = winreg.QueryValueEx(subkey, 'DisplayName')[0]
                                        publisher = winreg.QueryValueEx(subkey, 'Publisher')[0] if winreg.QueryValueEx(subkey, 'Publisher') else ''
                                        
                                        # Check if it's an antivirus
                                        av_keywords = ['antivirus', 'security', 'defender', 'protection', 
                                                      'avast', 'avg', 'kaspersky', 'mcafee', 'norton']
                                        
                                        if any(keyword in display_name.lower() for keyword in av_keywords):
                                            av_info['products'].append({
                                                'name': display_name,
                                                'publisher': publisher,
                                                'install_location': winreg.QueryValueEx(subkey, 'InstallLocation')[0] if winreg.QueryValueEx(subkey, 'InstallLocation') else '',
                                                'source': 'registry'
                                            })
                                    except:
                                        pass
                                    
                                    winreg.CloseKey(subkey)
                                except:
                                    continue
                            
                            winreg.CloseKey(key)
                        except:
                            continue
                except:
                    pass
            
            # Linux-specific AV detection
            elif platform.system() == 'Linux':
                # Check for ClamAV
                try:
                    result = subprocess.run(['clamscan', '--version'], capture_output=True, text=True)
                    if result.returncode == 0:
                        av_info['detected'].append({
                            'name': 'ClamAV',
                            'version': result.stdout.strip(),
                            'type': 'antivirus'
                        })
                except:
                    pass
                
                # Check for rkhunter/chkrootkit
                for tool in ['rkhunter', 'chkrootkit']:
                    try:
                        result = subprocess.run(['which', tool], capture_output=True, text=True)
                        if result.returncode == 0:
                            av_info['detected'].append({
                                'name': tool.capitalize(),
                                'path': result.stdout.strip(),
                                'type': 'rootkit_scanner'
                            })
                    except:
                        pass
        
        except Exception as e:
            logger.error(f"Error detecting antivirus: {e}")
        
        return av_info
    
    def _get_forensic_artifacts(self) -> Dict[str, Any]:
        """Collect forensic artifacts"""
        artifacts = {
            'system_logs': [],
            'application_logs': [],
            'browser_history': [],
            'recent_documents': [],
            'prefetch_files': [],
            'event_logs': [],
            'bash_history': []
        }
        
        try:
            if platform.system() == 'Windows':
                # Windows Event Logs
                try:
                    artifacts['event_logs'] = self._get_windows_event_logs()
                except:
                    pass
                
                # Prefetch files
                prefetch_path = r'C:\Windows\Prefetch'
                if os.path.exists(prefetch_path):
                    artifacts['prefetch_files'] = os.listdir(prefetch_path)[:20]  # First 20
                
                # Recent documents
                recent_path = os.path.join(os.environ['USERPROFILE'], 'Recent')
                if os.path.exists(recent_path):
                    artifacts['recent_documents'] = os.listdir(recent_path)[:50]
                
                # Browser history (simplified)
                artifacts['browser_history'] = self._get_browser_history()
                
                # Application logs
                appdata_path = os.path.join(os.environ['APPDATA'], '..', 'Local')
                for root, dirs, files in os.walk(appdata_path):
                    for file in files:
                        if file.endswith('.log'):
                            artifacts['application_logs'].append(os.path.join(root, file))
                            if len(artifacts['application_logs']) >= 50:
                                break
                    if len(artifacts['application_logs']) >= 50:
                        break
            
            elif platform.system() == 'Linux':
                # System logs
                log_files = ['/var/log/syslog', '/var/log/auth.log', 
                           '/var/log/kern.log', '/var/log/dmesg']
                for log_file in log_files:
                    if os.path.exists(log_file):
                        artifacts['system_logs'].append(log_file)
                
                # Bash history
                bash_history = os.path.expanduser('~/.bash_history')
                if os.path.exists(bash_history):
                    try:
                        with open(bash_history, 'r') as f:
                            artifacts['bash_history'] = f.readlines()[-100:]  # Last 100 commands
                    except:
                        pass
                
                # Browser history for current user
                artifacts['browser_history'] = self._get_browser_history()
        
        except Exception as e:
            logger.error(f"Error collecting forensic artifacts: {e}")
        
        return artifacts
    
    def _get_windows_event_logs(self) -> List[Dict[str, Any]]:
        """Get Windows event logs"""
        event_logs = []
        
        try:
            import win32evtlog
            
            # Common event logs to check
            log_types = ['Application', 'System', 'Security', 'Setup']
            
            for log_type in log_types:
                try:
                    hand = win32evtlog.OpenEventLog(None, log_type)
                    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    
                    log_events = []
                    for event in events[:10]:  # First 10 events
                        log_events.append({
                            'time_generated': str(event.TimeGenerated),
                            'source_name': event.SourceName,
                            'event_id': event.EventID,
                            'event_type': event.EventType,
                            'message': event.StringInserts[:200] if event.StringInserts else ''
                        })
                    
                    event_logs.append({
                        'log_type': log_type,
                        'events': log_events
                    })
                    
                    win32evtlog.CloseEventLog(hand)
                except:
                    continue
        
        except:
            pass
        
        return event_logs
    
    def _get_browser_history(self) -> List[Dict[str, Any]]:
        """Get browser history (simplified)"""
        history = []
        
        try:
            # Chrome history
            chrome_paths = [
                os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Google', 'Chrome', 'User Data', 'Default', 'History'),
                os.path.expanduser('~/.config/google-chrome/Default/History')
            ]
            
            for chrome_path in chrome_paths:
                if os.path.exists(chrome_path):
                    try:
                        import sqlite3
                        import shutil
                        
                        # Copy the database to avoid locking issues
                        temp_db = chrome_path + '_temp'
                        shutil.copy2(chrome_path, temp_db)
                        
                        conn = sqlite3.connect(temp_db)
                        cursor = conn.cursor()
                        
                        # Get recent history
                        cursor.execute("""
                            SELECT url, title, last_visit_time 
                            FROM urls 
                            ORDER BY last_visit_time DESC 
                            LIMIT 50
                        """)
                        
                        for row in cursor.fetchall():
                            history.append({
                                'browser': 'Chrome',
                                'url': row[0],
                                'title': row[1],
                                'last_visit': row[2]
                            })
                        
                        conn.close()
                        os.remove(temp_db)
                        
                    except:
                        pass
        
        except:
            pass
        
        return history
    
    def _calculate_risk_assessment(self) -> Dict[str, Any]:
        """Calculate risk assessment score"""
        risk_score = 0
        risk_factors = []
        
        try:
            # Check for antivirus
            av_info = self._get_antivirus_info()
            if not av_info['detected'] and not av_info['products']:
                risk_score += 20
                risk_factors.append('No antivirus detected')
            
            # Check firewall status
            firewall = self._get_firewall_status()
            if not firewall.get('enabled', False):
                risk_score += 15
                risk_factors.append('Firewall disabled')
            
            # Check if running as admin/root
            user_info = self._get_user_info()
            if user_info.get('is_administrator', False):
                risk_score += 25
                risk_factors.append('Running with administrative privileges')
            
            # Check for security processes
            security_processes = ['wireshark', 'procmon', 'processhacker', 'autoruns']
            for proc in psutil.process_iter(['name']):
                proc_name = proc.info['name'].lower()
                if any(sec_proc in proc_name for sec_proc in security_processes):
                    risk_score += 30
                    risk_factors.append(f'Security tool running: {proc_name}')
                    break
            
            # Check for debuggers
            if hasattr(sys, 'gettrace') and sys.gettrace() is not None:
                risk_score += 40
                risk_factors.append('Debugger detected')
            
            # Check for virtualization/sandbox
            if self._is_virtual_machine():
                risk_score += 10
                risk_factors.append('Running in virtual environment')
            
            # Calculate final risk level
            risk_level = 'LOW'
            if risk_score >= 70:
                risk_level = 'CRITICAL'
            elif risk_score >= 50:
                risk_level = 'HIGH'
            elif risk_score >= 30:
                risk_level = 'MEDIUM'
        
        except Exception as e:
            logger.error(f"Error calculating risk assessment: {e}")
            risk_level = 'UNKNOWN'
        
        return {
            'score': risk_score,
            'level': risk_level,
            'factors': risk_factors,
            'timestamp': datetime.datetime.now().isoformat()
        }
    
    def _is_virtual_machine(self) -> bool:
        """Check if running in virtual machine"""
        try:
            if platform.system() == 'Windows':
                # Check for common VM indicators in registry
                import winreg
                vm_indicators = [
                    (winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System", "SystemBiosVersion"),
                    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Disk\Enum", "0")
                ]
                
                for root, path, value_name in vm_indicators:
                    try:
                        key = winreg.OpenKey(root, path)
                        value, _ = winreg.QueryValueEx(key, value_name)
                        winreg.CloseKey(key)
                        
                        vm_strings = ['virtual', 'vmware', 'vbox', 'qemu', 'xen', 'kvm']
                        if any(vm_str in str(value).lower() for vm_str in vm_strings):
                            return True
                    except:
                        continue
                
                # Check WMI
                try:
                    import wmi
                    c = wmi.WMI()
                    
                    # Check BIOS
                    for bios in c.Win32_BIOS():
                        if any(vm_str in bios.Manufacturer.lower() for vm_str in vm_strings):
                            return True
                    
                    # Check computer system
                    for cs in c.Win32_ComputerSystem():
                        if cs.Model and any(vm_str in cs.Model.lower() for vm_str in vm_strings):
                            return True
                except:
                    pass
            
            elif platform.system() == 'Linux':
                # Check /sys/class/dmi/id
                dmi_files = ['product_name', 'sys_vendor', 'bios_vendor']
                for dmi_file in dmi_files:
                    try:
                        with open(f'/sys/class/dmi/id/{dmi_file}', 'r') as f:
                            content = f.read().lower()
                            vm_strings = ['virtual', 'vmware', 'virtualbox', 'qemu', 'kvm', 'xen']
                            if any(vm_str in content for vm_str in vm_strings):
                                return True
                    except:
                        pass
                
                # Check for hypervisor CPU flags
                try:
                    with open('/proc/cpuinfo', 'r') as f:
                        cpuinfo = f.read()
                        if 'hypervisor' in cpuinfo.lower():
                            return True
                except:
                    pass
            
            # Check for common VM processes
            vm_processes = ['vboxservice', 'vmware-tools', 'vmtoolsd', 'xen']
            for proc in psutil.process_iter(['name']):
                if any(vm_proc in proc.info['name'].lower() for vm_proc in vm_processes):
                    return True
        
        except:
            pass
        
        return False
    
    def export_to_file(self, filename: str = None) -> str:
        """Export system info to file"""
        if filename is None:
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'system_info_{timestamp}.json'
        
        data = self.get_comprehensive_info()
        
        try:
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            
            logger.info(f"System info exported to {filename}")
            return filename
        
        except Exception as e:
            logger.error(f"Error exporting to file: {e}")
            return None
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of system information"""
        data = self.get_comprehensive_info()
        
        summary = {
            'hostname': data['basic_info']['hostname'],
            'os': f"{data['basic_info']['operating_system']} {data['basic_info']['os_version']}",
            'architecture': data['basic_info']['architecture'],
            'cpu_cores': data['hardware_info']['cpu']['logical_cores'],
            'memory_gb': round(data['hardware_info']['memory']['virtual']['total'] / (1024**3), 2),
            'disk_count': len(data['hardware_info']['disks']),
            'user': data['user_info']['username'],
            'is_admin': data['user_info'].get('is_administrator', False),
            'antivirus_count': len(data['antivirus_info']['detected']) + len(data['antivirus_info']['products']),
            'process_count': data['process_info']['total_processes'],
            'network_connections': len(data['network_info']['connections']),
            'risk_level': data['risk_assessment']['level'],
            'risk_score': data['risk_assessment']['score'],
            'timestamp': data['timestamp']
        }
        
        return summary

# Global instance
_system_info = None

def get_system_info():
    """Get comprehensive system information"""
    global _system_info
    if _system_info is None:
        _system_info = EnhancedSystemInfo()
    
    return _system_info.get_comprehensive_info()

def get_system_summary():
    """Get system summary"""
    info = get_system_info()
    sys_info = EnhancedSystemInfo()
    return sys_info.get_summary()

if __name__ == "__main__":
    # Test system info collection
    print("Testing Enhanced System Information Collection...")
    
    sys_info = EnhancedSystemInfo()
    
    # Get summary
    summary = sys_info.get_summary()
    print(f"\nSystem Summary:")
    print(f"  Hostname: {summary['hostname']}")
    print(f"  OS: {summary['os']}")
    print(f"  CPU Cores: {summary['cpu_cores']}")
    print(f"  Memory: {summary['memory_gb']} GB")
    print(f"  User: {summary['user']} (Admin: {summary['is_admin']})")
    print(f"  Antivirus: {summary['antivirus_count']} detected")
    print(f"  Risk Level: {summary['risk_level']} ({summary['risk_score']} pts)")
    
    # Export to file
    filename = sys_info.export_to_file()
    if filename:
        print(f"\nDetailed info exported to: {filename}")
    
    print("\nCollection complete!")

