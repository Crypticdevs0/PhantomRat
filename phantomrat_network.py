
import socket
import ipaddress
import threading
import time
import concurrent.futures
import json
import os
import struct
import ssl
import dns.resolver
import subprocess
import random
from queue import Queue
from datetime import datetime
import logging
import scapy.all as scapy
from scapy.layers import http, dns, dhcp, tftp, smb, ftp, smtp, irc
import nmap
import paramiko
import telnetlib
import ftplib
import smtplib
import requests
import ssl as ssl_module
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class AdvancedNetworkScanner:
    """
    Advanced network reconnaissance with protocol analysis and vulnerability detection
    """
    
    def __init__(self, max_threads=100, timeout=2):
        self.max_threads = max_threads
        self.timeout = timeout
        self.results = {}
        self.open_ports = {}
        self.vulnerabilities = []
        self.services = {}
        self.banner_grabs = {}
        
        # Service detection patterns
        self.service_patterns = {
            21: ('ftp', self._check_ftp),
            22: ('ssh', self._check_ssh),
            23: ('telnet', self._check_telnet),
            25: ('smtp', self._check_smtp),
            53: ('dns', self._check_dns),
            80: ('http', self._check_http),
            443: ('https', self._check_https),
            445: ('smb', self._check_smb),
            1433: ('mssql', self._check_mssql),
            3306: ('mysql', self._check_mysql),
            3389: ('rdp', self._check_rdp),
            5432: ('postgresql', self._check_postgresql),
            5900: ('vnc', self._check_vnc),
            6379: ('redis', self._check_redis),
            27017: ('mongodb', self._check_mongodb)
        }
        
        # Known vulnerabilities and exploits
        self.vuln_signatures = {
            'ftp': {
                'anonymous_login': 'Anonymous FTP login allowed',
                'vsftpd_backdoor': 'VSFTPD v2.3.4 backdoor detected'
            },
            'ssh': {
                'weak_ciphers': 'Weak SSH ciphers enabled',
                'password_auth': 'Password authentication enabled'
            },
            'http': {
                'directory_listing': 'Directory listing enabled',
                'server_info': 'Server version information leaked'
            },
            'smb': {
                'eternalblue': 'SMBv1 vulnerability (MS17-010)',
                'null_session': 'Null session allowed'
            }
        }
        
        # Initialize Nmap scanner
        try:
            self.nm = nmap.PortScanner()
        except:
            self.nm = None
            logger.warning("Nmap not available, using basic scanning")
    
    def comprehensive_scan(self, target, scan_type='full'):
        """
        Perform comprehensive network scan
        Types: quick, full, stealth, aggressive
        """
        results = {
            'target': target,
            'start_time': datetime.now().isoformat(),
            'scan_type': scan_type,
            'hosts': {}
        }
        
        try:
            # Determine if target is single IP or network
            if '/' in target:
                # Network scan
                hosts = self._enumerate_hosts(target)
                results['network'] = target
                results['total_hosts'] = len(hosts)
                
                # Scan each host
                with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                    future_to_host = {
                        executor.submit(self._scan_host, host, scan_type): host 
                        for host in hosts[:50]  # Limit to 50 hosts for performance
                    }
                    
                    for future in concurrent.futures.as_completed(future_to_host):
                        host = future_to_host[future]
                        try:
                            host_result = future.result(timeout=30)
                            if host_result:
                                results['hosts'][host] = host_result
                        except Exception as e:
                            logger.error(f"Scan error for {host}: {e}")
            else:
                # Single host scan
                host_result = self._scan_host(target, scan_type)
                if host_result:
                    results['hosts'][target] = host_result
            
            # Perform additional reconnaissance
            if scan_type in ['full', 'aggressive']:
                self._perform_additional_recon(target, results)
            
            results['end_time'] = datetime.now().isoformat()
            results['duration'] = (datetime.fromisoformat(results['end_time']) - 
                                  datetime.fromisoformat(results['start_time'])).total_seconds()
            
            # Generate report
            report = self._generate_report(results)
            
            return report
            
        except Exception as e:
            logger.error(f"Comprehensive scan failed: {e}")
            return None
    
    def _enumerate_hosts(self, network):
        """Enumerate all hosts in network"""
        hosts = []
        try:
            net = ipaddress.ip_network(network, strict=False)
            for ip in net.hosts():
                hosts.append(str(ip))
        except:
            pass
        return hosts
    
    def _scan_host(self, host, scan_type):
        """Scan single host"""
        host_result = {
            'host': host,
            'alive': False,
            'ports': [],
            'os_guess': None,
            'vulnerabilities': [],
            'services': {}
        }
        
        try:
            # Ping check
            if self._ping_host(host):
                host_result['alive'] = True
                
                # Port scanning
                if scan_type == 'quick':
                    ports = self._quick_scan(host)
                elif scan_type == 'stealth':
                    ports = self._stealth_scan(host)
                elif scan_type == 'aggressive':
                    ports = self._aggressive_scan(host)
                else:  # full
                    ports = self._full_scan(host)
                
                host_result['ports'] = ports
                
                # Service detection
                for port_info in ports:
                    port = port_info['port']
                    if port_info['state'] == 'open':
                        service_info = self._detect_service(host, port)
                        if service_info:
                            host_result['services'][port] = service_info
                            
                            # Vulnerability checking
                            vulns = self._check_vulnerabilities(host, port, service_info)
                            if vulns:
                                host_result['vulnerabilities'].extend(vulns)
                
                # OS fingerprinting
                if scan_type in ['full', 'aggressive']:
                    os_guess = self._os_fingerprint(host)
                    host_result['os_guess'] = os_guess
            
            return host_result
            
        except Exception as e:
            logger.error(f"Host scan failed for {host}: {e}")
            return host_result
    
    def _ping_host(self, host):
        """Check if host is alive"""
        try:
            # ICMP ping
            if os.name == 'nt':  # Windows
                param = '-n'
            else:  # Linux/Mac
                param = '-c'
            
            result = subprocess.run(['ping', param, '1', '-W', '1', host], 
                                  capture_output=True, text=True)
            return result.returncode == 0
            
        except:
            # TCP ping fallback
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, 80))
                sock.close()
                return result == 0
            except:
                return False
    
    def _quick_scan(self, host):
        """Quick scan of common ports"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 
                       445, 993, 995, 1433, 3306, 3389, 5900, 8080]
        return self._scan_ports(host, common_ports)
    
    def _stealth_scan(self, host):
        """Stealth scan using SYN packets"""
        open_ports = []
        
        try:
            # Use scapy for SYN scan
            ports = list(range(1, 1025))  # First 1024 ports
            
            for port in ports[:100]:  # Limit for performance
                try:
                    packet = scapy.IP(dst=host)/scapy.TCP(dport=port, flags='S')
                    response = scapy.sr1(packet, timeout=0.5, verbose=0)
                    
                    if response and response.haslayer(scapy.TCP):
                        if response.getlayer(scapy.TCP).flags == 0x12:  # SYN-ACK
                            open_ports.append({
                                'port': port,
                                'state': 'open',
                                'method': 'syn_scan'
                            })
                            
                            # Send RST to close connection
                            scapy.send(scapy.IP(dst=host)/scapy.TCP(dport=port, flags='R'), verbose=0)
                    
                except:
                    continue
            
        except Exception as e:
            logger.error(f"Stealth scan failed: {e}")
            # Fallback to connect scan
            open_ports = self._scan_ports(host, list(range(1, 1025))[:100])
        
        return open_ports
    
    def _aggressive_scan(self, host):
        """Aggressive scan with service version detection"""
        open_ports = []
        
        if self.nm:
            try:
                self.nm.scan(host, arguments='-sV -O -T4')
                if host in self.nm.all_hosts():
                    for proto in self.nm[host].all_protocols():
                        ports = self.nm[host][proto].keys()
                        for port in ports:
                            port_info = self.nm[host][proto][port]
                            open_ports.append({
                                'port': port,
                                'state': port_info['state'],
                                'service': port_info.get('name', 'unknown'),
                                'version': port_info.get('version', ''),
                                'method': 'nmap_aggressive'
                            })
            except:
                pass
        
        # Fallback to full scan if nmap fails
        if not open_ports:
            open_ports = self._full_scan(host)
        
        return open_ports
    
    def _full_scan(self, host):
        """Full port scan (1-65535)"""
        open_ports = []
        
        # Scan in chunks for performance
        port_ranges = [
            (1, 1024),      # Well-known ports
            (1025, 10000),  # Registered ports
            (10001, 20000), # Common dynamic ports
            (20001, 30000), # Additional ports
            (30001, 40000), # More ports
            (40001, 50000), # Even more ports
            (50001, 65535)  # Remaining ports
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_range = {}
            
            for start, end in port_ranges:
                ports = list(range(start, end + 1))
                future = executor.submit(self._scan_ports, host, ports[:1000])  # Limit per range
                future_to_range[future] = (start, end)
            
            for future in concurrent.futures.as_completed(future_to_range):
                try:
                    result = future.result(timeout=30)
                    open_ports.extend(result)
                except Exception as e:
                    start, end = future_to_range[future]
                    logger.error(f"Port range {start}-{end} scan failed: {e}")
        
        return open_ports
    
    def _scan_ports(self, host, ports):
        """Basic TCP connect scan"""
        open_ports = []
        
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((host, port))
                sock.close()
                
                if result == 0:
                    return {
                        'port': port,
                        'state': 'open',
                        'method': 'tcp_connect'
                    }
            except:
                pass
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_port = {executor.submit(check_port, port): port for port in ports}
            
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    if result:
                        open_ports.append(result)
                except Exception as e:
                    logger.debug(f"Port {port} check failed: {e}")
        
        return open_ports
    
    def _detect_service(self, host, port):
        """Detect service running on port"""
        service_info = {
            'port': port,
            'service': 'unknown',
            'banner': '',
            'version': '',
            'vulnerable': False
        }
        
        try:
            # Check if we have a specific detection function
            if port in self.service_patterns:
                service_name, detection_func = self.service_patterns[port]
                result = detection_func(host, port)
                if result:
                    service_info.update(result)
                    service_info['service'] = service_name
            else:
                # Generic banner grab
                banner = self._grab_banner(host, port)
                if banner:
                    service_info['banner'] = banner
                    service_info['service'] = self._guess_service_from_banner(banner)
            
            return service_info
            
        except Exception as e:
            logger.error(f"Service detection failed for {host}:{port}: {e}")
            return service_info
    
    def _grab_banner(self, host, port, timeout=3):
        """Grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            # Try to receive initial banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            # Send probe for some protocols
            if port == 80 or port == 443:
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                banner += sock.recv(2048).decode('utf-8', errors='ignore').strip()
            elif port == 21:  # FTP
                sock.send(b'USER anonymous\r\n')
                banner += sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            sock.close()
            return banner
            
        except:
            return ""
    
    def _guess_service_from_banner(self, banner):
        """Guess service from banner string"""
        banner_lower = banner.lower()
        
        if 'ssh' in banner_lower:
            return 'ssh'
        elif 'ftp' in banner_lower:
            return 'ftp'
        elif 'smtp' in banner_lower:
            return 'smtp'
        elif 'http' in banner_lower:
            return 'http'
        elif 'microsoft' in banner_lower and 'iis' in banner_lower:
            return 'iis'
        elif 'apache' in banner_lower:
            return 'apache'
        elif 'nginx' in banner_lower:
            return 'nginx'
        else:
            return 'unknown'
    
    def _check_ftp(self, host, port):
        """Check FTP service"""
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=5)
            banner = ftp.getwelcome()
            
            # Try anonymous login
            try:
                ftp.login('anonymous', 'anonymous@example.com')
                anonymous_allowed = True
                ftp.quit()
            except:
                anonymous_allowed = False
            
            return {
                'banner': banner,
                'anonymous_allowed': anonymous_allowed
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _check_ssh(self, host, port):
        """Check SSH service"""
        try:
            sock = socket.create_connection((host, port), timeout=5)
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            # Extract version
            version = ''
            if 'SSH' in banner:
                version = banner.split('-')[1] if len(banner.split('-')) > 1 else ''
            
            return {
                'banner': banner,
                'version': version
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _check_http(self, host, port):
        """Check HTTP service"""
        try:
            url = f'http://{host}:{port}'
            response = requests.get(url, timeout=5, verify=False, 
                                  headers={'User-Agent': 'Mozilla/5.0'})
            
            server = response.headers.get('Server', '')
            powered_by = response.headers.get('X-Powered-By', '')
            
            # Check for directory listing
            is_directory_listing = 'Index of /' in response.text
            
            return {
                'server': server,
                'powered_by': powered_by,
                'status_code': response.status_code,
                'directory_listing': is_directory_listing,
                'headers': dict(response.headers)
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _check_https(self, host, port):
        """Check HTTPS service"""
        try:
            url = f'https://{host}:{port}'
            response = requests.get(url, timeout=5, verify=False,
                                  headers={'User-Agent': 'Mozilla/5.0'})
            
            server = response.headers.get('Server', '')
            powered_by = response.headers.get('X-Powered-By', '')
            
            # Check SSL certificate
            cert_info = {}
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                
                with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                    s.connect((host, port))
                    cert = s.getpeercert()
                    
                    if cert:
                        cert_info = {
                            'issuer': dict(x[0] for x in cert.get('issuer', [])),
                            'subject': dict(x[0] for x in cert.get('subject', [])),
                            'expires': cert.get('notAfter', ''),
                            'version': cert.get('version', '')
                        }
            except:
                pass
            
            return {
                'server': server,
                'powered_by': powered_by,
                'status_code': response.status_code,
                'certificate': cert_info,
                'headers': dict(response.headers)
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _check_smb(self, host, port):
        """Check SMB service"""
        try:
            # Try to connect and get info
            import impacket
            from impacket.smbconnection import SMBConnection
            
            conn = SMBConnection(host, host, timeout=5)
            
            # Try null session
            try:
                conn.login('', '')
                null_session = True
                conn.logoff()
            except:
                null_session = False
            
            return {
                'banner': conn.getServerName(),
                'os_version': conn.getServerOS(),
                'null_session_allowed': null_session
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    # Additional service check methods would be here...
    def _check_telnet(self, host, port):
        """Check Telnet service"""
        try:
            tn = telnetlib.Telnet(host, port, timeout=5)
            banner = tn.read_until(b'login:', timeout=3).decode('utf-8', errors='ignore')
            tn.close()
            return {'banner': banner}
        except:
            return {}
    
    def _check_smtp(self, host, port):
        """Check SMTP service"""
        try:
            server = smtplib.SMTP(host, port, timeout=5)
            banner = server.ehlo()
            server.quit()
            return {'banner': str(banner)}
        except:
            return {}
    
    def _check_dns(self, host, port):
        """Check DNS service"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [host]
            resolver.timeout = 3
            resolver.lifetime = 3
            
            # Try to query
            answer = resolver.resolve('google.com', 'A')
            return {'working': True, 'response': str(answer)}
        except:
            return {'working': False}
    
    def _check_mssql(self, host, port):
        """Check MSSQL service"""
        try:
            import pymssql
            # Would attempt connection here
            return {'service': 'mssql'}
        except:
            return {}
    
    def _check_mysql(self, host, port):
        """Check MySQL service"""
        try:
            import pymysql
            # Would attempt connection here
            return {'service': 'mysql'}
        except:
            return {}
    
    def _check_rdp(self, host, port):
        """Check RDP service"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            
            # Send RDP connection request
            sock.send(b'\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00')
            response = sock.recv(1024)
            sock.close()
            
            return {'rdp_supported': len(response) > 0}
        except:
            return {}
    
    def _check_vnc(self, host, port):
        """Check VNC service"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            
            # Send RFB protocol version
            sock.send(b'RFB 003.008\n')
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            return {'banner': response, 'vnc_supported': 'RFB' in response}
        except:
            return {}
    
    def _check_redis(self, host, port):
        """Check Redis service"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            
            # Send Redis ping
            sock.send(b'PING\r\n')
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            return {'banner': response, 'redis_supported': 'PONG' in response}
        except:
            return {}
    
    def _check_mongodb(self, host, port):
        """Check MongoDB service"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            
            # Send MongoDB isMaster command
            message = b'\x3a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00\x00\x00\x00\x00\x01\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            sock.send(message)
            response = sock.recv(1024)
            sock.close()
            
            return {'mongodb_supported': len(response) > 0}
        except:
            return {}
    
    def _check_postgresql(self, host, port):
        """Check PostgreSQL service"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            
            # Send startup packet
            sock.send(b'\x00\x00\x00\x08\x04\xd2\x16\x2f')
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            return {'banner': response, 'postgresql_supported': 'postgresql' in response.lower()}
        except:
            return {}
    
    def _check_vulnerabilities(self, host, port, service_info):
        """Check for known vulnerabilities"""
        vulnerabilities = []
        service = service_info.get('service', '')
        banner = service_info.get('banner', '').lower()
        
        # Check service-specific vulnerabilities
        if service in self.vuln_signatures:
            for vuln_name, vuln_desc in self.vuln_signatures[service].items():
                if self._check_vulnerability_signature(host, port, service, vuln_name, banner):
                    vulnerabilities.append({
                        'port': port,
                        'service': service,
                        'vulnerability': vuln_name,
                        'description': vuln_desc,
                        'severity': self._get_vulnerability_severity(vuln_name)
                    })
        
        # Check for outdated software
        outdated = self._check_outdated_software(banner, service)
        if outdated:
            vulnerabilities.append({
                'port': port,
                'service': service,
                'vulnerability': 'outdated_version',
                'description': f'Outdated {service} version: {outdated}',
                'severity': 'high'
            })
        
        return vulnerabilities
    
    def _check_vulnerability_signature(self, host, port, service, vuln_name, banner):
        """Check specific vulnerability signature"""
        if service == 'ftp' and vuln_name == 'anonymous_login':
            return self._check_ftp(host, port).get('anonymous_allowed', False)
        
        elif service == 'smb' and vuln_name == 'null_session':
            return self._check_smb(host, port).get('null_session_allowed', False)
        
        elif service == 'http' and vuln_name == 'directory_listing':
            return 'index of' in banner.lower()
        
        elif service == 'http' and vuln_name == 'server_info':
            return any(x in banner for x in ['apache/', 'nginx/', 'iis/', 'server:'])
        
        elif service == 'ssh' and vuln_name == 'weak_ciphers':
            # Would need to check SSH ciphers
            return False
        
        return False
    
    def _get_vulnerability_severity(self, vuln_name):
        """Get vulnerability severity"""
        high_severity = ['eternalblue', 'vsftpd_backdoor']
        medium_severity = ['null_session', 'directory_listing', 'weak_ciphers']
        
        if vuln_name in high_severity:
            return 'critical'
        elif vuln_name in medium_severity:
            return 'high'
        else:
            return 'medium'
    
    def _check_outdated_software(self, banner, service):
        """Check for outdated software versions"""
        # This would contain version checking logic
        # For now, return None or version string
        return None
    
    def _os_fingerprint(self, host):
        """OS fingerprinting using TCP/IP stack analysis"""
        try:
            if self.nm:
                self.nm.scan(host, arguments='-O')
                if host in self.nm.all_hosts():
                    return self.nm[host]['osmatch']
            
            # Fallback to basic fingerprinting
            return self._basic_os_fingerprint(host)
            
        except:
            return None
    
    def _basic_os_fingerprint(self, host):
        """Basic OS fingerprinting using TTL and TCP window size"""
        try:
            # Send SYN to common port
            packet = scapy.IP(dst=host)/scapy.TCP(dport=80, flags='S')
            response = scapy.sr1(packet, timeout=2, verbose=0)
            
            if response:
                ttl = response[scapy.IP].ttl
                window = response[scapy.TCP].window
                
                # OS guessing based on TTL and window size
                if ttl <= 64:
                    if window == 5840:
                        return 'Linux (kernel 2.4/2.6)'
                    elif window == 5720:
                        return 'Google Linux'
                    elif window == 65535:
                        return 'FreeBSD'
                    else:
                        return 'Linux/Unix'
                elif ttl <= 128:
                    if window == 8192:
                        return 'Windows XP/7/8/10'
                    elif window == 64240:
                        return 'Windows 7/8/10'
                    else:
                        return 'Windows'
                else:
                    return 'Unknown'
            
        except:
            pass
        
        return 'Unknown'
    
    def _perform_additional_recon(self, target, results):
        """Perform additional reconnaissance"""
        # DNS enumeration
        dns_info = self._dns_enumeration(target)
        if dns_info:
            results['dns_info'] = dns_info
        
        # Subdomain enumeration
        if '.' in target and '/' not in target:  # Likely a domain
            subdomains = self._subdomain_enumeration(target)
            if subdomains:
                results['subdomains'] = subdomains
        
        # WHOIS lookup
        whois_info = self._whois_lookup(target)
        if whois_info:
            results['whois_info'] = whois_info
    
    def _dns_enumeration(self, target):
        """Perform DNS enumeration"""
        dns_info = {}
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 3
            
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
            
            for record_type in record_types:
                try:
                    answers = resolver.resolve(target, record_type)
                    dns_info[record_type] = [str(r) for r in answers]
                except:
                    pass
            
            # Zone transfer attempt
            try:
                ns_servers = dns_info.get('NS', [])
                for ns in ns_servers[:2]:  # Try first 2 NS servers
                    try:
                        zone = dns.zone.from_xfr(dns.query.xfr(ns, target))
                        dns_info['zone_transfer'] = list(zone.nodes.keys())
                        break
                    except:
                        pass
            except:
                pass
            
        except Exception as e:
            logger.error(f"DNS enumeration failed: {e}")
        
        return dns_info if dns_info else None
    
    def _subdomain_enumeration(self, domain):
        """Enumerate subdomains"""
        subdomains = []
        
        # Common subdomain wordlist
        common_subs = [
            'www', 'mail', 'ftp', 'smtp', 'pop', 'ns1', 'ns2', 
            'webmail', 'admin', 'blog', 'shop', 'api', 'dev',
            'test', 'staging', 'mobile', 'secure', 'portal'
        ]
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            
            for sub in common_subs:
                try:
                    target = f"{sub}.{domain}"
                    answers = resolver.resolve(target, 'A')
                    subdomains.append(target)
                except:
                    pass
            
        except:
            pass
        
        return subdomains if subdomains else None
    
    def _whois_lookup(self, target):
        """Perform WHOIS lookup"""
        try:
            import whois
            w = whois.whois(target)
            return {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'name_servers': w.name_servers,
                'emails': w.emails
            }
        except:
            return None
    
    def _generate_report(self, scan_results):
        """Generate comprehensive scan report"""
        report = {
            'summary': {
                'target': scan_results.get('target'),
                'scan_type': scan_results.get('scan_type'),
                'start_time': scan_results.get('start_time'),
                'end_time': scan_results.get('end_time'),
                'duration': scan_results.get('duration'),
                'hosts_scanned': len(scan_results.get('hosts', {})),
                'open_ports_total': 0,
                'vulnerabilities_found': 0,
                'services_identified': 0
            },
            'hosts': {},
            'vulnerabilities': [],
            'recommendations': []
        }
        
        # Process each host
        for host, host_data in scan_results.get('hosts', {}).items():
            if host_data.get('alive'):
                host_report = {
                    'alive': True,
                    'open_ports': len(host_data.get('ports', [])),
                    'services': host_data.get('services', {}),
                    'os_guess': host_data.get('os_guess'),
                    'vulnerabilities': host_data.get('vulnerabilities', [])
                }
                
                report['summary']['open_ports_total'] += len(host_data.get('ports', []))
                report['summary']['vulnerabilities_found'] += len(host_data.get('vulnerabilities', []))
                report['summary']['services_identified'] += len(host_data.get('services', {}))
                
                report['vulnerabilities'].extend(host_data.get('vulnerabilities', []))
                
                report['hosts'][host] = host_report
        
        # Generate recommendations
        report['recommendations'] = self._generate_recommendations(report)
        
        return report
    
    def _generate_recommendations(self, report):
        """Generate security recommendations based on findings"""
        recommendations = []
        
        # Check for open sensitive ports
        sensitive_ports = {
            22: 'SSH - Ensure strong authentication and disable password auth',
            23: 'Telnet - Disable or replace with SSH',
            21: 'FTP - Use SFTP instead, disable anonymous login',
            3389: 'RDP - Use VPN, enable Network Level Authentication',
            445: 'SMB - Disable SMBv1, restrict access'
        }
        
        for host, host_data in report['hosts'].items():
            for port_info in host_data.get('services', {}).values():
                port = port_info.get('port')
                if port in sensitive_ports:
                    recommendations.append({
                        'host': host,
                        'port': port,
                        'service': port_info.get('service'),
                        'recommendation': sensitive_ports[port],
                        'priority': 'high'
                    })
        
        # Vulnerability-specific recommendations
        for vuln in report['vulnerabilities']:
            if 'anonymous_login' in vuln.get('vulnerability', ''):
                recommendations.append({
                    'host': 'Multiple',
                    'issue': 'Anonymous FTP login',
                    'recommendation': 'Disable anonymous FTP login',
                    'priority': 'critical'
                })
            elif 'null_session' in vuln.get('vulnerability', ''):
                recommendations.append({
                    'host': 'Multiple',
                    'issue': 'SMB null session',
                    'recommendation': 'Restrict null sessions in SMB configuration',
                    'priority': 'high'
                })
        
        # General recommendations
        if report['summary']['open_ports_total'] > 50:
            recommendations.append({
                'issue': 'Excessive open ports',
                'recommendation': 'Close unnecessary ports and services',
                'priority': 'medium'
            })
        
        return recommendations

def map_network(subnet, scan_type='quick'):
    """Main network mapping function"""
    try:
        scanner = AdvancedNetworkScanner(max_threads=50)
        results = scanner.comprehensive_scan(subnet, scan_type)
        
        # Save results
        if results:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'network_scan_{timestamp}.json'
            
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            print(f"Scan complete. Results saved to {filename}")
            
            # Print summary
            summary = results.get('summary', {})
            print(f"\nScan Summary:")
            print(f"  Target: {summary.get('target')}")
            print(f"  Hosts scanned: {summary.get('hosts_scanned')}")
            print(f"  Open ports found: {summary.get('open_ports_total')}")
            print(f"  Vulnerabilities: {summary.get('vulnerabilities_found')}")
            print(f"  Duration: {summary.get('duration'):.1f} seconds")
        
        return results
        
    except Exception as e:
        logger.error(f"Network mapping failed: {e}")
        return None

def detect_vulns(ip, port):
    """Legacy function for backward compatibility"""
    scanner = AdvancedNetworkScanner()
    service_info = scanner._detect_service(ip, port)
    return scanner._check_vulnerabilities(ip, port, service_info)

if __name__ == "__main__":
    # Test the network scanner
    print("Testing Advanced Network Scanner...")
    
    scanner = AdvancedNetworkScanner(max_threads=20)
    
    # Quick test scan
    results = scanner.comprehensive_scan('127.0.0.1', 'quick')
    
    if results:
        summary = results.get('summary', {})
        print(f"\nTest Scan Results:")
        print(f"  Hosts alive: {summary.get('hosts_scanned', 0)}")
        
        for host, host_data in results.get('hosts', {}).items():
            if host_data.get('alive'):
                print(f"\n  Host: {host}")
                print(f"    Open ports: {len(host_data.get('ports', []))}")
                
                for port, service in host_data.get('services', {}).items():
                    print(f"    Port {port}: {service.get('service', 'unknown')}")
                
                vulns = host_data.get('vulnerabilities', [])
                if vulns:
                    print(f"    Vulnerabilities: {len(vulns)}")
                    for vuln in vulns[:3]:  # Show first 3
                        print(f"      - {vuln.get('vulnerability')}")
    else:
        print("Scan failed")
