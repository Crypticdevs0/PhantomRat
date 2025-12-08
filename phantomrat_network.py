import socket
import ipaddress
import threading
import time

def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            print(f"Port {port} open on {ip}")
        sock.close()
    except:
        pass

def map_network(subnet):
    network = ipaddress.ip_network(subnet)
    for ip in network.hosts():
        for port in [22, 80, 443, 3389]:  # Common ports
            threading.Thread(target=scan_port, args=(str(ip), port)).start()
    time.sleep(5)  # Wait for threads

def detect_vulns(ip, port):
    # Simple vuln check, e.g., for HTTP
    if port == 80:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, port))
            sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
            response = sock.recv(1024)
            if b"Server:" in response:
                server = response.split(b"Server: ")[1].split(b"\r\n")[0]
                print(f"Server on {ip}:{port} is {server.decode()}")
                # Check for known vulns, e.g., if "Apache/2.4.49" then vulnerable to something
        except:
            pass

if __name__ == "__main__":
    map_network("141.105.71.0/24")  # VPS subnet