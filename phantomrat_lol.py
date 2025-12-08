import subprocess
import socket

def run_command(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout

def recon_system():
    print("Running system reconnaissance...")
    # Get processes
    processes = run_command("ps aux")
    print("Processes:", processes[:500])  # Truncate for brevity

    # Get network connections
    netstat = run_command("netstat -tulpn")
    print("Network:", netstat[:500])

    # Get users
    users = run_command("who")
    print("Users:", users)

def execute_command(cmd):
    # Execute arbitrary command
    return run_command(cmd)

if __name__ == "__main__":
    recon_system()
    # Example execution
    result = execute_command("ls -la")
    print("Command result:", result)