import psutil
import os

def list_processes():
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username']):
        processes.append(proc.info)
    return processes

def kill_process(pid):
    try:
        p = psutil.Process(pid)
        p.terminate()
        return True
    except:
        return False

def start_process(cmd):
    try:
        os.system(cmd)
        return True
    except:
        return False