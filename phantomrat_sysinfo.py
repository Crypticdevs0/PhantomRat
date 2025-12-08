import platform
import psutil
import os

def get_system_info():
    return {
        "platform": platform.platform(),
        "hostname": platform.node(),
        "cpu": platform.processor(),
        "ram": psutil.virtual_memory().total,
        "disk": psutil.disk_usage('/').total,
        "users": [user.name for user in psutil.users()],
        "processes": len(psutil.pids())
    }