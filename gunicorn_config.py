# gunicorn_config.py
bind = "0.0.0.0:8000"
workers = 4  # Reduce from 10 to 4 (10 is overkill for most C2)
worker_class = "gthread"
threads = 2
timeout = 120
keepalive = 5
max_requests = 1000
max_requests_jitter = 50
preload_app = True  # This helps with shared resources
