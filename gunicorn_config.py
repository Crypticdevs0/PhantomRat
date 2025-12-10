# Gunicorn configuration for PhantomRAT C2
import multiprocessing

# Server socket
bind = "0.0.0.0:8000"
backlog = 2048

# Worker processes
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "sync"
worker_connections = 1000
timeout = 30
keepalive = 2

# Logging
accesslog = "/home/sysmaint/PhantomRat/gunicorn_access.log"
errorlog = "/home/sysmaint/PhantomRat/gunicorn_error.log"
loglevel = "warning"

# Process naming
proc_name = "phantomrat_c2"

# Server mechanics
daemon = False
pidfile = "/home/sysmaint/PhantomRat/gunicorn.pid"
umask = 0
user = "sysmaint"
group = "sysmaint"
tmp_upload_dir = None

# SSL (uncomment if using HTTPS)
# keyfile = "/path/to/key.pem"
# certfile = "/path/to/cert.pem"

# Server hooks
def post_fork(server, worker):
    server.log.info("Worker spawned (pid: %s)", worker.pid)

def pre_fork(server, worker):
    pass

def pre_exec(server):
    server.log.info("Forked child, re-executing.")

def when_ready(server):
    server.log.info("Server is ready. Spawning workers")

def worker_int(worker):
    worker.log.info("Worker received INT or QUIT signal")

def worker_abort(worker):
    worker.log.info("Worker received SIGABRT signal")
