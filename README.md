# PhantomRAT 🚀

**Advanced Command & Control Framework for Security Research**

> ⚠️ **WARNING**: For educational and authorized penetration testing purposes only.

## 🎯 Features

- **Advanced C2 Server** with web dashboard
- **Stealthy Implants** with multiple evasion techniques
- **Encrypted Communication** using AES-256
- **Multi-platform Support** (Windows, Linux, macOS)
- **Real-time Task Management**
- **Telegram Bot Integration** for notifications
- **Ngrok Integration** for public access

## 🚦 Quick start

Run PhantomRAT from the repository root with the bundled launcher scripts. A Python 3 virtual environment is recommended to keep dependencies isolated.

### One-command launch (C2 + implant)
```bash
./start.sh
```
`start.sh` activates the virtual environment (creating one if absent), installs requirements, and starts both the C2 dashboard and the implant on `0.0.0.0:8000` with recommended optimizations.

### Manual launcher options
If you prefer to call the Python orchestrator directly:
```bash
python run.py --mode both --host 0.0.0.0 --port 8000 --implant-mode standard --optimize
```
Key flags:
- `--mode`: `c2`, `implant`, or `both`
- `--implant-mode`: `standard`, `stealth`, `aggressive`, or `test`
- `--debug`: enable verbose logging for the C2

### Component-only starts
- C2 only:
  ```bash
  python run.py --mode c2 --host 0.0.0.0 --port 8000 --optimize
  ```
- Implant only (against a running C2):
  ```bash
  python run.py --mode implant --implant-mode stealth --optimize
  ```

### First-time setup
If you want to prepare dependencies manually before launching:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```


