"""SafeShare Launcher.

Launches the Enterprise AI Privacy & Secret Firewall.
Auto-detects open ports (8000 -> 8001 -> 8080) so it never fails on port conflicts.
"""

import os
import socket
import subprocess
import sys
import threading
import time
import webbrowser

def ensure_dependencies():
    required = ["uvicorn", "starlette"]
    missing = []
    for pkg in required:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        print(f"[*] First-time launch: Installing {', '.join(missing)}...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", *missing, "--quiet"])
            print("[+] Installed successfully!\n")
        except Exception:
            pass

ensure_dependencies()

import uvicorn

HOST = "127.0.0.1"


def find_free_port(preferred_ports=(8000, 8001, 8080, 8088)):
    """Find first available port from preferred list, or system free port."""
    for p in preferred_ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((HOST, p))
                return p
            except OSError:
                continue
    # Fallback to any free ephemeral port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, 0))
        return s.getsockname()[1]


def open_browser(url):
    time.sleep(1.2)
    try:
        webbrowser.open(url)
    except Exception:
        pass


from desktop_app import (
    find_free_port,
    start_server,
    start_clipboard_daemon,
    launch_native_window,
)


def main():
    port = find_free_port(8000)
    url = f"http://127.0.0.1:{port}"

    print("=" * 74)
    print(" 🛡️  SafeShare Desktop Application")
    print("    Enterprise AI Privacy Firewall & System Clipboard Guardian")
    print("=" * 74)
    print(f" [SYSTEM] Machine: {os.environ.get('COMPUTERNAME', 'LOCALHOST')} | User: {os.environ.get('USERNAME', 'devhe')}")
    print(f" [CORE]   Server online at {url}")
    print(f" [AUDIT]  Persistent local store: {os.path.abspath('audit_log.json')}")
    print(f" [GUARD]  Active 50ms clipboard interception with Pause/Resume toggle")
    print("=" * 74)

    # 1. Start Server in daemon thread
    server_thread = threading.Thread(target=start_server, args=(port,), daemon=True)
    server_thread.start()
    time.sleep(1.0)

    # 2. Launch Native Window
    print(" -> Opening SafeShare Desktop UI...")
    launch_native_window(url)

    # 3. Start Clipboard Guardian in foreground / main thread
    print(" -> Starting Real-Time Clipboard Guardian daemon...\n")
    start_clipboard_daemon(port)


if __name__ == "__main__":
    main()
