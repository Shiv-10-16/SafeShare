"""SafeShare Desktop - Unified Standalone Application Launcher.

Runs the local Privacy Core, persistent audit store, and real-time Windows Clipboard Guardian,
launching the native desktop window matching the Coinview theme reference.
"""

import os
import socket
import subprocess
import sys
import threading
import time
import webbrowser

import uvicorn
from app import app
from audit_store import get_audit_summary, load_logs
from clipboard_guard import ClipboardGuardian


def find_free_port(start_port: int = 8000, max_attempts: int = 50) -> int:
    for port in range(start_port, start_port + max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    return start_port


def start_server(port: int):
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=port,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)
    server.run()


def start_clipboard_daemon(port: int):
    guardian = ClipboardGuardian(base_url=f"http://127.0.0.1:{port}")
    guardian.run_forever(poll_interval=0.05)


def launch_native_window(url: str):
    """Launch borderless native desktop app window using Microsoft Edge or default browser."""
    edge_paths = [
        os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
        os.path.expandvars(r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
        os.path.expandvars(r"%LocalAppData%\Microsoft\Edge\Application\msedge.exe"),
    ]

    for p in edge_paths:
        if os.path.exists(p):
            try:
                subprocess.Popen([
                    p,
                    f"--app={url}",
                    "--window-size=1280,840",
                    "--disable-extensions",
                    "--app-auto-launch",
                ])
                return
            except Exception:
                pass

    # Fallback to default browser
    webbrowser.open(url)


if __name__ == "__main__":
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

    # 1. Start Server thread
    server_thread = threading.Thread(target=start_server, args=(port,), daemon=True)
    server_thread.start()
    time.sleep(1.0)

    # 2. Launch Native Window
    print("\n -> Opening SafeShare Desktop UI...")
    launch_native_window(url)

    # 3. Start Clipboard Guardian in foreground / main thread loop
    print(" -> Starting Real-Time Clipboard Guardian daemon...\n")
    start_clipboard_daemon(port)
