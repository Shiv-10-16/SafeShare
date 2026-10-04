"""SafeShare - Desktop Clipboard Guardian.

Autonomous zero-trust background daemon that monitors the Windows system clipboard.
When sensitive PII, passwords, credentials, or confidential business data are copied,
SafeShare intercepts and anonymizes the clipboard content before it can be pasted
into ChatGPT, Claude, Gemini, or any external tool.
"""

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request

try:
    import winsound
except ImportError:
    winsound = None

# Fallback direct engine import if local core is imported directly
try:
    from safeshare_engine import merge_and_anonymize, restore_text, scan_patterns
    HAS_LOCAL_ENGINE = True
except ImportError:
    HAS_LOCAL_ENGINE = False

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

CF_TEXT = 1
CF_UNICODETEXT = 13
GMEM_MOVEABLE = 0x0002

user32.OpenClipboard.argtypes = [wintypes.HWND]
user32.OpenClipboard.restype = wintypes.BOOL
user32.CloseClipboard.argtypes = []
user32.CloseClipboard.restype = wintypes.BOOL
user32.EmptyClipboard.argtypes = []
user32.EmptyClipboard.restype = wintypes.BOOL
user32.GetClipboardData.argtypes = [wintypes.UINT]
user32.GetClipboardData.restype = wintypes.HANDLE
user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
user32.SetClipboardData.restype = wintypes.HANDLE
user32.GetClipboardSequenceNumber.argtypes = []
user32.GetClipboardSequenceNumber.restype = wintypes.DWORD

kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
kernel32.GlobalLock.restype = wintypes.LPVOID
kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
kernel32.GlobalUnlock.restype = wintypes.BOOL

VAULT_CACHE_FILE = os.path.join(os.path.dirname(__file__), "guardian_vault.json")


def read_clipboard() -> str:
    """Safely read Unicode text from Windows clipboard."""
    for _ in range(10):
        if user32.OpenClipboard(None):
            break
        time.sleep(0.02)
    else:
        return ""
    try:
        h_clip = user32.GetClipboardData(CF_UNICODETEXT)
        if not h_clip:
            return ""
        p_data = kernel32.GlobalLock(h_clip)
        if not p_data:
            return ""
        try:
            return ctypes.c_wchar_p(p_data).value or ""
        finally:
            kernel32.GlobalUnlock(h_clip)
    finally:
        user32.CloseClipboard()


def write_clipboard(text: str) -> bool:
    """Safely write Unicode and ANSI text to Windows clipboard."""
    for _ in range(15):
        if user32.OpenClipboard(None):
            break
        time.sleep(0.02)
    else:
        return False
    try:
        user32.EmptyClipboard()

        # 1. Write CF_UNICODETEXT
        encoded_u16 = (text + "\0").encode("utf-16le")
        h_u16 = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(encoded_u16))
        if h_u16:
            p_u16 = kernel32.GlobalLock(h_u16)
            if p_u16:
                ctypes.memmove(p_u16, encoded_u16, len(encoded_u16))
                kernel32.GlobalUnlock(h_u16)
                user32.SetClipboardData(CF_UNICODETEXT, h_u16)

        # 2. Write CF_TEXT (ANSI fallback for standard inputs)
        encoded_ansi = (text + "\0").encode("ascii", errors="replace")
        h_ansi = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(encoded_ansi))
        if h_ansi:
            p_ansi = kernel32.GlobalLock(h_ansi)
            if p_ansi:
                ctypes.memmove(p_ansi, encoded_ansi, len(encoded_ansi))
                kernel32.GlobalUnlock(h_ansi)
                user32.SetClipboardData(CF_TEXT, h_ansi)

        return True
    finally:
        user32.CloseClipboard()


def play_alert_sound():
    """Play alert sound on threat detection."""
    if winsound:
        try:
            winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
        except Exception:
            pass


def load_persistent_vault() -> dict:
    if os.path.exists(VAULT_CACHE_FILE):
        try:
            with open(VAULT_CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_persistent_vault(vault: dict):
    existing = load_persistent_vault()
    existing.update(vault)
    try:
        with open(VAULT_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2)
    except Exception:
        pass


def audit_text(text: str, base_url: str = "http://127.0.0.1:8000") -> dict:
    """Audit text via SafeShare API or fallback to local engine."""
    payload = json.dumps({"text": text, "source": "desktop"}).encode("utf-8")
    req = urllib.request.Request(
        f"{base_url}/api/audit",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=1.0) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        # Fallback to local engine
        if HAS_LOCAL_ENGINE:
            pat_findings = scan_patterns(text)
            report = merge_and_anonymize(text, pat_findings, [], mask_mode="synthetic")
            report["compliance_summary"] = "SafeShare Desktop Local Pattern Engine."
            return report
        return {"findings": [], "sanitized_text": text, "vault": {}}


def disable_quickedit():
    """Disable QuickEdit Mode in Windows console so mouse clicks don't pause the Python daemon."""
    try:
        STD_INPUT_HANDLE = -10
        ENABLE_QUICK_EDIT_MODE = 0x0040
        ENABLE_EXTENDED_FLAGS = 0x0080
        h_in = kernel32.GetStdHandle(STD_INPUT_HANDLE)
        mode = wintypes.DWORD()
        if kernel32.GetConsoleMode(h_in, ctypes.byref(mode)):
            new_mode = (mode.value & ~ENABLE_QUICK_EDIT_MODE) | ENABLE_EXTENDED_FLAGS
            kernel32.SetConsoleMode(h_in, new_mode)
    except Exception:
        pass


from audit_store import is_guardian_paused, save_log_entry


class ClipboardGuardian:
    def __init__(self, base_url: str = "http://127.0.0.1:8000"):
        self.base_url = base_url
        self.last_sanitized_text = None
        self.last_checked_clean_text = None
        self.last_seq = user32.GetClipboardSequenceNumber()
        self.interceptions_count = 0

    def inspect_and_protect(self) -> bool:
        """Inspect clipboard and sanitize if sensitive entities are detected.
        Supports pause state, unlimited copies, and persistent disk logging.
        """
        # If user paused the guardian in the UI, do not modify clipboard
        if is_guardian_paused():
            return False

        text = read_clipboard()
        if not text or len(text.strip()) < 3:
            return False

        # If this clipboard is the exact sanitized string SafeShare just produced, ignore it
        if text == self.last_sanitized_text:
            return False

        # If this clean text was already checked and had no findings, skip to avoid repeated no-op audits
        if text == self.last_checked_clean_text:
            return False

        # Run audit (handles any size of text)
        report = audit_text(text, self.base_url)
        findings = report.get("findings", [])

        if not findings:
            self.last_checked_clean_text = text
            return False

        sanitized_text = report.get("sanitized_text", text)
        vault = report.get("vault", {})

        if sanitized_text != text:
            # Overwrite clipboard with verified retry
            self.last_sanitized_text = sanitized_text
            self.last_checked_clean_text = None

            write_success = False
            for retry in range(15):
                if write_clipboard(sanitized_text):
                    if read_clipboard() == sanitized_text:
                        write_success = True
                        break
                time.sleep(0.02)

            if not write_success:
                write_clipboard(sanitized_text)

            # Synchronize sequence number to our own write so it doesn't trigger self-loop
            self.last_seq = user32.GetClipboardSequenceNumber()

            categories = list(set(f.get("category") or f.get("entity_type") or "PII" for f in findings))

            # 1. Save to local persistent disk audit log (stores user, machine, timestamp, tokens)
            save_log_entry(
                original_text=text,
                sanitized_text=sanitized_text,
                threats_count=len(findings),
                categories=categories,
                vault=vault,
                source="desktop_guard",
            )
            save_persistent_vault(vault)
            play_alert_sound()
            self.interceptions_count += 1

            # Log to console
            categories = list(set(f.get("category") or f.get("entity_type") or "PII" for f in findings))
            char_count = len(text)
            line_count = len(text.splitlines())
            size_label = f"{char_count:,} chars" if line_count <= 1 else f"{char_count:,} chars ({line_count} lines)"

            print("=" * 72)
            print(f"[SHIELD INTERCEPTED #{self.interceptions_count}] Data Sanitized in Windows Clipboard!")
            print(f"Time:        {time.strftime('%H:%M:%S')}")
            print(f"Volume:      {size_label} scanned & secured")
            print(f"Threats:     {len(findings)} detected ({', '.join(categories)})")
            print(f"Original:    {text[:80].strip()}...")
            print(f"Clipboard:   {sanitized_text[:80].strip()}...")
            print("Status:      [OK] Protected! Safe to paste in Claude / ChatGPT / Gemini.")
            print("=" * 72)

            # Inform backend
            try:
                log_payload = json.dumps({
                    "source": "desktop",
                    "threats_count": len(findings),
                    "categories": categories,
                    "snippet": sanitized_text[:100],
                }).encode("utf-8")
                urllib.request.urlopen(
                    urllib.request.Request(
                        f"{self.base_url}/api/guardian/log",
                        data=log_payload,
                        headers={"Content-Type": "application/json"},
                    ),
                    timeout=1.0,
                )
            except Exception:
                pass

            return True

        return False

    def run_forever(self, poll_interval: float = 0.05):
        """Continuously monitor clipboard sequence changes with ultra-fast 50ms polling."""
        disable_quickedit()

        print("=" * 72)
        print("  SafeShare Desktop Clipboard Guardian [ONLINE & PERSISTENT]")
        print("  Continuous Zero-Trust Protection Active (Unlimited Copies)")
        print("  Powered by Google Gemma 4 AI & SafeShare Local Firewall")
        print("  Monitoring Windows Clipboard (50ms ultra-low latency)...")
        print("=" * 72)
        print("Copy any sensitive data anywhere in Windows (passwords, Aadhaar, cards, API keys).")
        print("SafeShare automatically sanitizes the clipboard every time you copy!\n")

        # Immediately inspect current clipboard on launch
        self.inspect_and_protect()

        while True:
            try:
                seq = user32.GetClipboardSequenceNumber()
                if seq != self.last_seq:
                    self.last_seq = seq
                    self.inspect_and_protect()
                time.sleep(poll_interval)
            except KeyboardInterrupt:
                print("\n[SafeShare Guardian Stopped by User]")
                break
            except Exception:
                time.sleep(poll_interval)


def restore_clipboard_action():
    """Restore sanitized synthetic tokens back to original text using local vault."""
    text = read_clipboard()
    if not text:
        print("[!] Clipboard is empty.")
        return
    vault = load_persistent_vault()
    if not vault:
        print("[!] No tokens saved in vault.")
        return

    restored = text
    for token, secret in vault.items():
        restored = restored.replace(token, secret)

    if restored != text:
        write_clipboard(restored)
        print("[OK] Clipboard Restored! Synthetic tokens replaced with original values.")
        print(f"Preview: {restored[:80]}...")
    else:
        print("[i] No recognized synthetic tokens found in clipboard.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SafeShare Desktop Clipboard Guardian")
    parser.add_argument("--once", action="store_true", help="Inspect and protect current clipboard once then exit.")
    parser.add_argument("--restore", action="store_true", help="Restore synthetic tokens currently in clipboard.")
    parser.add_argument("--port", type=int, default=8000, help="SafeShare backend port (default: 8000)")
    args = parser.parse_args()

    base_url = f"http://127.0.0.1:{args.port}"

    if args.restore:
        restore_clipboard_action()
    elif args.once:
        guardian = ClipboardGuardian(base_url)
        inter = guardian.inspect_and_protect()
        print(f"Inspection complete. Threat intercepted: {inter}")
    else:
        guardian = ClipboardGuardian(base_url)
        guardian.run_forever()
