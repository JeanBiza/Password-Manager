import hashlib
import json
import os
import datetime
import time


CONFIG_FILE = "config.json"
MAX_ATTEMPTS = 3
LOCKOUT_MINUTES = 5

IDLE_TIMEOUT = 300
last_activity = [time.time()]

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as file:
            return json.load(file)
    else:
        return {}

def save_config(config_data):
    with open(CONFIG_FILE, 'w') as file:
        json.dump(config_data, file, indent=4)

def is_first_run():
    config = load_config()
    return config.get("is_first_run", True)

def toggle_first_run():
    config = load_config()
    config["is_first_run"] = not bool(get_pin())
    save_config(config)

def hash_pin(pin: str) -> str:
    return hashlib.sha256(pin.encode()).hexdigest()

def set_pin(pin: str):
    config = load_config()
    config["pin"] = hash_pin(pin)
    save_config(config)

def verify_pin(pin: str) -> bool:
    config = load_config()
    stored = config.get("pin", None)
    if stored is None:
        return False
    return hash_pin(pin) == stored

def get_pin():
    config = load_config()
    return config.get("pin", None)


def get_failed_attempts() -> int:
    config = load_config()
    return config.get("failed_attempts", 0)

def increment_failed_attempts():
    config = load_config()
    config["failed_attempts"] = config.get("failed_attempts", 0) + 1
    if config["failed_attempts"] >= MAX_ATTEMPTS:
        config["lockout_until"] = (datetime.datetime.now() + datetime.timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
    save_config(config)

def reset_failed_attempts():
    config = load_config()
    config["failed_attempts"] = 0
    config.pop("lockout_until", None)
    save_config(config)

def is_locked_out() -> bool:
    config = load_config()
    lockout_until = config.get("lockout_until")
    if not lockout_until:
        return False
    if datetime.datetime.now() < datetime.datetime.fromisoformat(lockout_until):
        return True
    reset_failed_attempts()
    return False

def lockout_remaining() -> int:
    config = load_config()
    lockout_until = config.get("lockout_until")
    if not lockout_until:
        return 0
    delta = datetime.datetime.fromisoformat(lockout_until) - datetime.datetime.now()
    return max(0, int(delta.total_seconds() / 60) + 1)

def reset_activity(event=None):
    last_activity[0] = time.time()

def check_idle(win, current_view):
    if current_view[0] == "view":
        if time.time() - last_activity[0] > IDLE_TIMEOUT:
            messagebox.showwarning("Session expired", "Session expired due to inactivity.")
            current_view[0] = "locked"
            pin_window(win)
            return
    win.after(10000, lambda: check_idle(win, current_view))