import hashlib
import json
import os

CONFIG_FILE = "config.json"

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