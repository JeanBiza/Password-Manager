import os
import sqlite3
import json
import hashlib
from cryptography.fernet import Fernet

CONFIG_FILE = "config.json"
DB_NAME = "database.db"

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

def get_pin():
    config = load_config()
    return config.get("pin", None)

def create_master_key():
    master = Fernet.generate_key()
    with open("master.key", "wb") as file:
        file.write(master)

def get_master_key():
    if not os.path.exists("master.key"):
        create_master_key()
    with open("master.key", "rb") as file:
        return file.read()

def encrypt_password(password):
    fernet = Fernet(get_master_key())
    encrypted = fernet.encrypt(password.encode())
    return encrypted

def decrypt_password(encrypted_password):
    fernet = Fernet(get_master_key())
    decrypted = fernet.decrypt(encrypted_password).decode()
    return decrypted

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            website TEXT NOT NULL,
            user TEXT NOT NULL,
            password BLOB NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def save_password(website, user, password):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    encrypted = encrypt_password(password)
    c.execute("INSERT INTO passwords (website, user, password) VALUES (?, ?, ?)",
              (website, user, encrypted))
    conn.commit()
    conn.close()

def delete_password(pass_id):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("DELETE FROM passwords WHERE id = ?", (pass_id,))
    conn.commit()
    conn.close()

def update_password(pass_id, website, user):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute(
        "UPDATE passwords SET website = ?, user = ? WHERE id = ?",
        (website, user, pass_id)
    )
    conn.commit()
    conn.close()

def get_passwords():
    passwords = []
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT * from passwords")
    for fila in c.fetchall():
        pass_id, website, user, encrypted = fila
        decrypted = decrypt_password(encrypted)
        password = [pass_id,website,user,decrypted]
        passwords.append(password)

    return passwords

