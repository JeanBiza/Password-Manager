import sqlite3
from cryptography.fernet import Fernet

from crypto import encrypt_password, decrypt_password

DB_NAME = "database.db"

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
