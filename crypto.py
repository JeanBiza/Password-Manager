from cryptography.fernet import Fernet
import os

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