# Password Manager

A local desktop password manager built with Python and customtkinter. Passwords are encrypted with Fernet symmetric encryption and protected behind a hashed PIN.

## Features

- **Fernet encryption** — all passwords stored encrypted in a local SQLite database
- **PIN protection** — SHA-256 hashed PIN required to access stored passwords
- **Lockout system** — account locks for 5 minutes after 3 failed PIN attempts
- **Auto-lock** — session locks automatically after 5 minutes of inactivity
- **Real-time search** — filter passwords by website instantly
- **Password generator** — generates secure random passwords using `secrets`
- **Copy to clipboard** — copy passwords without displaying them

## Requirements

- Python 3.11+

## Installation

**1. Clone the repository**
```bash
git clone https://github.com/JeanBiza/password-manager.git
cd password-manager
```

**2. Create a virtual environment and install dependencies**
```bash
python -m venv venv
source venv/bin/activate        # Linux / macOS
venv\Scripts\activate           # Windows
pip install -r requirements.txt
```

**3. Run the app**
```bash
python main.py
```

On first run you will be asked to set a security PIN. This PIN is required every time you access your stored passwords.

## Usage

- **Add Password** — enter the website, username/email and password. Use the Generate button for a secure random password.
- **View Passwords** — requires PIN. Search by website, select an entry to view details, copy the password to clipboard, update or delete entries.
- **Change PIN** — available from the PIN screen.

## Security notes

- Passwords are encrypted with Fernet before being stored — the database file alone is not enough to read them.
- The master key is stored locally in `master.key`. Keep this file safe — losing it means losing access to all stored passwords.
- The PIN is never stored in plaintext — only its SHA-256 hash is saved.
- `master.key`, `config.json` and `database.db` are excluded from version control.

## Project structure

```
password-manager/
├── main.py          # UI built with customtkinter
├── config.py        # PIN management, lockout and session logic
├── crypto.py        # Fernet encryption and master key handling
├── database.py      # SQLite password storage
├── utils.py         # Password generator
├── requirements.txt
└── .gitignore
```

## Stack

- [customtkinter](https://github.com/TomSchimansky/CustomTkinter) — modern dark UI
- [cryptography](https://cryptography.io/) — Fernet symmetric encryption
- SQLite — local encrypted password storage
