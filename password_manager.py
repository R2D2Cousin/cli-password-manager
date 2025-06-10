import sqlite3
import os
import base64
import re
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import pyperclip
import time
import random
import string

# Constants
DB_FILE = "vault.db"
SALT_FILE = "key.salt"

# Generate a key from master password
def derive_key(password):
    if not os.path.exists(SALT_FILE):
        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
    else:
        with open(SALT_FILE, "rb") as f:
            salt = f.read()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Initialize DB
def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                site TEXT PRIMARY KEY,
                username TEXT,
                password TEXT
            )
        """)

# Encrypt and decrypt
def encrypt(data, fernet):
    return fernet.encrypt(data.encode()).decode()

def decrypt(data, fernet):
    return fernet.decrypt(data.encode()).decode()

# Password strength checker
def check_password_strength(password):
    strength = 0
    remarks = []

    if len(password) >= 8:
        strength += 1
    else:
        remarks.append("Too short")

    if re.search(r"[a-z]", password):
        strength += 1
    else:
        remarks.append("No lowercase letters")

    if re.search(r"[A-Z]", password):
        strength += 1
    else:
        remarks.append("No uppercase letters")

    if re.search(r"\d", password):
        strength += 1
    else:
        remarks.append("No digits")

    if re.search(r"\W", password):
        strength += 1
    else:
        remarks.append("No special characters")

    verdict = {
        5: "Very Strong",
        4: "Strong",
        3: "Moderate",
        2: "Weak",
        1: "Very Weak",
        0: "Useless"
    }[strength]

    print(f"Password Strength: {verdict}")
    if remarks:
        print("Tips:", ", ".join(remarks))

# Password generator
def generate_password(length=16, digits=True, symbols=True):
    chars = string.ascii_letters
    if digits:
        chars += string.digits
    if symbols:
        chars += string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

# Clipboard copy
def copy_to_clipboard(data):
    pyperclip.copy(data)
    print("Copied to clipboard. Will clear in 10 seconds.")
    time.sleep(10)
    pyperclip.copy("")

# Menu options
def add_password(fernet):
    site = input("Site: ")
    username = input("Username: ")

    use_generator = input("Generate a secure password? (y/n): ").lower()
    if use_generator == "y":
        try:
            length = int(input("Password length (default 16): ") or "16")
        except ValueError:
            length = 16
        use_digits = input("Include digits? (y/n): ").lower() == "y"
        use_symbols = input("Include symbols? (y/n): ").lower() == "y"
        password = generate_password(length, use_digits, use_symbols)
        print("Generated Password:", password)
        check_password_strength(password)
    else:
        password = getpass("Password: ")
        check_password_strength(password)

    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            "REPLACE INTO credentials (site, username, password) VALUES (?, ?, ?)",
            (site, encrypt(username, fernet), encrypt(password, fernet))
        )
    print("✅ Credentials saved.")

def view_password(fernet):
    site = input("Enter site to view: ")
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.execute("SELECT username, password FROM credentials WHERE site = ?", (site,))
        row = cursor.fetchone()
        if row:
            username = decrypt(row[0], fernet)
            password = decrypt(row[1], fernet)
            print("Username:", username)
            print("Password:", password)
            if input("Copy password to clipboard? (y/n): ").lower() == "y":
                copy_to_clipboard(password)
        else:
            print("❌ No entry found.")

def delete_password():
    site = input("Enter site to delete: ")
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("DELETE FROM credentials WHERE site = ?", (site,))
    print("🗑️ Deleted if it existed.")

def list_sites():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.execute("SELECT site FROM credentials")
        sites = [row[0] for row in cursor.fetchall()]
    if sites:
        print("Saved sites:")
        for s in sites:
            print("-", s)
    else:
        print("No entries yet.")

# Main loop
def main():
    print("🔐 Welcome to the CLI Password Manager")
    master_password = getpass("Enter master password: ")
    key = derive_key(master_password)
    fernet = Fernet(key)
    init_db()

    while True:
        print("\nOptions:")
        print("1. Add password")
        print("2. View password")
        print("3. Delete password")
        print("4. List all sites")
        print("5. Exit")
        choice = input("> ")

        if choice == "1":
            add_password(fernet)
        elif choice == "2":
            view_password(fernet)
        elif choice == "3":
            delete_password()
        elif choice == "4":
            list_sites()
        elif choice == "5":
            print("Goodbye!")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()