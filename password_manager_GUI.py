import tkinter as tk
from tkinter import simpledialog, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import cryptography
import base64
import os

# Function to generate key
def write_key():
    if not os.path.exists("key.key"):
        key = Fernet.generate_key()
        with open("key.key", "wb") as key_file:
            key_file.write(key)
        print("Encryption key generated and saved as key.key")
    else:
        print("Key file already exists. Skipping key generation.")

# Function to load key
def load_key(master_pwd):
    with open("key.key", "rb") as file:
        key = file.read() 
    
    derived_key = Fernet.generate_key()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=os.urandom(16),
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_pwd.encode()))
    return key

# Check if key file exists; if not, generate the key
write_key()

# Prompt for master password
master_pwd = simpledialog.askstring("Master Password", "Enter the master password:")

# Loading key
key = load_key(master_pwd) 
fer = Fernet(key)

# Function to view passwords
def view():
    passwords = ""
    with open('passwords.txt', 'r') as f:
        for line in f.readlines():
            data = line.rstrip()
            user, passw = data.split(" | ")
            try:
                decrypted_pass = fer.decrypt(passw.encode()).decode()
                passwords += f"User_Name: {user} | Password: {decrypted_pass}\n"
            except cryptography.fernet.InvalidToken:
                passwords += f"Invalid password token detected for {user}.\n"
            except ValueError as e:
                passwords += f"Error decrypting password for {user}: {e}\n"
    return passwords

# Function to add passwords
def add(account_name, password):
    encrypted_pwd = fer.encrypt(password.encode()).decode()
    with open('passwords.txt', 'a') as f:
        f.write(account_name + " | " + encrypted_pwd + "\n")

# Tkinter GUI setup
root = tk.Tk()
root.title("Password Manager")

# View passwords button
def view_passwords():
    passwords = view()
    messagebox.showinfo("View Passwords", passwords)

view_button = tk.Button(root, text="View Passwords", command=view_passwords)
view_button.pack()

# Add password button
def add_password():
    account_name = simpledialog.askstring("Add Password", "Enter account name:")
    password = simpledialog.askstring("Add Password", "Enter password:")
    add(account_name, password)

add_button = tk.Button(root, text="Add Password", command=add_password)
add_button.pack()

# Quit button
quit_button = tk.Button(root, text="Quit", command=root.destroy)
quit_button.pack()

# Center the window on the screen
root.update_idletasks()
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
window_width = root.winfo_width()
window_height = root.winfo_height()
x = (screen_width - window_width) // 2
y = (screen_height - window_height) // 2
root.geometry(f"+{x}+{y}")

root.mainloop()
