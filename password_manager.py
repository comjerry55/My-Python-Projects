#importing fernet class from cryptography.fernet modulle
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import cryptography
import base64
import os

#optional function to generate key

def write_key():
    if not os.path.exists("key.key"): #check if the key file already exists
     key = Fernet.generate_key()
     with open("key.key", "wb") as key_file:
        key_file.write(key)
     print("Encryption key generated and saved as key.key")
    else:
     print("Key file already exists. Skipping key generation. ")

#function to load key
#loads key from key.key file and concatinates it with provided master key
def load_key(master_pwd):
   with open("key.key", "rb") as file:
    key = file.read() 
    

    #derive a new key using the master password
    derived_key = Fernet.generate_key()  #generate new key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt= os.urandom(16), #use unique salt per application
        iterations=100000,  #adjust iteration number as needd
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_pwd.encode()))

    return key

#check if key file exists; if not, generatethe key
write_key()

#prompt for master password
master_pwd = input("What is the master password?: ")

#loading key and asking for fernet objects
##fernet object is created using the key loaded by the master password
key = load_key(master_pwd) 
fer = Fernet(key)

#function to view passwords
#This function reads the "passwords.txt" file line by line, splits each line into username and encrypted password, decrypts the password using the Fernet object, and prints the username and decrypted password. It uses a try-except block to handle decryption errors.
def view():
    with open('passwords.txt', 'r') as f:
        for line in f.readlines():
            data = line.rstrip()
            user, passw = data.split(" | ")
            try:
                decrypted_pass = fer.decrypt(passw.encode()).decode()
                print("User_Name:", user, "| Password:", decrypted_pass)
            except cryptography.fernet.InvalidToken:
               print("Invalid password token detected. Please check the key and password input. ")
            except ValueError as e:
                print("Error decrypting password for: ", user, "-", e)


#function to add passwords
#This function prompts the user to input an account name and password. It encrypts the password using the Fernet object, appends the username and encrypted password to the "passwords.txt" file.
def add():
    name = input("Account Name: ")
    pwd = input("Password: ")
    encrypted_pwd = fer.encrypt(pwd.encode()).decode()
   
    with open('passwords.txt', 'a') as f:
        f.write(name + " | " + encrypted_pwd + "\n")


#The main program loop
#the loop repeatedly prompts the user to to choose between (view, add, )and calls corresponding function based on users choice
while True:
    mode = input("would you like to add anew password or view existing passwords (view, add)? press Q to quit : ").lower()
    if mode == "q":
        break

    if mode == "view":
        view()
    elif mode == "add":
        add()
    else:
        print("Invalid mode:")
        continue
