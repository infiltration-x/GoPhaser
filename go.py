from cryptography.fernet import Fernet
import base64 
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def generate_key():

    password = input("Enter password: ") 
    password = password.encode()
    salt = input("Enter salt: ")
    salt = salt.encode()
    kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key


def enphase_t():

    input_file = input("Enter file to be phased: ")
    output_file = input("Enter desired name of output file: ")

    with open(input_file, 'rb') as f:
        data = f.read()

    key = generate_key()
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data)

    array64 = list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+=-_")
    
    ciph = input("Enter covering file: ")
    ciph = "C:\\Users\\hp\\Pictures\\GoPhaser\\ciphers\\" + ciph

    with open(ciph) as ciph:
        cipherArray = ciph.readlines()

    with open(output_file, 'w+') as f:
        for char2 in encrypted:
            char = chr(char2)
            if char != '\n':
                f.write(cipherArray[array64.index(char)])


def dephase_t():

    input_file = input("Enter file to be dephased ")
    output_file = input("Enter desired name of output file ")

    array64 = list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+=-_")

    with open(input_file) as file:
        coveredfile = file.readlines()

    ciph = input("Enter the cover to be removed ")
    ciph = "C:\\Users\\hp\\Pictures\\GoPhaser\\ciphers\\" + ciph

    with open(ciph) as file:
        cipher = file.readlines()

    enc = ""
    for word in coveredfile:
        enc += array64[cipher.index(word)]

    enc = enc.encode()
    key = generate_key()
    fernet = Fernet(key)
    decrypted = fernet.decrypt(enc)

    with open(output_file, "wb") as f:
        f.write(decrypted)

def browse():

    l = os.listdir("C:\\Users\\hp\\Pictures\\GoPhaser\\ciphers\\")
    for i in l:
        print(i)

    ciph = input("Enter cipher file name ")
    ciph = "C:\\Users\\hp\\Pictures\\GoPhaser\\ciphers\\" + ciph

    with open(ciph) as file:
        coveredfile = file.readlines()

    x = 0
    print()
    for i in coveredfile:
        if x < 10:
            print(i)
            x = x + 1

def helping():

    print("WHAT IT DOES :")
    print("GoPhaser transforms any filetype (e.g. .zip, .exe, .xls, etc.) into")
    print("a list of harmless-looking strings. This lets you hide the file in plain sight,")
    print("and transfer the file without triggering alerts.")
    print("For example, you can transform a .zip file into a list made of Pokemon creatures")
    print("or Top 100 Websites. You then transfer the cloaked phased however you choose,")
    print("and then dephase the exfiltrated file back into its original form. The ciphers")
    print("are designed to appear like harmless / ignorable lists, though some (like MD5")
    print("password hashes) are specifically meant as distracting bait.")

if __name__ == "__main__":

    print()
    print()

    print("  ____       ____  _")
    print(" / ___| ___ |  _ \| |__   __ _ ___  ___ _ __")
    print("| |  _ / _ \| |_) | '_ \ / _` / __|/ _ \ '__|")
    print("| |_| | (_) |  __/| | | | (_| \__ \  __/ |")
    print(" \____|\___/|_|   |_| |_|\__,_|___/\___|_|")

    print()
    print()

    print("1. Simple Encryption ")
    print("2. Text Steganography ")
    print("Enter your choice: ")

    c = int(input())

    if c == 1 :

        print()
        print("1. Encrypt ")
        print("2. Decrypt")
        k = int(input())
        if k == 1:

            print()
            str = input("Enter message to be encrypted: ")
            str = str.encode()
            key = generate_key()
            fernet = Fernet(key)
            enc_str = fernet.encrypt(str)
            enc_str = enc_str.decode()
            print("Encrypted message : ", enc_str)

        elif k == 2:
            
            print()
            str_enc = input("Enter message to be decrypted: ")
            str_enc = str_enc.encode()
            key = generate_key()
            fernet = Fernet(key)
            str = fernet.decrypt(str_enc)
            str = str.decode()
            print("Decrypted message ", str)

    elif c == 2 :

        print()
        print("1. Enphase ")
        print("2. Dephase ")
        print("3. Browse Ciphers ")
        print("4. Help ")
        print("5. Quit")
        print()
        st = int(input("Enter your choice: "))
        if st == 1:
            enphase_t()
        elif st == 2:
            dephase_t()
        elif st == 3:
            browse()
        elif st == 4:
            helping()
        elif st == 5:
            print()
            print("GoodBye!!!")
        else:
            print("Wrong choice: ")

    else :
        print("Wrong choice: ")










  
