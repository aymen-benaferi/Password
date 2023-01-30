import re
import hashlib


def check_password_strength(password):
    if len(password) < 8:
        return False
    if not re.search("[a-z]", password):
        return False
    if not re.search("[A-Z]", password):
        return False
    if not re.search("[0-9]", password):
        return False
    if not re.search("[!@#\$%\^&\*]", password):
        return False
    return True


while True:
    password = input("Choose a password: ")
    if check_password_strength(password):
        print("Password is valid.")
        break
    else:
        print("Password is not valid. Please try again.")


password_hash = hashlib.sha256(password.encode())
print("Encrypted password: ", password_hash.hexdigest())
