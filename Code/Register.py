import hashlib
import getpass
def validate_password(password):
    if len(password) < 6:
        print("Password should be at least 6 characters long.")
        return False
    if not any(char.isdigit() for char in password):
        print("Password should contain at least one digit.")
        return False
    if not any(char.isupper() for char in password):
        print("Password should contain at least one uppercase letter.")
        return False
    if not any(char.islower() for char in password):
        print("Password should contain at least one lowercase letter.")
        return False
    return True
def validate_pin(pin):
    if len(pin) != 4 or not pin.isdigit():
        print("PIN must be a 4-digit number.")
        return False
    return True
def hash_password(password):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(password.encode('utf-8'))  
    return sha256_hash.hexdigest()  
def register_user():
    username = input("Enter your username: ")
    while True:
        password = getpass.getpass("Enter your password: ")  
        confirm_password = getpass.getpass("Confirm your password: ")
        if password != confirm_password:
            print("Passwords do not match. Please try again.")
        elif not validate_password(password):
            print("Password is not strong enough. Try again.")
        else:
            break 
    while True:
        pin = input("Enter your 4-digit secret PIN: ")
        if not validate_pin(pin):
            print("Invalid PIN. Please enter a 4-digit number.")
        else:
            break 
    hashed_password = hash_password(password)
    with open("UserInfo.txt", "a") as file:
        file.write(f"Username: {username}\n")
        file.write(f"Password (hashed): {hashed_password}\n")
        file.write(f"Secret PIN: {pin}\n")
        file.write("\n")
    print("Registration successful!")
register_user()
