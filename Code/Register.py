import hashlib
import getpass

def hash_password(password):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(password.encode('utf-8'))  
    return sha256_hash.hexdigest()  

def hash_pin(pin):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(pin.encode('utf-8'))
    return sha256_hash.hexdigest()  # Hash the PIN

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

def is_username_taken(username):
    # Check if the username already exists in the UserInfo.txt file
    try:
        with open("UserInfo.txt", "r") as file:
            lines = file.readlines()
            for line in lines:
                if line.startswith(f"Username: {username}"):
                    return True
    except FileNotFoundError:
        return False  # If the file doesn't exist, the username is not taken
    return False

def register_user():
    username = input("Enter your username: ")
    
    # Check if the username already exists
    if is_username_taken(username):
        print("This username is already exist. Please choose another username.")
        return  # Exit the registration process if username is already taken
    
    while True:
        password = getpass.getpass("Enter your password: ")  
        if not validate_password(password):
            print("Password is not strong enough. Try again.")
        else:
            break
    while True:
        confirm_password = getpass.getpass("Confirm your password: ")
        if password != confirm_password:
            print("Passwords do not match. Please try again.")
        else:
            break 
        
    while True:
        pin = getpass.getpass("Enter your 4-digit secret PIN: ")  # Use getpass for PIN
        if not validate_pin(pin):
            print("Invalid PIN. Please enter a 4-digit number.")
        else:
            break 
    
    # Hash both password and PIN
    hashed_password = hash_password(password)
    hashed_pin = hash_pin(pin)
    
    with open("UserInfo.txt", "a") as file:
        file.write(f"Username: {username}\n")
        file.write(f"Password (hashed): {hashed_password}\n")
        file.write(f"Secret PIN (hashed): {hashed_pin}\n")
        file.write("\n")
    
    print("Registration successful!")

register_user()
