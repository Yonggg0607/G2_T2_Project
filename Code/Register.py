import hashlib
import getpass
import random
import string

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
    try:
        with open("UserInfo.txt", "r") as file:
            lines = file.readlines()
            for line in lines:
                if line.startswith(f"Username: {username}"):
                    return True
    except FileNotFoundError:
        return False  # If the file doesn't exist, the username is not taken
    return False

def generate_random_password(length=12):
    """Generate a random password with at least one uppercase letter, one digit, and one lowercase letter."""
    while True:
        password = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        if any(char.isdigit() for char in password) and any(char.isupper() for char in password) and any(char.islower() for char in password):
            return password

def register_user():
    while True:
        username = input("Enter your username: ")

        if is_username_taken(username):
            print("This username already exists. Please choose another username.")
        else:
            break  # Break the loop if username is available

    attempts = 0
    while attempts < 3:
        password = getpass.getpass("Enter your password: ")  
        if not validate_password(password):
            print("Password is not strong enough. Try again.")
            attempts += 1
        else:
            break
    
    if attempts == 3:
        # After 3 failed attempts, ask if they want to generate a password or continue typing
        print("You have failed to provide a valid password 3 times.")
        print("!Warning: Auto-Generate password cannot be changed!!!")
        choice = input("Do you want to (1) auto-generate a random password or (2) continue typing your own password? Enter 1 or 2: ")
        
        if choice == '1':
            # Generate a random password
            password = generate_random_password()
            print(f"Your new password is: {password}")
        elif choice == '2':
            # Allow them to try again
            print("You can continue typing your own password.")
            attempts = 0
            while attempts < 3: 
                password = getpass.getpass("Enter your password: ")  
                if not validate_password(password):
                    print("Password is not strong enough. Try again.")
                    attempts += 1
                else:
                    break
            if attempts == 3:
                print("You have failed to provide a valid password again. A random password will be generated for you.")
                password = generate_random_password()
                print(f"Your new password is: {password}")
        else:
            print("Invalid choice. A random password will be generated for you.")
            password = generate_random_password()
            print(f"Your new password is: {password}")

    # Confirm password
    while True:
        confirm_password = getpass.getpass("Confirm your password: ")
        if password != confirm_password:
            print("Passwords do not match. Please try again.")
            # Prompt the user to re-enter the original password if confirmation fails
            password = getpass.getpass("Enter your password: ")  
            continue
        break 

    while True:
        pin = getpass.getpass("Enter your 4-digit secret PIN: ")  # Use getpass for PIN
        if not validate_pin(pin):
            print("Invalid PIN. Please enter a 4-digit number.")
        else:
            break 

    hashed_password = hash_password(password)
    hashed_pin = hash_pin(pin)
    
    with open("UserInfo.txt", "a") as file:
        file.write(f"Username: {username}\n")
        file.write(f"Password (hashed): {hashed_password}\n")
        file.write(f"Secret PIN (hashed): {hashed_pin}\n")
        file.write("\n")
    
    print("Registration successful!")

register_user()
