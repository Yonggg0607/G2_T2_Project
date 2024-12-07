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
    return sha256_hash.hexdigest()


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
    print("\n=== User Registration ===")
    while True:
        username = input("Enter your username: ").strip()
        if is_username_taken(username):
            print("This username already exists. Please choose another username.")
        else:
            break

    attempts = 0
    while attempts < 3:
        password = getpass.getpass("Enter your password: ")
        if not validate_password(password):
            print("Password is not strong enough. Try again.")
            attempts += 1
        else:
            break

    if attempts == 3:
        print("You have failed to provide a valid password 3 times.")
        print("!Warning: Auto-Generate password cannot be changed!!!")
        choice = input("Do you want to (1) auto-generate a random password or (2) continue typing your own password? Enter 1 or 2: ")

        if choice == '1':
            password = generate_random_password()
            print(f"Your new password is: {password}")
        else:
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

    while True:
        confirm_password = getpass.getpass("Confirm your password: ")
        if password != confirm_password:
            print("Passwords do not match. Please try again.")
        else:
            break

    while True:
        pin = getpass.getpass("Enter your 4-digit secret PIN: ")
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


def login_user():
    print("\n=== User Login ===")
    username = input("Enter your username: ").strip()
    user_found = False

    try:
        with open("UserInfo.txt", "r") as file:
            lines = file.readlines()
            for line in lines:
                if line.startswith(f"Username: {username}"):
                    user_found = True
                    break
    except FileNotFoundError:
        print("No user data found. Please register first.")
        return

    if not user_found:
        print("Username does not exist. Please register first.")
        return

    attempts = 0
    max_attempts = 3
    password_matched = False

    while attempts < max_attempts:
        password = getpass.getpass("Enter your password: ")
        hashed_input_password = hash_password(password)

        with open("UserInfo.txt", "r") as file:
            user_data = file.read()

        if f"Username: {username}\nPassword (hashed): {hashed_input_password}" in user_data:
            password_matched = True
            break

        print("Incorrect password. Please try again.")
        attempts += 1

    if not password_matched:
        print("You have entered the wrong password 3 times.")
        reset_choice = input("Do you want to reset your password? (yes/no): ").strip().lower()

        if reset_choice == "yes":
            reset_password(username)
            return
        elif reset_choice == "no":
            print("You may attempt to enter your password 3 more times.")
            attempts = 0
            while attempts < max_attempts:
                password = getpass.getpass("Enter your password: ")
                hashed_input_password = hash_password(password)

                if f"Username: {username}\nPassword (hashed): {hashed_input_password}" in user_data:
                    password_matched = True
                    break

                print("Incorrect password. Please try again.")
                attempts += 1

            if not password_matched:
                print("Too many failed attempts. Your account has been blocked.")
                block_user(username)
                return
        else:
            print("Invalid choice. Exiting.")
            return

    print(f"Welcome back, {username}!")


def reset_password(username):
    print("\n=== Reset Password ===")
    while True:
        new_password = getpass.getpass("Enter your new password: ")
        if validate_password(new_password):
            confirm_password = getpass.getpass("Confirm your new password: ")
            if new_password == confirm_password:
                hashed_password = hash_password(new_password)
                with open("UserInfo.txt", "r") as file:
                    lines = file.readlines()
                with open("UserInfo.txt", "w") as file:
                    for line in lines:
                        if line.startswith(f"Username: {username}"):
                            file.write(line)
                            file.write(f"Password (hashed): {hashed_password}\n")
                        elif not line.startswith("Password (hashed):"):
                            file.write(line)
                print("Password reset successfully.")
                return
            else:
                print("Passwords do not match. Try again.")
        else:
            print("Invalid password. Follow the requirements.")


def block_user(username):
    print(f"User {username} has been blocked due to multiple failed login attempts.")
    # Additional logic can be added to log this information or notify an admin.


def main():
    while True:
        print("\n1. Register\n2. Login\n3. Exit")
        choice = input("Enter your choice: ")
        if choice == "1":
            register_user()
        elif choice == "2":
            login_user()
        elif choice == "3":
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
