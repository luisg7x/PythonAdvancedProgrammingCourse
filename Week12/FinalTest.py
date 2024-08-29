import base64
from secrets import token_bytes
from pyotp import TOTP
# !!!!! username: user1234 | password: 1234

# User database 
users = {}

def generate_2fa_secret():
    secret_key = token_bytes(16)
    encoded = base64.b32encode(secret_key).decode()
    return encoded

def register_user(username, email):
    if username in users:
        print("Username already exists")
        return
    
    user_data = {
        "email": email,
        "secret": generate_2fa_secret(),
        "login_attempts": 0
    }
    
    users[username] = user_data
    print(f"User {username} registered successfully")

def login_user(username, password):
    if username not in users:
        print("Username not found")
        return
    
    user_data = users[username]
    
    # Simulate API call to check password 
    if password == "1234":
        # 2FA required
        print("Password correct. 2FA enabled.")
        
        # Generate time-based one-time password
        totp = TOTP(user_data["secret"])
        code = totp.now()
        
        print(f"Your 2FA code is: {code}")
        
        # Simulate user entering the 2FA code
        user_input = input("Enter your 2FA code: ")
        
        if user_input == code:
            print("2FA successful. Login granted.")
        else:
            user_data["login_attempts"] += 1
            print(f"2FA failed. {user_data['login_attempts']} attempts remaining.")
            
    else:
        # Incorrect password
        print("Incorrect password")
        
if __name__ == "__main__":
    
    register_user("user1234", "user1234@email.com")
    
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    
    login_user(username, password)