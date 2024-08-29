import time

attempts = 0
lock_time = 60  # Initial lock time in seconds

def check_password(password):
    global attempts, lock_time
    
    start = time.time()
    
    if password == "pass1234":
        reset_attempts()
        return True
        
    attempts += 1
            
    current_lock_time = get_lock_time()
            
    if attempts >= 5 and current_lock_time < 300:
        print("Too many login attempts detected. Locked for 5 minutes.")
        lock_for(current_lock_time)
        
    elif attempts >= 10 and current_lock_time < 900:
        print("Too many login attempts detected. Locked for 15 minutes.")  
        lock_for(current_lock_time)  
          
    elif attempts >= 15 and current_lock_time < 1800:
        print("Too many login attempts detected. Locked for 30 minutes.")
        lock_for(current_lock_time)
            
def reset_attempts():
    global attempts, lock_time
    attempts = 0
    
def get_lock_time():
    return int(lock_time * (2 ** ((attempts - 1) // 5)))

def lock_for(time_in_seconds):
    print(f"Locked for {time_in_seconds / 60} minutes")
    time.sleep(time_in_seconds)

start = time.time()
    
while True:
    password = input("Enter your password: ")
      
    if check_password(password): 
        print("Login successful!")
        break