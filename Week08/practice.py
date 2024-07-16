import os
import subprocess
import re
import ipaddress

#Printing the OS name
print("The OS is " + os.name)

#Printing the file current location or directory
print("The current file's directory is " + os.getcwd())

#Setting a spficifc path
specific_path = "C:/"

#setting the content of the path to a variable
content = os.listdir(specific_path)

#printing the content and specific path
print("The path " + specific_path + " has this content: ", content)

#path of a file to be checked
check_file_path = "C:/Windows"

#checking if the path exists
if os.path.exists(check_file_path):
    print("Exist! - The file in: " + check_file_path)
else:
    print("Does not exist! - The file in: " + check_file_path)

#getting the network's interfaces
output = subprocess.run(["netsh","wlan","show","interfaces"], capture_output=True, text=True).stdout

#printing the output
print(output)

try:
        #run the ipconfig command and capture the output
        result = subprocess.check_output(['ipconfig'], universal_newlines=True)

        #using regular expressions to find the ipv4 address, subnet mask and gateway
        ip_pattern = r'IPv4 Address[ .]+: ([\d.]+)'
        subnet_pattern = r'Subnet Mask[ .]+: ([\d.]+)'
        gateway_pattern = r'Default Gateway[ .]+: ([\d.]+)'

        #getting the
        ip_match = re.search(ip_pattern, result)
        subnet_match = re.search(subnet_pattern, result)
        gateway_match = re.search(gateway_pattern, result)

        #checking if they have a value
        if ip_match and subnet_match and gateway_match:
            ip_address = ip_match.group(1)
            subnet_mask = subnet_match.group(1)
            default_gateway = gateway_match.group(1)

            print(f"IPv4 Address: {ip_address}")
            print(f"Subnet Mask: {subnet_mask}")
            print(f"Default Gateway: {default_gateway}")

            #convert strings to IPv4Address objects
            ip_address = ipaddress.IPv4Address(ip_address)
            subnet_mask = ipaddress.IPv4Address(subnet_mask)
            
            #calculate the network address
            network_address = ipaddress.IPv4Network(f"{ip_address}/{subnet_mask}", strict=False).network_address
            print(f"Network Address: {network_address}")

            #calculate the broadcast address
            broadcast_address = ipaddress.IPv4Network(f"{ip_address}/{subnet_mask}", strict=False).broadcast_address
            print(f"Broadcast Address: {broadcast_address}")

            #calculate the usable host range
            first_usable_host = network_address + 1
            last_usable_host = broadcast_address - 1
            print(f"Usable Host Range: {first_usable_host} - {last_usable_host}")

            network = ipaddress.IPv4Network(f"{network_address}/{subnet_mask}", strict=False)
            #checking for every ip address is it whether it is avaible or not
            for ip in network.hosts():
                ip_str = str(ip)
                result = subprocess.call(['ping', '-n', '1', ip_str], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if result == 0:
                    print(f"{ip_str} is up")
                else:
                    print(f"{ip_str} is down")

        else:
            print("Unable to extract IP address or subnet mask or default gateway.")

except (subprocess.CalledProcessError, ipaddress.AddressValueError) as e:
    print(f"Error: {e}")
