import nmap
from scapy.all import ICMP, IP, TCP, UDP, sr1, RandShort, sniff 
import os
import requests
from Wappalyzer import Wappalyzer, WebPage
import smtplib
import datetime
import subprocess 
from fpdf import FPDF
import re
import time
from inotify_simple import INotify, flags
import pyshark

#Variables that will feed the script
subnet = "192.168.1"
config_file = "/home/user/.ssh/config"
website_url = "https://www.una.ac.cr/"
email_To = "email@example.com"
log_files = ["/var/log/auth.log", "/var/log/messages", "/var/log/audit/audit.log"]
sniff_config = {
    'display_filter': 'tcp port == 80'
}
try:
    packets = pyshark.LiveCapture(interface='eth0', **sniff_config)
except Exception as e:
    print(f"Error during execution, pyshark.LiveCapture: {str(e)}")


suspicious_ips = [
    "192.168.1.100",
    "10.0.0.50",
    "172.16.31.200",
    "127.0.0.2", 
    "23.228.128.186",
    "52.87.163.243"
]

trusted_ips = [
    "192.168.1.10",
    "10.0.0.20",
    "172.16.31.100",  
    "8.8.4.4", 
    "127.0.0.1", 
    "23.228.128.184",
    "52.87.163.242"
]
# Combined list of suspicius ip
suspicious_ip_from_monitor_callback_and_network_log = []

# Will storage the reports during execution
reports = {}

# Function to append a value to an existing dictionary key or create a new key-value pair
def add_value_to_dict(my_dict, key, value):
    # Check if the key already exists in the dictionary
    if key in my_dict:
        # If it does, append the new value to the list associated with that key
        my_dict[key].append(value)
    else:
        # If not, create a new key-value pair with a list containing only the given value
        my_dict[key] = [value]

class Generate_alerts:
    #USED
    def send_email_alert(self, to, subject, message):
        try:
            from_email = "your_email@example.com"
            password = "your_passwond"
            server = smtplib.SMTP('smtp.example.com', 587)
            server.starttls()
            server.login(from_email, password)

            msg = f"Subject: {subject}\n\n{message}"
            server.sendmail(from_email, to, msg)
            server.quit()

            print("Email sent successfully!")
        except Exception as e:
            print(f"Error sending email: {str(e)}")

#USED    
class PrintPDF(FPDF):
    def header(self):
        """Set the report title in the header of each page"""
        # Set font, make it bold and size 12
        self.set_font("Arial", "B", 12)  
        # Create a cell with the text centered horizontally
        self.cell(0, 10, "Print Report", 0, 1, "C")
        
    def footer(self):
        """Set the page number in the footer of each page""" 
        # Move cursor to bottom of page (15 mm from bottom)
        self.set_y(-15)  
        # Set font for footer text
        self.set_font("Arial", "I", 8)  
        # Create a cell with the current page number, centered horizontally
        self.cell(0, 10, "Page %s" % self.page_no(), 0, 0, "C")
        
    def add_print(self, text):
        """Add some text to the PDF at the default y-position"""
        # Set font size (12)  
        self.set_font("Arial", size=12)
        # Create a multi-cell with the provided text, spanning the full width, height 10mm, left-aligned
        self.multi_cell(0, 10, txt=text, align="L")

class Generate_reports:
    #USED
    def generate_report(self):
        try:
            # Initialize a new PrintPDF object to generate the report
            pdf = PrintPDF()
            
            # Get the current date and time as a timestamp string 
            now = datetime.datetime.now()  
            timestamp = now.strftime("%d_%m_%Y_%H_%M_%S")
            
            # Keep track of the previous key to detect when it changes
            current_key = None
            
            # Iterate over each key-value pair in the reports dictionary
            for key, value_list in reports.items():
                if key != current_key:
                    # If this is a new key, start a new page
                    current_key = key  
                    pdf.add_page()
                    
                # Print all values associated with the current key
                for value in value_list:   
                    pdf.add_print(value)
                    
            # Save the PDF report to disk with the timestamp filename 
            pdf.output("Report_" + timestamp + ".pdf")
            
            print("PDF report generated successfully!")
            
        except Exception as e:
            # Catch and display any exceptions that occur during generation
            print(f"Error generating PDF report: {str(e)}")

class Network_monitor:
    #NO USED #192.168.1.1/21
    def scan_network(self, network):
        """
        Performs a network scan on the specified IP address or range.

        Args:
            network (str): The IP address or range to be scanned.
        """

        # Create an Nmap scanner object
        scanner = nmap.PortScanner()

        # Perform the network scan
        print(f"Scanning the network {network}...")
        try:
            # Use the '-sn' argument for a simple ping sweep
            scanner.scan(hosts=network, arguments='-sn')
        except nmap.nmap.PortScanningError as e:
            # Handle any errors that occur during scanning
            print(f"Error scanning the network: {e}")
            return

        # Get the scan results
        hosts_list = [(x, scanner[x]) for x in scanner.all_hosts()]

        # Print the scan results
        print(f"Scan results for network {network}:")
        for host, scan_result in hosts_list:
            if scan_result.state() == 'up':
                print(f"Host: {host}")
                print(f"State: {scan_result.state()}")
                print("Open Ports:")
                for proto in scan_result[host].all_protocols():
                    # Get the list of open ports
                    lport = scan_result[host][proto].keys()
                    print(f"  Protocol: {proto}")
                    for port in lport:
                        # Print the details of each open port
                        print(f"    Port: {port} - State: {scan_result[host][proto][port]['state']} - Service: {scan_result[host][proto][port]['name']}")
            else:
                print(f"Host: {host} - State: {scan_result.state()}")
    
    #USED #192.168.1
    def ping_sweep(self, target_subnet) :
        live_hosts = []
        try:
            for host in range(1, 255):
                # Construct the full IP address by appending the current host number
                target_ip = target_subnet + "." + str(host)
                # Create an ICMP echo request packet to send a ping
                packet = IP(dst=target_ip)/ICMP()
                # Send the ping and wait for a response with a timeout of 1 second
                response = sr1(packet, timeout=1, verbose=0)
                # If a response is received, the host is considered live
                if response is not None:
                    print(f" {target_ip} está vivo.")
                    live_hosts.append(target_ip)
                else:
                    print(f" {target_ip} está muerto o no responde a pings.")
            # Return the list of IP addresses of live hosts discovered in the subnet
            return live_hosts
        except Exception as e:
            print(f"Error executing ping_sweep: {str(e)}")
        #print(f"\nHosts vivos en la subred {target_subnet} :") 
        #for host in live_hosts:
            #print(host)

    #USED #("192.168.50.1", range(1,1024)
    def port_scan(self, host, port_range):
        try:
            for dst_port in port_range:
                src_port = RandShort()
                packet = IP(dst=host)/TCP(sport=src_port, dport=dst_port, flags="S")
                response = sr1(packet, timeout=2, verbose=0)
                if response is not None:
                    if response[TCP].flags == "SA":
                        print("Port " + str(dst_port) + " is open")
        except Exception as e:
            print(f"Error during port scan: {str(e)}")
        # You can log the error or take other appropriate actions here

    #USED #sniff(prn=nm.monitor_callback, filter="ip", store=0)           
    def monitor_callback(self, pkt):
        key = "monitor_callback"  # Key for storing report in the reports dictionary
        generate_alerts = Generate_alerts()  # Instance of the alert generation class
        
        try:
            # Check if the packet has an IP layer
            if pkt.haslayer(IP):
                # Iterate over each suspicious IP address
                for host in suspicious_ips:
                    # Compare the source IP of the packet with the suspicious IP
                    if pkt[IP].src == host:
                        # Add the suspicious IP to the log list
                        suspicious_ip_from_monitor_callback_and_network_log.append(host)
                        
                        # Print a message indicating suspicious activity
                        print("Suspicious traffic detected from: " + pkt[IP].src)
                        
                        # Generate and send an email alert
                        generate_alerts.send_email_alert(email_To, "Suspicious traffic detected", f"Suspicious traffic detected from: {pkt[IP].src}")
                        
                        # Add a report entry to the dictionary
                        add_value_to_dict(reports, key, "Suspicious traffic detected from: " + pkt[IP].src)
        
        except Exception as e:
            # Catch and display any exceptions that occur during processing
            print(f"Error executing monitor_callback: {str(e)}")

class Logs_analysis:
    #USED #suspictious ips list
    def network_log_check(self):
        key = "network_log_check"
        generate_alerts = Generate_alerts()
        try:
            # Capture network traffic using Tcpdump command
            command = "tcpdump -i eth0 -n -vv -s 0 -c 100"
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)

            while True:
                output = process.stdout.read()
                
                # Parse the captured packets
                for line in output.decode().splitlines():
                    # Check for specific patterns or conditions in each packet
                    if "SYN" in line and any(ip in line for ip in suspicious_ips):
                        print("Potential SYN flood attack detected!")

                        # Add the IP to the guilty_ips list
                        suspected_ip = next((ip for ip in suspicious_ips if ip in line), None)
                        if suspected_ip:
                            suspicious_ip_from_monitor_callback_and_network_log.append(suspected_ip)
                            generate_alerts.send_email_alert(email_To, "Potential SYN flood attack detected", f"Potential SYN flood attack detected from: " + suspected_ip)
                            add_value_to_dict(reports, key, "Potential SYN flood attack detected from: " + suspected_ip)
                    
                    elif "ACK" not in line and "GET /index.php HTTP/1.1" in line:
                        print("Possible GET request without ACK flag!")
                        generate_alerts.send_email_alert(email_To, "Possible GET request without ACK flag!", f"Possible GET request without ACK flag!")
                        add_value_to_dict(reports, key, "Possible GET request without ACK flag!")

            # Terminate the Tcpdump process
            process.kill()
        except Exception as e:
            print(f"Error executing network_log_check: {str(e)}")
    
    #USED
    def log_check(self, log_file_path):
        key = "log_check"
        generate_alerts = Generate_alerts()
        try:
            # Load log files into a list
            with open(log_file_path, "r") as file:
                logs = file.readlines()

            # Define patterns to match suspicious activity
            login_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} - - \[.*\] \"GET /login HTTP/1.1\"")
            access_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} - - \[.*\] \"GET \/root HTTP\/1.1\"")

            # Iterate over logs and check for matches
            for log in logs:
                if login_pattern.match(log):
                    print("Suspicious login attempt detected!")
                    generate_alerts.send_email_alert(email_To, "Suspicious login attempt detected!", f"Suspicious login attempt detected in the machine, {log}")
                    add_value_to_dict(reports, key, "Suspicious login attempt detected!")
                
                elif access_pattern.match(log):
                    print("Unauthorized access to root directory detected!")
                    generate_alerts.send_email_alert(email_To, "Unauthorized access to root directory detected!", f"Unauthorized access to root directory detected in the machine, {log}" )
                    add_value_to_dict(reports, key, "Unauthorized access to root directory detected!")
        except Exception as e:
            print(f"Error executing log_check: {str(e)}")

class Vulnerabilities_detection:    
    #NO USED
    def linux_behaviour_check(self):
        try:
            # Create an instance of the INotify class
            notifier = INotify()

            # Watch for modifications to a specific directory
            mask = flags.CLOSE_WRITE | flags.MODIFY
            directory = "/path/to/watch"

            # Add watch event
            watch_event = notifier.add_watch(directory, mask)

            while True:
                events = notifier.read_events()
                
                # Process the file events
                for event in events:
                    path = event.pathname
                    
                    # Check if a file was modified or created
                    if flags.MODIFY in event.mask:
                        print(f"File {path} has been modified!")
                    
                    elif flags.CLOSE_WRITE in event.mask:
                        print(f"File {path} has been closed and written to!")

                time.sleep(1)

        except Exception as e:
            print(f"Error executing linux_behaviour_check: {str(e)}")

    #USED #path "/home/user/.ssh/config"
    def analyze_linux_ssh_config(file_path):
        # Initialize variables for tracking findings
        weak_passwords = []
        insecure_ciphers = []
        
        try:
            with open(file_path, "r") as file:
                lines = file.readlines()
                
            # Iterate over each line in the configuration file
            for line in lines:
                # Skip commented lines
                if "#" not in line:
                    key_value_pair = line.strip().split(" ")
                    
                    # Check if the line contains exactly two values (key and value)
                    if len(key_value_pair) == 2:
                        key, value = key_value_pair
                        
                        # Check for password authentication setting
                        if key.lower() == "passwordauthentication":
                            if value.lower() == "yes":
                                weak_passwords.append(line)
                                
                        # Check for insecure ciphers
                        elif key.lower() == "cipher":
                            if "3des" in value.lower():
                                insecure_ciphers.append(line)
                        
            # Log and report weak passwords found
            print("Weak passwords found:")
            for password in weak_passwords:
                print(password, end="")
                add_value_to_dict(reports, "linux_analyze_ssh_config", f"Weak passwords found: {password}")
                
            # Log and report insecure ciphers found
            print("\nInsecure ciphers found:")  
            for cipher in insecure_ciphers:
                print(cipher, end="")
                add_value_to_dict(reports, "linux_analyze_ssh_config", f"Insecure ciphers found: {cipher}")
                
        except Exception as e:
            print(f"Error executing analyze_linux_ssh_config: {str(e)}")

    #USED #192.168.50.1 
    def scan_host(self, host):
        key = "scan_host"
        try:
            # Send TCP SYN packets to port 80 (HTTP)
            tcp_packet = IP(dst=host)/TCP(dport=80, flags="S")
            response = sr1(tcp_packet, timeout=1, verbose=0)

            if response:
                print(f"{host} is vulnerable to TCP SYN flooding")
                add_value_to_dict(reports, key, f"{host} is vulnerable to TCP SYN flooding")

            # Send UDP packets to port 53 (DNS)
            udp_packet = IP(dst=host)/UDP(dport=53)
            response = sr1(udp_packet, timeout=1, verbose=0)

            if response:
                print(f"{host} is vulnerable to UDP flood attacks")
                add_value_to_dict(reports, key, f"{host} is vulnerable to UDP flood attacks")

            # Send ICMP echo request
            icmp_packet = IP(dst=host)/ICMP()
            response = sr1(icmp_packet, timeout=1, verbose=0)

            if not response:
                print(f"{host} dropped the ICMP echo request")
                add_value_to_dict(reports, key, f"{host} dropped the ICMP echo request")
        except Exception as e:
                print(f"Error executing scan_host: {str(e)}")

class Attack_prevention:
    #USED #block suspicious ip: 192.168.50.1
    def block_ip(self, ip_address):
        try:
            key = "block_ip"
            # Execute command to block the ip
            os.system("sudo iptables -A INPUT -s {} -j DROP".format(ip_address))
            add_value_to_dict(reports, key, f"{ip_address} has been blocked")
        except Exception as e:
                print(f"Error executing block_ip: {str(e)}")

    #NO USED #sniff(prn=ap.filter_packet, filter="tcp")
    def filter_packet_version_1(pkt):      
        #pkt.haslayer(TCP) and pkt.getlayer(TCP).dport == 80:
           #print("\n{}: {}:{}".format(pkt.getlayer(IP).src, pkt.getlayer(IP).dst, pkt.getlayer(TCP).dport))
           print("filter_packet_version_1 is not being used")

    #USED sniff(prn=ap.filter_packet, filter="tcp")
    def filter_packet(self, pkt):
        key = "filter_packet"
        generate_alerts = Generate_alerts()
        guilty_ips = []
        try:
            if pkt.haslayer(TCP) and pkt.getlayer(TCP).dport == 80:
                src_ip = pkt.getlayer(IP).src
                dst_ip = pkt.getlayer(IP).dst
                dport = pkt.getlayer(TCP).dport
                
                # Check for a single IP address making a high volume of requests
                if src_ip in suspicious_ips and dport == 80:
                    guilty_ips.append(src_ip)
                    print(f"High volume requests from {src_ip}")
                    generate_alerts.send_email_alert(email_To, "High volume requests detected", f"High volume requests from {src_ip}")
                    add_value_to_dict(reports, key, f"High volume requests from {src_ip}")
                    
                # Check for requests coming from unexpected or unfamiliar sources
                elif src_ip not in trusted_ips and dport == 80:
                    guilty_ips.append(src_ip)
                    print(f"Request from unknown source: {src_ip}")
                    generate_alerts.send_email_alert(email_To, "Request from unknown source", f"Request from unknown source from {src_ip}")
                    add_value_to_dict(reports, key, f"Request from unknown source from {src_ip}")
                    
                # Check for malformed or unusual HTTP requests
                if "Host:" not in pkt.sprintf("%IP.host%") and dport == 80:
                    print("Malformed request")
                    generate_alerts.send_email_alert(email_To, "Malformed request", f"Malformed request")
                    add_value_to_dict(reports, key, f"Malformed request")
                
                elif len(pkt.getlayer(TCP).payload) < 100 and dport == 80:
                    print("Short payload request")
                    generate_alerts.send_email_alert(email_To, "Short payload reques", f"Short payload request")
                    add_value_to_dict(reports, key, f"Short payload request")
                    
                else:
                    print(f"{src_ip}: {dst_ip}:{dport}")
                
                return guilty_ips
        except Exception as e:
            print(f"Error executing filter_packet: {str(e)}")

class Traffic_anaysis:
    #USED #https://www.una.ac.cr/
    def web_traffic_sqli_analisys(self, url):
        key = "web_traffic_sqli_analisys"
        generate_alerts = Generate_alerts()
        try:
            # Sniff packets and analyze them
            for packet in packets.sniff_continuously():
                if 'Host' in packet and url in packet['Host']:
                    http_data = packet.get('http')

                    if http_data:
                        # Check for SQL injection patterns
                        sql_injection_patterns = ['UNION', 'SELECT', 'FROM', 'WHERE', 'LIMIT', "admin' --", "admin' /*", "admin'or '1'='1", "admin' or '1'='1' --", "admin' or'1'='1' /*"]
                        for pattern in sql_injection_patterns:
                            if pattern.upper() in http_data['data']:
                                print(f"Potential SQL injection attempt detected: {http_data['request']}")
                                generate_alerts.send_email_alert(email_To, "Potential SQL injection attempt detected", f"Potential SQL injection attempt detected: {http_data['request']}")
                                add_value_to_dict(reports, key, f"Potential SQL injection attempt detected: {http_data['request']}")


                        # Check for XSS attack patterns
                        xss_patterns = ['<script>', '</script>', 'javascript:', 'onload=', 'onerror=']
                        for pattern in xss_patterns:
                            if pattern in http_data['data']:
                                print(f"Potential XSS attack detected: {http_data['request']}")
                                generate_alerts.send_email_alert(email_To, "Potential XSS attack detected", f"Potential XSS attack detected: {http_data['request']}")
                                add_value_to_dict(reports, key, f"Potential XSS attack detected: {http_data['request']}")
        except Exception as e:
            print(f"Error executing web_traffic_sqli_analisys: {str(e)}")
            
class Get_recommendations:
    #USED #https://www.una.ac.cr/
    def web_check_tools(self, url):
        key = "web_check"
        try:
            request = requests.get(url)
            #Instantiate Wappalyzer
            wappalyzer = Wappalyzer.latest()
            #Create a WebPage object from the URL
            webpage = WebPage.new_from_url(request.url)
            #Analyze the webpage with Wappalyzer
            analysis = wappalyzer.analyze_with_versions_and_categories(webpage)
            #Print all the technologies Wappalyzer found
            for number, (key, value) in enumerate(analysis.items(), start=1):
                add_value_to_dict(reports, key, f"Tecnology: {number} {key}: {value}")
                print(f"Tecnology: {number} {key}: ")
                print(value)
                print()
        except Exception as e:
            print(f"Error executing web_check_tools: {str(e)}")
        
def main():
    # Create instances of the relevant classes
    network_monitor = Network_monitor()
    logs_analysis = Logs_analysis()
    vuln_detection = Vulnerabilities_detection() 
    attack_prevention = Attack_prevention()
    traffic_analysis = Traffic_anaysis()
    generate_alerts = Generate_alerts()
    get_recommendations = Get_recommendations()
    generate_reports = Generate_reports()

    # Ask for any target subnet
    target_subnet = input ("Type any subnet: ")

    # If no subnet is provided, use the default 'subnet'
    if target_subnet is None: target_subnet = subnet
    # Perform a ping sweep on the target subnet to identify alive hosts
    host_alive = network_monitor.ping_sweep(target_subnet)

    # For each host found alive, perform port scans and vulnerability checks
    for host in host_alive:
        # Scan ports 1-1024 for open ports
        network_monitor.port_scan(host, range(1, 1024))
        # Check the host for vulnerabilities 
        vuln_detection.scan_host(host)
    
    # Sniff network traffic with an IP filter and store it in memory
    sniff(prn=network_monitor.monitor_callback, filter="ip", store=0) 

    # Analyze network logs for suspicious activity
    logs_analysis.network_log_check()

    # Identify suspicious IPs based on a TCP filter
    guilty_ips = sniff(prn=attack_prevention.filter_packet, filter="tcp")

    # Combine the list of guilty IPs with previously identified suspicious IPs
    combined_suspicious_ip_list = list(set(guilty_ips + suspicious_ip_from_monitor_callback_and_network_log))

    # Block the combined list of suspicious IPs
    for host in combined_suspicious_ip_list:
        attack_prevention.block_ip(host)

    # Send an email alert about blocked IPs
    generate_alerts.send_email_alert(email_To, "Se han bloqueado una lista de ip", f"Se han bloqueado las siguientes ip {', '.join(combined_suspicious_ip_list)}.")

    # Analize every log path
    for log_file in log_files:
        logs_analysis.analyze_log(log_file)

    # Analyze Linux SSH configuration for vulnerabilities 
    vuln_detection.linux_analyze_ssh_config(config_file)

    # Analyze web traffic for SQL injection attacks on the website URL
    traffic_analysis.web_traffic_sqli_analisys(website_url)
    
    # Perform web checks vulnerabilities of the tool on a specified website URL
    get_recommendations.web_check_tools(website_url) 

    # Generate a report of the security scan results
    generate_reports.generate_report()

if __name__ == "__main__":
    main()


    

