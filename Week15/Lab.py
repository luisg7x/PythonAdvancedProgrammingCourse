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

subnet = "192.168.1"
config_file = "/home/user/.ssh/config"
website_url = "https://www.una.ac.cr/"
email_To = "email@example.com"
log_files = ["/var/log/auth.log", "/var/log/messages", "/var/log/audit/audit.log"]
sniff_config = {
    'display_filter': 'tcp port == 80',
    'packet_count': 100,
}
packets = pyshark.LiveCapture(interface='eth0', **sniff_config)

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

suspicious_ip_from_monitor_callback_and_network_log = []

class Generate_alerts:
    #USED
    def send_email_alert(self, to, subject, message):
        from_email = "your_email@example.com"
        password = "your_passwond"
        server = smtplib.SMTP('smtp.example.com', 587)
        server.starttls()
        server.login(from_email, password)

        msg = f"Subject: {subject}\n\n{message}"
        server.sendmail(from_email, to, msg)
        server.quit()
    
class Generate_reports:
    def generate_report(self):
        now = datetime.datetime.now()
        timestamp = now.strftime("%d_%m_%Y_%H")
        
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size = 15)
        
        pdf.cell(200, 10, txt = f"Report generated on {timestamp}", ln = True, align = 'C')
        
        pdf.ln(10)
        
        for func in dir():
            if not func.startswith('__'):
                try:
                    result = eval(func)()
                except Exception as e:
                    result = str(e)
                    
                pdf.cell(200, 10, txt = f"Function: {func}\nResult:\n{result}", ln = True, align = 'L')
                
        pdf.output("Report_" + timestamp + ".pdf")

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
        for host in range(1, 255):
            target_ip = target_subnet + "." + str(host)
            packet = IP(dst=target_ip)/ICMP()
            response = sr1(packet, timeout=1, verbose=0)
            if response is not None:
                print(f" {target_ip} está vivo.")
                live_hosts.append(target_ip)
            else:
                print(f" {target_ip} está muerto o no responde a pings.")
        return live_hosts
        #print(f"\nHosts vivos en la subred {target_subnet} :") 
        #for host in live_hosts:
            #print(host)

    #USED #("192.168.50.1", range(1,1024)
    def port_scan(self, host, port_range):
        for dst_port in port_range:
            src_port = RandShort()
            packet = IP(dst=host)/TCP(sport=src_port, dport=dst_port, flags="S")
            response = sr1(packet, timeout=2, verbose=0)
            if response is not None:
                if response[TCP].flags == "SA":
                    print("Port " + str(dst_port) + " is open")

    #USED #sniff(prn=nm.monitor_callback, filter="ip", store=0)           
    def monitor_callback(self, pkt):
        generate_alerts = Generate_alerts()
        if pkt.haslayer(IP):
            for host in suspicious_ips:
                if pkt[IP].src == host:
                    suspicious_ip_from_monitor_callback_and_network_log.append(host)
                    print("Suspicious trafic detected from: " + pkt[IP].src)
                    generate_alerts.send_email_alert(email_To, "Suspicious trafic detected", f"Suspicious trafic detected from: " + pkt[IP].src)

class Logs_analysis:
    #USED #suspictious ips list
    def network_log_check(self):
        generate_alerts = Generate_alerts()
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
                
                elif "ACK" not in line and "GET /index.php HTTP/1.1" in line:
                    print("Possible GET request without ACK flag!")
                    generate_alerts.send_email_alert(email_To, "Possible GET request without ACK flag!", f"Possible GET request without ACK flag!")

        # Terminate the Tcpdump process
        process.kill()
    
    #USED
    def log_check(self, log_file_path):
        generate_alerts = Generate_alerts()
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
            
            elif access_pattern.match(log):
                print("Unauthorized access to root directory detected!")
                generate_alerts.send_email_alert(email_To, "Unauthorized access to root directory detected!", f"Unauthorized access to root directory detected in the machine, {log}" )

        # Parse timestamp format
        #timestamp_format = "%a %b %d %H:%M:%S %Y"
        #timestamp_regex = re.compile(r"\[(.*)\]")
        #for log in logs:
            #match = timestamp_regex.search(log)
            #if match:
                #timestamp = datetime.strptime(match.group(1), timestamp_format)
    
class Vulnerabilities_detection:
    #USED #https://www.una.ac.cr/
    def web_check(self, website):
        request = requests.get(website)
        #Instantiate Wappalyzer
        wappalyzer = Wappalyzer.latest()
        #Create a WebPage object from the URL
        webpage = WebPage.new_from_url(request.url)
        #Analyze the webpage with Wappalyzer
        analysis = wappalyzer.analyze_with_versions_and_categories(webpage)
        #Print all the technologies Wappalyzer found
        for number, (key, value) in enumerate(analysis.items(), start=1):
            print(f"Tecnology: {number} {key}: ")
            print(value)
            print()
    
    #NO USED
    def linux_behaviour_check(self):
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

    #USED #path "/home/user/.ssh/config"
    def linux_analyze_ssh_config(self, file_path):
            with open(file_path, "r") as file:
                lines = file.readlines()

            weak_passwords = []
            insecure_ciphers = []

            for line in lines:
                if "#" not in line:
                    key_value_pair = line.strip().split(" ")

                    if len(key_value_pair) == 2:
                        key, value = key_value_pair

                        if key.lower() == "passwordauthentication":
                            if value.lower() == "yes":
                                weak_passwords.append(line)

                        elif key.lower() == "cipher":
                            if "3des" in value.lower():
                                insecure_ciphers.append(line)

            print("Weak passwords found:")
            for password in weak_passwords:
                print(password, end="")

            print("\nInsecure ciphers found:")
            for cipher in insecure_ciphers:
                print(cipher, end="")

    #USED #192.168.50.1 
    def scan_host(self, host):
        # Send TCP SYN packets to port 80 (HTTP)
        tcp_packet = IP(dst=host)/TCP(dport=80, flags="S")
        response = sr1(tcp_packet, timeout=1, verbose=0)

        if response:
            print(f"{host} is vulnerable to TCP SYN flooding")

        # Send UDP packets to port 53 (DNS)
        udp_packet = IP(dst=host)/UDP(dport=53)
        response = sr1(udp_packet, timeout=1, verbose=0)

        if response:
            print(f"{host} is vulnerable to UDP flood attacks")

        # Send ICMP echo request
        icmp_packet = IP(dst=host)/ICMP()
        response = sr1(icmp_packet, timeout=1, verbose=0)

        if not response:
            print(f"{host} dropped the ICMP echo request")

class Attack_prevention:
    #USED #block suspicious ip: 192.168.50.1
    def block_ip(self, ip_address):
        os.system("sudo iptables -A INPUT -s {} -j DROP".format(ip_address))

    #sniff(prn=ap.filter_packet, filter="tcp")
    #def filter_packet(pkt):
        #if pkt.haslayer(TCP) and pkt.getlayer(TCP).dport == 80:
            #print("\n{}: {}:{}".format(pkt.getlayer(IP).src, pkt.getlayer(IP).dst, pkt.getlayer(TCP).dport))

    #USED sniff(prn=ap.filter_packet, filter="tcp")
    def filter_packet(self, pkt):
        generate_alerts = Generate_alerts()
        guilty_ips = []
        if pkt.haslayer(TCP) and pkt.getlayer(TCP).dport == 80:
            src_ip = pkt.getlayer(IP).src
            dst_ip = pkt.getlayer(IP).dst
            dport = pkt.getlayer(TCP).dport
            
            # Check for a single IP address making a high volume of requests
            if src_ip in suspicious_ips and dport == 80:
                guilty_ips.append(src_ip)
                print(f"High volume requests from {src_ip}")
                generate_alerts.send_email_alert(email_To, "High volume requests detected", f"High volume requests from {src_ip}")
                
            # Check for requests coming from unexpected or unfamiliar sources
            elif src_ip not in trusted_ips and dport == 80:
                guilty_ips.append(src_ip)
                print(f"Request from unknown source: {src_ip}")
                generate_alerts.send_email_alert(email_To, "Request from unknown source", f"Request from unknown source from {src_ip}")
                
            # Check for malformed or unusual HTTP requests
            if "Host:" not in pkt.sprintf("%IP.host%") and dport == 80:
                print("Malformed request")
                generate_alerts.send_email_alert(email_To, "Malformed request", f"Malformed request")
            
            elif len(pkt.getlayer(TCP).payload) < 100 and dport == 80:
                print("Short payload request")
                generate_alerts.send_email_alert(email_To, "Short payload reques", f"Short payload reques")
                
            else:
                print(f"{src_ip}: {dst_ip}:{dport}")
            
            return guilty_ips

class Traffic_anaysis:
    #USED #https://www.una.ac.cr/
    def web_traffic_sqli_analisys(self, url):
        generate_alerts = Generate_alerts()
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

                    # Check for XSS attack patterns
                    xss_patterns = ['<script>', '</script>', 'javascript:', 'onload=', 'onerror=']
                    for pattern in xss_patterns:
                        if pattern in http_data['data']:
                            print(f"Potential XSS attack detected: {http_data['request']}")
                            generate_alerts.send_email_alert(email_To, "Potential XSS attack detected", f"Potential XSS attack detected: {http_data['request']}")
            
class Get_recommendations:
    #!!!! USED #https://www.una.ac.cr/
    def get_recommended_tools(self, url):
        wappalyzer_api_url = "https://api.wappalyzer.com/v1/"
        params = {
            'url': url,
            'license': 'free',
            'limit': 10
        }
        
        response = requests.get(wappalyzer_api_url, params=params)
        data = response.json()
        
        recommended_tools = []
        for item in data['tools']:
            name = item['name']
            description = item['description']
            icon = item['icon']
            
            # Add tool to recommendations list
            recommended_tools.append({
                'name': name,
                'description': description,
                'icon': icon
            })
        
        return recommended_tools

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
    Vulnerabilities_detection.linux_analyze_ssh_config(config_file)
    # Perform web checks vulnerabilities on a specified website URL
    Vulnerabilities_detection.web_check(website_url)

    # Analyze web traffic for SQL injection attacks on the website URL
    traffic_analysis.web_traffic_sqli_analisys(website_url)
    
    # Get recommendations for security tools based on the website URL
    recommendations = get_recommendations.get_recommended_tools(website_url)
    for recommendation in recommendations:
        print(f"Tool: {recommendation['name']}")
        print(f"Description: {recommendation['description']}")
        print(f"Icon: {recommendation['icon']}")    

    # Generate a report of the security scan results
    generate_reports.generate_report()

if __name__ == "__main__":
    main()


    

