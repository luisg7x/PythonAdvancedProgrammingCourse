from fpdf import FPDF
import datetime
from scapy.all import ICMP, IP, TCP, UDP, sr1, RandShort, sniff
import requests 
from Wappalyzer import Wappalyzer, WebPage
import pyshark

suspicious_ips = [
    "192.168.1.100",
    "10.0.0.50",
    "172.16.31.200",
    "127.0.0.2", 
    "23.228.128.186",
    "52.87.163.243"
]

sniff_config = {
    'display_filter': 'tcp port == 80',
    'packet_count': 100,
}
packets = pyshark.LiveCapture(interface='eth0', **sniff_config)


class Generate_reports:
    def generate_report():
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

class net:
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
        if pkt.haslayer(IP):
            for host in suspicious_ips:
                if pkt[IP].src == host:
                    print("Suspicious trafic detected from: " + pkt[IP].src)

    def web_traffic_sqli_analisys(self, url):

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
                               
                        # Check for XSS attack patterns
                    xss_patterns = ['<script>', '</script>', 'javascript:', 'onload=', 'onerror=']
                    for pattern in xss_patterns:
                        if pattern in http_data['data']:
                            print(f"Potential XSS attack detected: {http_data['request']}")
                                
          
def main():
    n = net()
    g = Generate_reports()

    n.web_traffic_sqli_analisys("https://www.una.ac.cr/")

    host_alive = n.ping_sweep("192.168.50")

    # For each host found alive, perform port scans and vulnerability checks
    for host in host_alive:
        # Scan ports 1-1024 for open ports
        n.port_scan(host, range(1, 1024))
    
    # Sniff network traffic with an IP filter and store it in memory
    sniff(prn=n.monitor_callback, filter="ip", store=0) 

    g.generate_report()

if __name__ == "__main__":
    main()
