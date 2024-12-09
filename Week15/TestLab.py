from fpdf import FPDF
import datetime
from scapy.all import ICMP, IP, TCP, UDP, sr1, RandShort, sniff, conf, L3socket
from Wappalyzer import Wappalyzer, WebPage
import sys


reports = {}

def add_value_to_dict(my_dict, key, value):
    if key in my_dict:
        my_dict[key].append(value)
    else:
        my_dict[key] = [value]

class PrintPDF(FPDF):
    def header(self):
        self.set_font("Arial", "B", 12)
        self.cell(0, 10, "Print Report", 0, 1, "C")

    def footer(self):
        self.set_y(-15)
        self.set_font("Arial", "I", 8)
        self.cell(0, 10, "Page %s" % self.page_no(), 0, 0, "C")

    def add_print(self, text):
        self.set_font("Arial", size=12)
        self.multi_cell(0, 10, txt=text, align="L")

class Generate_reportds:
    def generate_report(self):
        pdf = PrintPDF()
        now = datetime.datetime.now()
        timestamp = now.strftime("%d_%m_%Y_%H_%M_%S")

        current_key = None
        for key, value_list in reports.items():
            if key != current_key:
                # Key has changed
                current_key = key
                pdf.add_page()

            # Print all values associated with the current key
            for value in value_list:
                pdf.add_print(value)

        pdf.output("Report_" + timestamp + ".pdf")

        print("PDF report generated successfully!")
        

class Generate_reports:

    def scan_network(self, network):
        key = "scan_network"
        """
        Performs a network scan on the specified IP address or range.

        Args:
            network (str): The IP address or range to be scanned.
        """

        if network is not None:
            print("Network found")
            add_value_to_dict(reports, key, f"Network found {key}")
        else:
            print("not nentwrok")
            add_value_to_dict(reports, key, "not nentwrok")

        add_value_to_dict(reports, key, "true")
        return True
    

    def packet_handler(packet):
        if 'IP' in packet:
            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst

            # Check for SQL injection patterns
            sql_injection_patterns = ['UNION', 'SELECT', 'FROM', 'WHERE', 'LIMIT', "admin' --", "admin' /*", "admin'or '1'='1", "admin' or '1'='1' --", "admin' or'1'='1' /*"]
            for pattern in sql_injection_patterns:
                if pattern.upper() in str(packet):
                    print(f"Potential SQL injection attempt detected from {src_ip} to {dst_ip}")
                      
            # Check for XSS attack patterns
            xss_patterns = ['<script>', '</script>', 'javascript:', 'onload=', 'onerror=']
            for pattern in xss_patterns:
                if pattern in str(packet):
                    print(f"Potential XSS attack detected from {src_ip} to {dst_ip}")
  
            
def main():

    g = Generate_reports()

    g.scan_network("192.168.50.1/21")

    conf.L3socket = L3RawSocket

    url = "https://translate.google.com/?sl=en&tl=es&op=translate"
    sniff(iface='eth0', prn=g.packet_handler, filter=f"host {url}")

    s = Generate_reportds()
    s.generate_report()

if __name__ == "__main__":
    main()
