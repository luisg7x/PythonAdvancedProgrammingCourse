import dns.resolver
import whois
import os
import platform
import subprocess

domain = "pypi.org"

#DNS RESOLVER
print(f"----DNS RESOLVER ---------------->")
try:
    results = dns.resolver.resolve(domain, 'A')

    for result in results:
        print(f"{domain} resolves to {result.address}")
except dns.resolver.NoAnswer:
    print(f'No A record found for {domain}')
except dns.exception.DNSException as e:
    print(f'DNS lookup failed: {e}')

#WHOIS
print(f"----WHOIS ----------------->")
domain_information = whois.whois(domain)
print(domain_information)

#OS
print(f"----OS & PLATFORM ------------------>")
print(f"OS Name: {os.name}")
print(f"OS Version: {platform.version()}")
print(f"OS Machine: {platform.machine()}")

#SUBPROCESS
print(f"----SUBPROCESS --------------------->")
try:
    command = ["ping", "-c 5", domain]
    process = subprocess.Popen(command, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    stdout, stderr = process.communicate()
    print(stdout.decode())
except PermissionError as p:
    print(f"Permisson denied: Require administrative privileges")



