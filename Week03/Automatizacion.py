import ssl
import socket 
from urllib.parse import urlparse

def check_https(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    port = parsed_url.port or 443

    try: 
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                certificate = ssock.getpeername()
        if certificate:
            print(f"The {url} WebSite uses HTTPS and SSL certificates")
        else:
            print(f"The {url} WebSite uses HTTPS but the SSL certicate could not be validated")
    except (ssl.SSLError, socket.error) as e:
        print(f"The {url} WebSite does not use a HTTPS conection, or could not establish any conection: {e}")

url = "https://www.google.com"
check_https(url)