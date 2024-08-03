import nmap

def scan_network(network):
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


if __name__ == "__main__":
    network = input("Introduce la red a escanear (ej: 192.168.1.0/24): ")
    scan_network(network)