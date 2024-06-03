from scapy.all import ICMP, IP, sr1, RandShort 

def ping_sweep(target_subnet) :
    live_hosts = []
    for host in range(1, 255):
        target_ip = f"{target_subnet}.{host}"
        packet = IP(dst=target_ip)/ICMP(id=RandShort(), seq=RandShort())
        response = sr1(packet, timeout=1, verbose=0)
        if response is not None:
            print(f" {target_ip} está vivo.")
            live_hosts.append(target_ip)
        else:
            print(f" {target_ip} está muerto o no responde a pings.")
    return live_hosts
            
target_subnet = input ("127.0.0.1")
live_hosts = ping_sweep(target_subnet)
print(f"\nHosts vivos en la subred {target_subnet} :") 
for host in live_hosts:
    print(host)