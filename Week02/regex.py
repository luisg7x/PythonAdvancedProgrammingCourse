import re

def validar_ipv4(direccion):
    patron_ipv4 = re.compile(
        r'^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )
    if patron_ipv4.match(direccion):
        return True
    return False

direcciones = [
    "192.168.1.1",
    "255.255.255.0",
    "10.0.0.0",
    "172.16.0.0",
    "300.1.1.1",
    "fidelitas.com"
]

for direccion in direcciones:
    resultado = "valida" if validar_ipv4(direccion) else "invalida"
    print(f"La dirección {direccion} es {resultado}")
