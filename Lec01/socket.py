import socket
from concurrent.futures import ThreadPoolExecutor

def escanear_puerto(host, puerto):
    try:    
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        resultado = sock.connect_ex((host, puerto))
        if resultado == 0:
            print(f"Puerto {puerto}: ABIERTO")
        else:
            print(f"Puerto {puerto}: CERRADO")
        sock.close()

    except Exception as e:
        print(f"Error en el {puerto}: {e}")

def escanear_puertos(host, puerto_inicio, puerto_fin):
    with ThreadPoolExecutor(max_workers=100) as executor:
        for puerto in range(puerto_inicio, puerto_fin + 1):
            executor.submit(escanear_puerto, host, puerto)

host_objetivo = "localhost"
puerto_inicio = 400
puerto_fin = 450

print(f"Escaneando puertos {puerto_inicio} a {puerto_fin} en {host_objetivo}")
escanear_puertos(host_objetivo, puerto_inicio, puerto_fin)
