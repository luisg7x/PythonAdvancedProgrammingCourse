import string
import random
import pyperclip

def generar_contrasena(longitud):
    caracteres = string.ascii_letters + string.digits + string.punctuation
    contrasena = ''.join(random.choice(caracteres) for _ in range(longitud))
    return contrasena

longitud_contrasena = 16
contrasena_generada = generar_contrasena(longitud_contrasena)

print(f"Contrasena generada: {contrasena_generada}")

pyperclip.copy(contrasena_generada)










    