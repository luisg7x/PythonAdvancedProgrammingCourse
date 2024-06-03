text = "abraabra Mundo"

#Reemplaza todas las apariciones de old en la cadena por new. Si se especifica el argumento count, solo se reemplazan las primeras count apariciones.
print(text.replace("Mundo", "Friends"))

#Devuelve el índice de la primera aparición de sub en la cadena, o -1 si sub no se encuentra. Los argumentos start y end son opcionales y especifican el rango de búsqueda.
print(text.find("Mundo"))

#Reemplaza todas las apariciones de old en la cadena por new. Si se especifica el argumento count, solo se reemplazan las primeras count apariciones
print(text.replace("Mundo", "Friends"))

#Devuelve el número de apariciones no superpuestas de sub en la cadena. Los argumentos start y end son opcionales y especifican el rango de búsqueda.
print(text.count("abra"))

#Devuelve True si la cadena comienza con el prefijo especificado, y False en caso contrario. Los argumentos start y end son opcionales y especifican el rango de búsqueda.
print(text.startswith("Mundo"))

#Devuelve True si la cadena termina con el sufijo especificado, y False en caso contrario. Los argumentos start y end son opcionales y especifican el rango de búsqueda.
print(text.endswith("Mundo"))

#Realiza una operación de formato de cadena, reemplazando las llaves {} en la cadena con los valores proporcionados en args y kwargs
text = "Hola, eres {} y has encendido {}"
print(text.format("Juan", 2))

#Devuelve True si todos los caracteres de la cadena son alfanuméricos (letras y/o números) y False en caso contrario.
print(text.isalnum())

#Devuelve True si todos los caracteres de la cadena son letras y False en caso contrario.
print(text.isalpha())

#Devuelve True si todos los caracteres de la cadena son dígitos y False en caso contrario.
print(text.isdigit())