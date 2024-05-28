from cryptography.fernet import Fernet

#Generate the key
key = Fernet.generate_key()

#Instacing Fernet using the key
cypher = Fernet(key)

#Message to cypher
message = "This message is a secret"

#Cyphering the message
cypher_message = cypher.encrypt(message)
print(f"Message cypher: {cypher_message}")

#Dedyphering the message
decypher_message = cypher.decrypt(cypher_message)
print(f"Message decypher: {decypher_message}")