import sqlite3
import unittest

# Function to establish a connection to the SQLite database.
def obtener_conexion():
   return sqlite3.connect('ejemplo.db')

# Function to create a table if it doesn't exist in the database.
def crear_tabla():
   conn = obtener_conexion()  # Establish a connection to the database.
   cursor = conn.cursor()      # Create a cursor object to execute SQL commands.
   cursor.execute('''CREATE TABLE IF NOT EXISTS usuarios (id INTEGER PRIMARY KEY, nombre TEXT, edad INTEGER)''')
   conn.commit()               # Commit the transaction.
   conn.close()                # Close the connection.

# Function to insert a user into the database.
def insertar_usuario(nombre, edad):
   conn = obtener_conexion()  # Establish a connection to the database.
   cursor = conn.cursor()      # Create a cursor object to execute SQL commands.
   cursor.execute('INSERT INTO usuarios (nombre, edad) VALUES (?, ?)', (nombre, edad))
   conn.commit()               # Commit the transaction.
   conn.close()                # Close the connection.

# Function to query a user from the database based on their ID.
def consultar_usuario(id):
   conn = obtener_conexion()  # Establish a connection to the database.
   cursor = conn.cursor()      # Create a cursor object to execute SQL commands.
   cursor.execute('SELECT * FROM usuarios WHERE id = ?', (id,))
   resultado = cursor.fetchone()  # Fetch one result from the query.
   conn.close()                # Close the connection.
   return resultado

# Unit test class for testing user-related operations.
class TestUsuarios(unittest.TestCase):
   def setUp(self):
       crear_tabla()  # Create the table before each test case runs.

   def tearDown(self):
       conn = obtener_conexion()  # Establish a connection to the database.
       cursor = conn.cursor()      # Create a cursor object to execute SQL commands.
       cursor.execute('DROP TABLE IF EXISTS usuarios')  # Drop the table if it exists.
       conn.commit()               # Commit the transaction.
       conn.close()                # Close the connection.

   def test_insertar_consultar_usuario(self):
       # Attempted SQL injection: 'Alice'; DROP TABLE usuarios; --
       insertar_usuario("'Alice'; DROP TABLE usuarios; --", 30)  # Insert a user with attempted SQL injection.
       usuario = consultar_usuario(1)  # Query the user by ID.
       self.assertEqual(usuario, (1, "'Alice'; DROP TABLE usuarios; --", 30))  # Assert that the result matches expected values.

   def test_usuario_no_encontrado(self):
       # Attempted SQL injection: 999 OR 1=1; --
       usuario = consultar_usuario("999 OR 1=1; --")  # Query a non-existing user with attempted SQL injection.
       self.assertIsNone(usuario)  # Assert that the result is None as expected.

if __name__ == "__main__":
   unittest.main()

