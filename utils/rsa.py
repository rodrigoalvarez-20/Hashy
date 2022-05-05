import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import *

def generate_key_pair():
    """
    Función que permite generar un par de claves (publica y privada) en la carpeta "keys"
    Si se desea regenerar estos archivos, simplemente basta con borrarlos de la carpeta y ejecutar esta función
    """
    # Se utiliza RSA para la generación de llaves, se tiene un exponente arbitrario bastante grande y 
    # el tamaño de la llave es de 1024 bits
    key = rsa.generate_private_key(backend=default_backend(), public_exponent=65537, key_size=1024)
    # Se genera una llave privada en formato PEM, esto con la finalidad de poder leer el archivo de una manera más facil
    encrypted_pem_private_key = key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())

    # A partir del valor de la llave privada obtenida, se genera una llave publica, con el mismo formato PEM
    pem_public_key = key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

    # Guardamos los bytes obtenidos de la llave privada a un archivo
    with open(f"{os.getcwd()}/keys/private.pem", "w") as pKey:
        pKey.write(encrypted_pem_private_key.decode("utf-8"))
    
    # Guardamos los bytes obtenidos de la llave publica a un archivo
    with open(f"{os.getcwd()}/keys/public.pem", "w") as pubKey:
        pubKey.write(pem_public_key.decode("utf-8"))
    

def validate_key():
    """
    Función que permite validar que el par de llaves exista
    @return Verdadero si ambos archivos existen, False de lo contrario
    """
    return os.path.isfile(f"{os.getcwd()}/keys/private.pem") and os.path.isfile(f"{os.getcwd()}/keys/public.pem")


def get_keys():
    """
    Función que permite obtener los datos de ambas llaves.
    Primero se abre la llave privada y a partir de ella, se obtiene la llave publica
    @return private_key_str: Cadena con el valor de nuestra llave privada
    @return public_key_str: Cadena con el valor de nuestra llave publica
    """
    # Se debe de abrir el archivo de la llave privada
    with open(f"{os.getcwd()}/keys/private.pem", "rb") as pKey:
        # Se carga los datos de la llave (PEM) 
        private_key = serialization.load_pem_private_key(pKey.read(), password=None)
        # A partir de estos datos obtenidos, se genera la llave publica
        pubKey = private_key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        # Se debe de obtener los bytes de nuestra llave privada
        pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())
        private_key_str = pem.decode('utf-8') # Ya que los valores obtenidos vienen en bytes, se hace un decode
        public_key_str = pubKey.decode('utf-8')
        return private_key_str, public_key_str

def cipher(plain_value, key_path) -> bytes:
    """
    Función que permite cifrar un texto/valor en plano, utilizando la llave publica
    @param plain_value: Valor en cadena que se desea cifrar
    @param key_path: Ruta del archivo de llave a ocupar
    @return cipher: Valor cifrado
    @return None si ha ocurrido un error de cifrado
    """
    try:
        public_key = open(key_path, "rb") # Se abre la llave especificada en formato binario
        # Se hace una serialización (se carga) de la llave. Para este cifrado, se debe de ocupar la llave publica
        public = serialization.load_der_public_key(public_key.read(), backend=default_backend())
        # Utilizamos la función encrypt que permite generar el texto cifrado, dando el padding adecuado, si es que lo necesita
        cipher = public.encrypt(plain_value.encode(), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None))
        public_key.close()
        return cipher
    except UnsupportedAlgorithm:
        print("El algoritmo de la llave proporcionada es invalido para el metodo seleccionado")
        return None
    except ValueError:
        print("El valor de la llave seleccionada es invalido")
        return None

def uncipher(value, key_path) -> str:
    try:
        private_key = open(key_path, "rb")
        private = serialization.load_pem_private_key(private_key.read(), backend=default_backend(), password=None)
        plain = private.decrypt(value, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None))
        return plain
    except InvalidKey:
        print("La llave proporcionada es invalida para el metodo seleccionado")
        return None
    except UnsupportedAlgorithm:
        print("El algoritmo de la llave proporcionada es invalido para el metodo seleccionado")
        return None
    except ValueError:
        print("El valor de la llave seleccionada es invalido")
        return None

def sign(value, key_path) -> tuple:
    """
    Función que permite firmar un valor dado.
    Para esto se ocupa la llave privada de quien está firmando
    @param value: Valor en cadena que se desea firmar
    @param key_path: Ruta de la llave a utilizar
    @return Tuple: Una tupla de valores (Codigo de estado, Mensaje/Error)
    """
    try:
        # Se abre la llave privada en modo binario
        private_key = open(key_path, "rb")
        # Se hace la carga de la llave privada (se convierten los bytes del archivo a una instancia de llave privada)
        private = serialization.load_pem_private_key(private_key.read(), backend=default_backend(), password=None)
        # Mediante la función SIGN y un padding adecuado, se genera la firma de dicho texto o valor
        # Cabe decir que se ha ocupado el SHA256, por su seguridad
        signed_hash = private.sign(value, padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256())
        return ("ok",signed_hash)
    except UnsupportedAlgorithm:
        print("La llave de firma es incorrecta para el modo de operacion")
        return ("error", "La llave de firma es incorrecta para el modo de operacion")
    except:
        print("Error al generar la firma")
        return ("error", "Error al generar la firma")

def verify_sign(plain_value, sign_value, key_path) -> tuple:
    """
    Función que permite verificar la firma de los datos
    Hace la comparacion de un valor firmado, con los valores originales
    @param plain_value: Valor en bytes de los datos originales
    @param sign_value: Valor en bytes de los que ya se tienen firmados
    @param key_path: Ruta de la llave (publica) que se ha de ocupar para verificar la integridad de los datos
    @return Tuple: (Estado, Mensaje/Error)
    """
    try:
        # Se abre la llave en modo Binario
        public_key = open(key_path, "rb")
        # Se hace la carga del PEM
        public = serialization.load_pem_public_key(public_key.read(), backend=default_backend())
        # Se procede a verificar
        # Internamente, esta función genera un hash de los datos, decifra el valor que se tiene firmado 
        # y posteriormente compara ambos valores obtenidos
        public.verify(signature=sign_value, data=plain_value, padding= padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),algorithm=hashes.SHA256())
        return ("ok", "Los hashes coinciden")
    except InvalidSignature:
        return ("error", "La firma es inválida")
    except ValueError:
        print("La llave seleccionada no coincide con el formato para verificar (PRIVATE_KEY_SELECTED)")
        return ("error", "La llave seleccionada no coincide con el formato necesario (PRIVATE_KEY_SELECTED)")
    
    