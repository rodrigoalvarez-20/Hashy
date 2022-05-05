import os
from utils.hash import get_hash
from utils.rsa import generate_key_pair, sign, validate_key, verify_sign
from tempfile import gettempdir

def init_keys():
    if (validate_key()):
        # Open The keys
        print("Keys already generated")
    else:
        print("Generating keys...")
        generate_key_pair()

def main_menu():
    print("=== Menu de opciones ===")
    print("1. Firmar archivo")
    print("2. Verificar archivo")

def get_file_paths(type = 0):
    key_path = input("Introduce la ruta de la llave a utilizar: ")
    while(not os.path.isfile(key_path)):
        print("La ruta de la llave es incorrecta")
        key_path = input("Introduce la ruta de la llave a utilizar: ")

    file_path = input(f"Introduce la ruta del archivo a {'firmar' if type == 0 else 'verificar'}: ")
    while(not os.path.isfile(file_path)):
        print("La ruta del archivo es incorrecta")
        file_path = input("Introduce la ruta del archivo a firmar: ")

    return key_path, file_path

if __name__ == "__main__":
    init_keys()
    main_menu()
    main_opc = int(input("Selecciona una opcion: "))
    key_path, file_path = get_file_paths(main_opc - 1)

    if main_opc == 1:
        # Hashear el contenido del archivo
        digest = get_hash(file_path)
        # Cifrar el valor del hash
        #print(digest)
        sign_data = sign(digest.encode(), key_path)
        if "error" in sign_data:
            print(sign_data[1])
            exit(0)
        # Guardar el valor del hash al final del archivo original
        with open(file_path, "ab") as org_file:
            org_file.write(b"\n=HASH=\n")
            org_file.write(sign_data[1])
        
        print("Se ha guardado el hash cifrado en el archivo")
    else:
        # Abrir el archivo elegido para verificar que si exista el hash cifrado
        with open(file_path, "rb") as cipher_file:
            file_content = cipher_file.read()
            if (file_content.find(b"\n=HASH=\n") == -1):
                print("El archivo no contiene un hash válido")
                exit(0)
            
            contents = file_content.split(b"\n=HASH=\n")
            
            # Generar archivo temporal para obtener el hash de los datos originales
            temp_file = f"{gettempdir()}/temp.txt"
            open(temp_file, "wb" ).write(contents[0])
            hash_value_of_data = get_hash(temp_file)
            # Verificar el hash de los datos

            hash_status = verify_sign(hash_value_of_data.encode(), contents[1], key_path)

            if "error" in hash_status:
                print(hash_status[1])
            else:
                print(hash_status[0])

            os.remove(temp_file)