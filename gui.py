from functools import partial
from tkinter import CENTER, DISABLED, END, GROOVE, Entry, IntVar, Radiobutton, StringVar, Text, Tk, Frame, Label, filedialog, Button, TOP, LEFT, messagebox

from tempfile import gettempdir
import os
from tkinter.font import NORMAL

from utils.hash import get_hash
from utils.rsa import sign, verify_sign

root = Tk()

global mode_sel, key_path, file_path
mode_sel = 0
key_path = None
file_path = None
op_mode = IntVar()

root.geometry("640x580")
root.title("RSA y SHA1")  # Titulo de la ventana

Tops = Frame(root, width=640, relief=GROOVE)  # Contenedor principal
Tops.pack(side=TOP)

f1 = Frame(root, width=640, height=580,
           relief=GROOVE)
f1.pack(side=LEFT)

def handle_user_mode_sel():
    global mode_sel
    mode_sel = 0
    mode_sel = op_mode.get()

def open_file(type, preview = None):
    file_types = (
        ('Text files', '*.txt'),
        ('PEM files', '*.pem'),
        ('Key files', '*.key'),
        ('All files', '*.*')
    )

    # Selector de archivos propio del S.O.
    f = filedialog.askopenfile(filetypes=file_types)

    if f is not None:  # Si hemos seleccionado un archivo
        global key_path, file_path  # Reasignamos los valores de las variables globales
        # Obtenemos el nombre (que en realidad es la ruta completa)
        if type == 0:
            key_path = f.name
        else:
            file_path = f.name
            with open(file_path, "r", encoding="latin1") as prevFile:
                preview.config(state=NORMAL)
                preview.delete("1.0", END)
                preview.insert("1.0", prevFile.read())
                preview.config(state=DISABLED)
    else:
        if type == 0:
            key_path = None
        else:
            file_path = None
            preview.config(state=NORMAL)
            preview.delete("1.0", END)
            preview.config(state=DISABLED)
        # Mostramos una advertencia en el caso de que no se haya seleccionado un archivo
        messagebox.showinfo("Advertencia", "No seleccionó ningun archivo")

def run_process(out_label):
    out_text_label = StringVar()
    out_text = "Salida: \n"
    if key_path is None or file_path is None:
        messagebox.showerror("Error", "Por favor seleccione los archivos correctamente")
    else:
        if mode_sel == 0:
            # Firmar archivo
            digest = get_hash(file_path)
            out_text += f"Hash generado: {digest}\n"
            sign_data = sign(digest.encode(), key_path)
            if "error" in sign_data:
                messagebox.showerror("Error", sign_data[1])
            else:
                with open(file_path, "ab") as org_file:
                    org_file.write(b"\n=HASH=\n")
                    org_file.write(sign_data[1])
                out_text += "Se ha firmado el hash y guardado en el archivo\n"
        else:
            with open(file_path, "rb") as cipher_file:
                file_content = cipher_file.read()
                if (file_content.find(b"\n=HASH=\n") == -1):
                    out_text += "El archivo no contiene un hash válido"
                else:
                    contents = file_content.split(b"\n=HASH=\n")
                    
                    # Generar archivo temporal para obtener el hash de los datos originales
                    temp_file = f"{gettempdir()}/temp.txt"
                    open(temp_file, "wb" ).write(contents[0])
                    hash_value_of_data = get_hash(temp_file)
                    # Verificar el hash de los datos

                    hash_status = verify_sign(hash_value_of_data.encode(), contents[1], key_path)

                    out_text += hash_status[1]
                    
                    os.remove(temp_file)
        
        out_text_label.set(out_text)
        out_label.config(textvariable = out_text_label)

# Label de titulo en la ventana
lblInfo = Label(Tops, font=('helvetica', 32, 'bold'),
                text="Practica #3. Firma digital", fg="Black", bd=10, anchor=CENTER)

lblInfo.grid(row=0, column=0, columnspan=2)

lblTypes =  Label(Tops, font=('helvetica', 24),
                text="Selecciona la acción deseada", fg="Black", bd=10, anchor=CENTER)

lblTypes.grid(row=1, column=0, columnspan=2)

rbSign = Radiobutton(Tops, text="Firmar archivo",
                       variable=op_mode, value=0, command=handle_user_mode_sel)
rbSign.grid(row=2, column=0)

rbVerify = Radiobutton(Tops, text="Verificar archivo firmado",
                          variable=op_mode, value=1, command=handle_user_mode_sel)
rbVerify.grid(row=2, column=1)

lblKeyFileSelect = Label(Tops, font=("helvetica", 18),
                      text="Selecciona el archivo de la llave")
lblKeyFileSelect.grid(row=3, column=0, pady=12)

openKeyFileButton = Button(Tops, text="Abrir archivo", command=partial(open_file, 0))
openKeyFileButton.grid(row=3, column=1, padx=12)

lblFileSelect = Label(Tops, font=("helvetica", 18),
                      text="Selecciona el archivo a trabajar")
lblFileSelect.grid(row=4, column=0, pady=4)

txtDisplayFileSelected = Text(Tops, height=12)

openFileButton = Button(Tops, text="Abrir archivo", command=partial(open_file, 1, txtDisplayFileSelected))

openFileButton.grid(row=4, column=1, padx=12)
txtDisplayFileSelected.grid(row=5, column=0, columnspan=2, pady=6)

lblOut = Label(Tops, font=("helvetica", 18),
                      text="Salida: ")

acceptButton = Button(Tops, text="Comenzar", command=partial(run_process, lblOut))

acceptButton.grid(row=6, column=1, padx=12)
lblOut.grid(row=7, column=0, pady=8, columnspan=2)

root.mainloop()
