from tkinter import *
from tkinter.filedialog import *
from cryptography.fernet import Fernet
import tkinter.messagebox
from tkinter import scrolledtext

root=Tk()
root.title("Program Encrypt-Decrypt")
root.geometry("500x450")
root.resizable(0, 0)

plain = b'' # Original text
cipherData = b'' # Encrypted original text

def openText():
    try:
        myFile = askopenfilename(initialdir="./", title="Open note", filetypes=(("Text File", "*.txt"), ("All File", "*")))
        with open(myFile, "rb") as file:
            global plain
            plain = file.read()
            plain_txt.insert("1.0", plain.decode('utf-8'))
    except FileNotFoundError:
        tkinter.messagebox.showerror("Erorr", "File not found.")

def encrypt():                
    key = Fernet.generate_key() # Generate a symmetric key

    encrypted_txt.delete("1.0", END) # Clear cipher text
    key_txt.delete(0, END) # Clear decrypt key text

    temp = plain_txt.get("1.0", tkinter.END)
    plain = bytes(temp, 'utf-8')

    if not plain.strip() :
        tkinter.messagebox.showwarning("Warning", "Plaintext is empty.")
    else:
        # Create "secretKey.key" for keep key.
        with open('secretKey.key', 'wb') as file:
            file.write(key) 

        # Read "secretKey.key"
        with open('secretKey.key', 'rb') as file:
            global genKey
            genKey = file.read()

        f = Fernet(genKey)
        global encryptedData
        encryptedData = f.encrypt(plain) # encrypted
        encrypted_txt.insert("1.0", encryptedData)

        with open('cipherText.txt', 'wb') as file:
            file.write(encryptedData)

        key_txt.insert(0, genKey)

        tkinter.messagebox.showinfo("Encrypytion", "Plaintext is encrypted.")

def openCipher():
    try:
        cipherFile = askopenfilename(initialdir="./", title="Open Cipher", filetypes=(("Text File", "*.txt"), ("All File", "*")))
        with open(cipherFile, 'rb') as file:
            global cipherData
            cipherData = file.read()
            cipher_txt.insert("1.0", cipherData)

    except FileNotFoundError:
        tkinter.messagebox.showerror("Erorr", "File not found.")

def decrypt():
    cipherData = cipher_txt.get("1.0", tkinter.END)
    if not cipherData.strip() :
        tkinter.messagebox.showwarning("Warning", "CipherText is empty.")
    else:
        if not decrypt_key_txt.get().strip():
            tkinter.messagebox.showwarning("Warning", "Please enter key.")
        else:
            try:
                keyDecrypt = Fernet(decrypt_key_txt.get()) # Decrypt key
                decryptedData = keyDecrypt.decrypt(cipherData) # Decrypt
                decrypt_cipher_txt.insert("1.0", decryptedData.decode())
                tkinter.messagebox.showinfo("Decrypytion", "Ciphertext is decrypted.")
            except Exception as e:
                tkinter.messagebox.showerror("Error", f"Decryption failed")
            


#design frame
btnFrame=LabelFrame(root, text="Option")
EncryptFrame=LabelFrame(root, text="Encrypt")
DecryptFrame=LabelFrame(root, text="Decrypt")
btnFrame.pack()
EncryptFrame.pack(pady=10)
DecryptFrame.pack(pady=10)

#button widget
btnOpen=Button(btnFrame, text="Open file", command=openText)
btnOpen.grid(row=0, column=0, padx=5, pady=5)

btnEncrypt=Button(btnFrame, text="Encrypt", command=encrypt)
btnEncrypt.grid(row=0, column=1, padx=5, pady=5)

btnOpenCipher=Button(btnFrame, text="Open Cipher", command=openCipher)
btnOpenCipher.grid(row=0, column=2, padx=5, pady=5)

btnDecrypt=Button(btnFrame, text="Decrypt", command=decrypt)
btnDecrypt.grid(row=0, column=4, padx=5, pady=5)

#encrypt input widget
plain_lable = Label(EncryptFrame, text="Plaintext")
plain_txt = scrolledtext.ScrolledText(EncryptFrame, bg="white", width = 37, height = 1)
encrypted_lable = Label(EncryptFrame, text="Cipher text")
encrypted_txt = scrolledtext.ScrolledText(EncryptFrame, bg="white", width = 37, height = 1)
key_lable= Label(EncryptFrame, text="Decrypt key")
key_txt = Entry(EncryptFrame, width=52)

plain_lable.grid(row=0, column=0, padx=5, pady=5, sticky=NW)
plain_txt.grid(row=0, column=1, padx=2, pady=2)
encrypted_lable.grid(row=1, column=0, padx=5, pady=5, sticky=NW)
encrypted_txt.grid(row=1, column=1, padx=2, pady=2)
key_lable.grid(row=2, column=0, padx=5, pady=5, sticky=W)
key_txt.grid(row=2, column=1)

#decrypt input widget
cipher_lable = Label(DecryptFrame, text="Cipher text")
cipher_txt = scrolledtext.ScrolledText(DecryptFrame, bg="white", width = 37, height = 1)
decrypt_key_lable = Label(DecryptFrame, text="Decrypt key")
decrypt_key_txt = Entry(DecryptFrame, width=52)
decrypt_cipher_lable = Label(DecryptFrame, text="Plaintext")
decrypt_cipher_txt = scrolledtext.ScrolledText(DecryptFrame, bg="white", width = 37, height = 1)

cipher_lable.grid(row=0, column=0, padx=5, pady=5, sticky=NW)
cipher_txt.grid(row=0, column=1, padx=2, pady=2)
decrypt_key_lable.grid(row=1, column=0, padx=5, pady=5, sticky=W)
decrypt_key_txt.grid(row=1, column=1)
decrypt_cipher_lable.grid(row=2, column=0, padx=5, pady=5, sticky=NW)
decrypt_cipher_txt.grid(row=2, column=1, padx=3, pady=2)

root.mainloop()