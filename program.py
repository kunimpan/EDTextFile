from tkinter import *
from tkinter.filedialog import *
from cryptography.fernet import Fernet
import tkinter.messagebox
from tkinter import scrolledtext

root=Tk()
root.title("EDTextFile (V.1.0)")
root.geometry("500x500")
root.resizable(0, 0)

plain = b'' # Original text.
cipherData = b'' # The original text has been encrypted.

# Function import plain text file
def openText():
    try:
        myFile = askopenfilename(initialdir="./", title="Open Text", filetypes=(("Text File", "*.txt"), ("All File", "*")))
        with open(myFile, "rb") as file:
            global plain
            plain = file.read()
            plain_txt.delete("1.0", END)
            plain_txt.insert("1.0", plain.decode('utf-8'))
    except FileNotFoundError:
        tkinter.messagebox.showerror("Erorr", "File not found.")

# Function encrypt plain text file
def encrypt():                
    encrypted_txt.delete("1.0", END) # Clear cipher text
    key_txt.delete(0, END) # Clear decrypt key text

    temp = plain_txt.get("1.0", tkinter.END)
    plain = bytes(temp, 'utf-8')

    if not plain.strip() :
        tkinter.messagebox.showwarning("Warning", "Plain text is empty.")
    else:
        key = Fernet.generate_key() # Generate a symmetric key
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

        encrypted_txt["state"]='normal'
        encrypted_txt.insert("1.0", encryptedData)
        encrypted_txt["state"]='disable'

        with open('cipherText.txt', 'wb') as file:
            file.write(encryptedData)
            
        key_txt["state"] = 'normal'
        key_txt.delete(0, END)
        key_txt.insert(0, genKey)
        key_txt["state"] = 'readonly'

        tkinter.messagebox.showinfo("Encrypytion", "Plain text is encrypted.")

# Function import cipher file
def openCipher():
    try:
        cipherFile = askopenfilename(initialdir="./", title="Open Cipher", filetypes=(("Text File", "*.txt"), ("All File", "*")))
        with open(cipherFile, 'rb') as file:
            global cipherData
            cipherData = file.read()
            cipher_txt.delete("1.0", END)
            cipher_txt.insert("1.0", cipherData)

    except FileNotFoundError:
        tkinter.messagebox.showerror("Erorr", "File not found.")

# Function import key file
def openKey():
    try:
        cipherFile = askopenfilename(initialdir="./", title="Open Key", filetypes=(("Key File", "*.key"), ("All File", "*")))
        with open(cipherFile, 'rb') as file:
            decrypt_key_txt.delete(0, END) # Clear decrypt key text
            decrypt_key_txt.insert(0, file.read())
    except FileNotFoundError:
        tkinter.messagebox.showerror("Erorr", "File not found.")

    
# Function decrypt cipher text file
def decrypt():
    cipherData = cipher_txt.get("1.0", tkinter.END)
    if not cipherData.strip() :
        tkinter.messagebox.showwarning("Warning", "CipherText is empty.")
    else:
        if not decrypt_key_txt.get().strip():
            tkinter.messagebox.showwarning("Warning", "Please enter key.")
        else:
            try:
                if len(decrypt_key_txt.get()) == 44:
                    keyDecrypt = Fernet(decrypt_key_txt.get()) # Decrypt key
                    decryptedData = keyDecrypt.decrypt(cipherData) # Decrypt
                    decrypt_cipher_txt["state"]='normal'
                    decrypt_cipher_txt.delete("1.0", END) # Clear plain text
                    decrypt_cipher_txt.insert("1.0", decryptedData.decode())
                    decrypt_cipher_txt["state"]='disable'
                    tkinter.messagebox.showinfo("Decrypytion", "Cipher text is decrypted.")
                else:
                    tkinter.messagebox.showerror("Error", f"Decryption failed : The key format is incorrect.")
            except Exception as e:
                tkinter.messagebox.showerror("Error", f"Decryption failed : Invalid Cipher text or Key.")

# Function clear input text    
def reset():
    plain_txt.delete("1.0", END)
    encrypted_txt["state"]='normal'
    encrypted_txt.delete("1.0", END)
    encrypted_txt["state"]='disable'

    key_txt["state"]='normal'
    key_txt.delete(0, END)
    key_txt["state"]='readonly'

    cipher_txt.delete("1.0", END)
    decrypt_key_txt.delete(0, END)

    decrypt_cipher_txt["state"]='normal'
    decrypt_cipher_txt.delete("1.0", END)
    decrypt_cipher_txt["state"]='disable'
    tkinter.messagebox.showinfo("Notify", "Cleared.")

#settings
btnFont = ("Arial", 9, "bold")
titleFont = ("Arial", 15, "bold")
labelFrameFont = ("", 11, "underline")

#design frame
titleFrame=Frame(root)
btnFrame=LabelFrame(root, text="Options", font=labelFrameFont)
EncryptFrame=LabelFrame(root, text="Encryption", font=labelFrameFont)
DecryptFrame=LabelFrame(root, text="Decryption",  font=labelFrameFont)
titleFrame.pack()
btnFrame.pack(pady=(10,2))
EncryptFrame.pack(pady=10)
DecryptFrame.pack(pady=10)

#title frame
title_lable=Label(titleFrame, text="Program Encrypt-Decrypt Text and Text file", font=titleFont)
title_lable.pack(pady=(12,2))

#button widget
btnOpen=Button(btnFrame, text="Open Text", command=openText, font=btnFont)
btnOpen.grid(row=0, column=0, padx=4, pady=5)

btnEncrypt=Button(btnFrame, text="Encrypt", command=encrypt, font=btnFont)
btnEncrypt.grid(row=0, column=1, padx=4, pady=5)

btnOpenCipher=Button(btnFrame, text="Open Cipher", command=openCipher, font=btnFont)
btnOpenCipher.grid(row=0, column=2, padx=4, pady=5)

btnKey=Button(btnFrame, text="Open key", command=openKey, font=btnFont)
btnKey.grid(row=0, column=3, padx=4, pady=5)

btnDecrypt=Button(btnFrame, text="Decrypt", command=decrypt, font=btnFont)
btnDecrypt.grid(row=0, column=4, padx=4, pady=5)

btnReset=Button(btnFrame, text="Clear ", command=reset, font=btnFont)
btnReset.grid(row=0, column=5, padx=4, pady=5)


#encrypt input widget
plain_lable = Label(EncryptFrame, text="Plain text")
plain_txt = scrolledtext.ScrolledText(EncryptFrame, bg="white", width = 37, height = 1)
encrypted_lable = Label(EncryptFrame, text="Encrypted text")
encrypted_txt = scrolledtext.ScrolledText(EncryptFrame, bg="#F0F0F0", width = 37, height = 1, state='disabled')
key_lable= Label(EncryptFrame, text="Key generate")
key_txt = Entry(EncryptFrame, width=52, state='readonly')

plain_lable.grid(row=0, column=0, padx=5, pady=5, sticky=NW)
plain_txt.grid(row=0, column=1, padx=2, pady=2)
encrypted_lable.grid(row=1, column=0, padx=5, pady=5, sticky=NW)
encrypted_txt.grid(row=1, column=1, padx=2, pady=2)
key_lable.grid(row=2, column=0, padx=5, pady=5, sticky=W)
key_txt.grid(row=2, column=1)

#decrypt input widget
cipher_lable = Label(DecryptFrame, text="Cipher text")
cipher_txt = scrolledtext.ScrolledText(DecryptFrame, bg="white", width = 37, height = 1)
decrypt_key_lable = Label(DecryptFrame, text="Decrypt key    ")
decrypt_key_txt = Entry(DecryptFrame, width=52)
decrypt_cipher_lable = Label(DecryptFrame, text="Plain text")
decrypt_cipher_txt = scrolledtext.ScrolledText(DecryptFrame, bg="#F0F0F0", width = 37, height = 1, state='disabled')

cipher_lable.grid(row=0, column=0, padx=5, pady=5, sticky=NW)
cipher_txt.grid(row=0, column=1, padx=2, pady=2)
decrypt_key_lable.grid(row=1, column=0, padx=5, pady=5, sticky=W)
decrypt_key_txt.grid(row=1, column=1)
decrypt_cipher_lable.grid(row=2, column=0, padx=5, pady=5, sticky=NW)
decrypt_cipher_txt.grid(row=2, column=1, padx=3, pady=(2,7))

root.mainloop()