from tkinter import *
from tkinter.filedialog import *
from cryptography.fernet import Fernet
import tkinter.messagebox
from tkinter import scrolledtext

root=Tk()
root.title("Program Encrypt-Decrypt")
root.geometry("500x500")
root.resizable(0, 0)

# Generate a symmetric key
key = Fernet.generate_key()

plain = b'' # Original text
cipherData = b'' # Encrypted original text

def openText():
    myFile = askopenfilename(initialdir="./", title="Open note", filetypes=(("Text File", "*.txt"), ("All File", "*")))
    with open(myFile, "rb") as file:
        global plain
        plain = file.read()
        plain_txt.insert("1.0", plain.decode('ascii'))

def encrypt():
    temp = plain_txt.get("1.0", tkinter.END)
    plain = bytes(temp, 'utf-8')

    # Create "secretKey.key" for keep key.
    with open('secretKey.key', 'wb') as file:
        file.write(key) 

    # Read "secretKey.key"
    with open('secretKey.key', 'rb') as file:
        global genKey
        genKey = file.read()
        print(genKey)

    f = Fernet(genKey)
    global encryptedData
    encryptedData = f.encrypt(plain) # encrypted
    encrypted_txt.insert("1.0", encryptedData)

    with open('cipherText.txt', 'wb') as file:
        file.write(encryptedData)

    key_txt.insert(0, genKey)


def openCipher():
    cipherFile = askopenfilename(initialdir="./", title="Open Cipher", filetypes=(("Text File", "*.txt"), ("All File", "*")))
    with open(cipherFile, 'rb') as file:
        global cipherData
        cipherData = file.read()
        cipher_txt.insert(0, cipherData)

def decrypt():
    cipherData = cipher_txt.get("1.0", tkinter.END)
    print(cipherData)
    keyDecrypt = Fernet(decrypt_key_txt.get()) # Decrypt key
    decryptedData = keyDecrypt.decrypt(cipherData) # Decrypt
    print(decryptedData.decode())
    decrypt_cipher_txt.insert("1.0", decryptedData.decode())

#design frame
btnFrame=LabelFrame(root, text="Menu")
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
btnDecrypt.grid(row=0, column=3, padx=5, pady=5)

#encrypt input widget
plain_lable = Label(EncryptFrame, text="Plain text")
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

#textArea_lable.grid(row=3, column=0, padx=5, pady=5, sticky=N)
#textArea.grid(row=3, column=1)

#decrypt input widget
cipher_lable = Label(DecryptFrame, text="Cipher text")
cipher_txt = scrolledtext.ScrolledText(DecryptFrame, bg="white", width = 37, height = 1)
decrypt_key_lable = Label(DecryptFrame, text="Decrypt key")
decrypt_key_txt = Entry(DecryptFrame, width=52)
decrypt_cipher_lable = Label(DecryptFrame, text="Plain text")
decrypt_cipher_txt = scrolledtext.ScrolledText(DecryptFrame, bg="white", width = 37, height = 1)

cipher_lable.grid(row=0, column=0, padx=5, pady=5, sticky=NW)
cipher_txt.grid(row=0, column=1, padx=2, pady=2)
decrypt_key_lable.grid(row=1, column=0, padx=5, pady=5, sticky=W)
decrypt_key_txt.grid(row=1, column=1)
decrypt_cipher_lable.grid(row=2, column=0, padx=5, pady=5, sticky=NW)
decrypt_cipher_txt.grid(row=2, column=1, padx=2, pady=2)

root.mainloop()