from tkinter import *

root=Tk()
root.title("Program Encrypt-Decrypt")
root.geometry("500x350")
root.resizable(0, 0)

#design frame
btnFrame=LabelFrame(root, text="Menu")
EncryptFrame=LabelFrame(root, text="Encrypt")
DecryptFrame=LabelFrame(root, text="Decrypt")
btnFrame.grid(row=0, column=0, columnspan=2, ipadx=200, pady=5)
EncryptFrame.grid(row=1, column=0)
DecryptFrame.grid(row=2, column=0)

#button widget
btnOpen=Button(btnFrame, text="Open file")
btnOpen.grid(row=0, column=0, padx=5, pady=5)

btnEncrypt=Button(btnFrame, text="Encrypt")
btnEncrypt.grid(row=0, column=1, padx=5, pady=5)

#encrypt input widget
plain_lable = Label(EncryptFrame, text="Plain text")
plain_txt = Entry(EncryptFrame, width=50)
encrypted_lable = Label(EncryptFrame, text="Encrypted text")
encrypted_txt = Entry(EncryptFrame, width=50)
key_lable= Label(EncryptFrame, text="Key")
key_txt = Entry(EncryptFrame, width=50)

plain_lable.grid(row=0, column=0, padx=5, pady=5)
plain_txt.grid(row=0, column=1)
encrypted_lable.grid(row=1, column=0, padx=5, pady=5)
encrypted_txt.grid(row=1, column=1)
key_lable.grid(row=2, column=0, padx=5, pady=5)
key_txt.grid(row=2, column=1)

#decrypt input widget
cipher_lable = Label(DecryptFrame, text="Cipher text")
cipher_txt = Entry(DecryptFrame, width=50)
decrypt_key_lable = Label(DecryptFrame, text="Decrypt key")
decrypt_key_txt = Entry(DecryptFrame, width=50)
decrypt_cipher_lable = Label(DecryptFrame, text="PlainD text")
decrypt_cipher_txt = Entry(DecryptFrame, width=50)

cipher_lable.grid(row=0, column=0, padx=5, pady=5)
cipher_txt.grid(row=0, column=1)
decrypt_key_lable.grid(row=1, column=0, padx=5, pady=5)
decrypt_key_txt.grid(row=1, column=1)
decrypt_cipher_lable.grid(row=2, column=0, padx=5, pady=5)
decrypt_cipher_txt.grid(row=2, column=1)

root.mainloop()