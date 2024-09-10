import tkinter as tk
from tkinter import filedialog
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import os
from secure_delete import secure_delete

def encrypt_folder():
    folder_path = filedialog.askdirectory(title="Select Folder to Encrypt")
    if folder_path:
        key = key_entry.get().encode()
        key = key.ljust(32, b'\0')  # Pad key to 32 bytes (256 bits)
        try:
            encrypt_folder_contents(folder_path, key)
            result_label.config(text="Folder has been encrypted successfully.")
        except Exception as e:
            result_label.config(text=f"Error: {str(e)}")
    else:
        result_label.config(text="Error: No folder has been selected.")

def encrypt_file(file_path, key):
    """Encrypt a single file."""
    with open(file_path, 'rb') as file:
        plaintext = file.read()

    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    encrypted_file_path = file_path + ".encrypted"
    with open(encrypted_file_path, 'wb') as file:
        file.write(cipher.nonce)
        file.write(tag)
        file.write(ciphertext)
    
    secure_delete.secure_delete(file_path)

def encrypt_folder_contents(folder_path, key):
    """Encrypt all files in a folder."""
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            encrypt_file(file_path, key)

def decrypt_file():
    """Decrypt a selected file."""
    encrypted_file_path = filedialog.askopenfilename(title="Select File to Decrypt")
    if encrypted_file_path:
        key = key_entry.get().encode()
        key = key.ljust(32, b'\0')  # Pad key to 32 bytes (256 bits)
        
        try:
            with open(encrypted_file_path, 'rb') as file:
                nonce = file.read(16)
                tag = file.read(16)
                ciphertext = file.read()

            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)

            decrypted_file_path = encrypted_file_path[:-10]
            with open(decrypted_file_path, 'wb') as file:
                file.write(plaintext)
            
            secure_delete.secure_delete(encrypted_file_path)
            result_label.config(text="File has been decrypted successfully.")
        except ValueError as e:
            result_label.config(text="Decryption failed. Incorrect key or corrupted file.")
    else:
        result_label.config(text="Error: No file has been selected.")

# Tkinter GUI setup
root = tk.Tk()
root.title("Encryption Tool")
root.geometry("500x350")
root.configure(bg="white")

frame = tk.Frame(root, bg="white")
frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

key_label = tk.Label(frame, text="Please Enter Encryption/Decryption Key:", fg="#003EFF", bg="white")
key_label.pack()
key_entry = tk.Entry(frame, show="*")
key_entry.pack()

encrypt_button = tk.Button(frame, text="Encrypt Folder", command=encrypt_folder)
encrypt_button.pack(pady=10)

decrypt_button = tk.Button(frame, text="Decrypt File", command=decrypt_file)
decrypt_button.pack()

result_label = tk.Label(frame, text="", bg="white")
result_label.pack(pady=10)

warning_label = tk.Label(root, text="Warning: There is no forgot password option.", bg="white", fg="red")
warning_label.pack(side=tk.BOTTOM, pady=10)

root.mainloop()
