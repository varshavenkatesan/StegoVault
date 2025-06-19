# StegoVault/ui.py

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

from crypto_utils import AESCipher
import steg

class StegoVaultApp:
    def __init__(self, root):
        self.root = root
        self.root.title("StegoVault")
        self.root.geometry("600x650")
        
        # --- Main Frame ---
        main_frame = tk.Frame(root, padx=10, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- Encode Frame ---
        encode_frame = tk.LabelFrame(main_frame, text="Encrypt & Embed", padx=10, pady=10)
        encode_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.encode_img_path = tk.StringVar()
        tk.Label(encode_frame, text="Image File:").grid(row=0, column=0, sticky=tk.W, pady=2)
        tk.Entry(encode_frame, textvariable=self.encode_img_path, width=50).grid(row=0, column=1, sticky=tk.W)
        tk.Button(encode_frame, text="Browse...", command=self.browse_encode_image).grid(row=0, column=2, padx=5)

        tk.Label(encode_frame, text="Secret Message:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.msg_entry = scrolledtext.ScrolledText(encode_frame, height=5, width=50)
        self.msg_entry.grid(row=1, column=1, columnspan=2, sticky=tk.W+tk.E, pady=2)
        
        tk.Label(encode_frame, text="Password:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.encode_password = tk.StringVar()
        tk.Entry(encode_frame, textvariable=self.encode_password, show="*", width=50).grid(row=2, column=1, sticky=tk.W)
        
        tk.Button(encode_frame, text="Encrypt & Embed", command=self.encode_action, bg="#4CAF50", fg="white").grid(row=3, column=1, pady=10, sticky=tk.E)

        # --- Decode Frame ---
        decode_frame = tk.LabelFrame(main_frame, text="Extract & Decrypt", padx=10, pady=10)
        decode_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.decode_img_path = tk.StringVar()
        tk.Label(decode_frame, text="Stego Image File:").grid(row=0, column=0, sticky=tk.W, pady=2)
        tk.Entry(decode_frame, textvariable=self.decode_img_path, width=50).grid(row=0, column=1, sticky=tk.W)
        tk.Button(decode_frame, text="Browse...", command=self.browse_decode_image).grid(row=0, column=2, padx=5)

        tk.Label(decode_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.decode_password = tk.StringVar()
        tk.Entry(decode_frame, textvariable=self.decode_password, show="*", width=50).grid(row=1, column=1, sticky=tk.W)
        
        tk.Button(decode_frame, text="Extract & Decrypt", command=self.decode_action, bg="#f44336", fg="white").grid(row=2, column=1, pady=10, sticky=tk.E)

        tk.Label(decode_frame, text="Extracted Message:").grid(row=3, column=0, sticky=tk.NW, pady=2)
        self.decoded_msg_text = scrolledtext.ScrolledText(decode_frame, height=8, width=60, state=tk.DISABLED)
        self.decoded_msg_text.grid(row=4, column=0, columnspan=3, sticky=tk.W+tk.E, pady=2)


    def browse_encode_image(self):
        filepath = filedialog.askopenfilename(filetypes=[("PNG files", "*.png"), ("All files", "*.*")])
        if filepath:
            self.encode_img_path.set(filepath)

    def browse_decode_image(self):
        filepath = filedialog.askopenfilename(filetypes=[("PNG files", "*.png"), ("All files", "*.*")])
        if filepath:
            self.decode_img_path.set(filepath)

    def encode_action(self):
        try:
            image_path = self.encode_img_path.get()
            message = self.msg_entry.get("1.0", tk.END).strip()
            password = self.encode_password.get()

            if not all([image_path, message, password]):
                messagebox.showerror("Error", "All fields are required for encoding.")
                return
            
            # 1. Encrypt the message
            cipher = AESCipher(password)
            encrypted_data = cipher.encrypt(message)
            
            # 2. Embed the encrypted data
            new_image = steg.embed_data(image_path, encrypted_data)
            
            # 3. Save the new image
            save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
            if save_path:
                new_image.save(save_path)
                messagebox.showinfo("Success", f"Message embedded and saved to:\n{save_path}")
        except Exception as e:
            messagebox.showerror("Encoding Error", str(e))

    def decode_action(self):
        try:
            image_path = self.decode_img_path.get()
            password = self.decode_password.get()
            
            if not all([image_path, password]):
                messagebox.showerror("Error", "Image file and password are required.")
                return

            # 1. Extract the hidden data
            extracted_data = steg.extract_data(image_path)

            # 2. Decrypt the data
            cipher = AESCipher(password)
            decrypted_message = cipher.decrypt(extracted_data)
            
            # 3. Display the message
            self.decoded_msg_text.config(state=tk.NORMAL)
            self.decoded_msg_text.delete("1.0", tk.END)
            self.decoded_msg_text.insert(tk.END, decrypted_message)
            self.decoded_msg_text.config(state=tk.DISABLED)
            
        except ValueError as e:
             messagebox.showerror("Decryption Error", "Failed to decrypt. Likely an incorrect password.")
             self.decoded_msg_text.config(state=tk.NORMAL)
             self.decoded_msg_text.delete("1.0", tk.END)
             self.decoded_msg_text.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Extraction Error", str(e))