# StegoVault/crypto_utils.py

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# --- Constants for AES ---
# Using a static salt is not ideal for production, but simplifies this project.
# A better approach would be to generate a random salt for each encryption and prepend it to the ciphertext.
SALT = b'\x9a\x8e\x1f\xdc\xb6\x3f\x4b\x29\x88\x74\x94\x23\x7d\x8c\x5d\x6a' 
KEY_SIZE = 32  # 256-bit key
ITERATIONS = 100000 # Number of iterations for PBKDF2

class AESCipher:
    """
    Handles AES encryption and decryption.
    """
    def __init__(self, password):
        """
        Derives a key from the password using PBKDF2.
        """
        self.key = PBKDF2(password, SALT, dkLen=KEY_SIZE, count=ITERATIONS)

    def encrypt(self, plaintext):
        """
        Encrypts plaintext using AES-256 in CBC mode.
        - Plaintext is padded to be a multiple of the block size.
        - An Initialization Vector (IV) is generated and prepended to the ciphertext.
        """
        # Ensure plaintext is bytes
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # Pad the data to be a multiple of AES.block_size
        padded_data = pad(plaintext, AES.block_size)

        # Create a cipher object
        cipher = AES.new(self.key, AES.MODE_CBC)
        
        # Encrypt the data
        ciphertext = cipher.encrypt(padded_data)
        
        # Return the IV + ciphertext
        return cipher.iv + ciphertext

    def decrypt(self, ciphertext):
        """
        Decrypts ciphertext using AES-256 in CBC mode.
        - Assumes the IV is prepended to the ciphertext.
        - Unpads the decrypted text to get the original message.
        """
        # The IV is the first 16 bytes (AES.block_size)
        iv = ciphertext[:AES.block_size]
        actual_ciphertext = ciphertext[AES.block_size:]

        # Create a cipher object
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)

        # Decrypt the data and unpad it
        try:
            decrypted_padded = cipher.decrypt(actual_ciphertext)
            decrypted = unpad(decrypted_padded, AES.block_size)
            return decrypted.decode('utf-8')
        except (ValueError, KeyError) as e:
            # This often happens if the password is wrong, leading to incorrect decryption
            print(f"Decryption failed. Error: {e}. Likely incorrect password or corrupted data.")
            raise ValueError("Decryption failed. Check password or data integrity.")