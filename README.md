### Technical Deep Dive

#### 1. Steganography Basics (LSB)

Steganography is the art of hiding a message within another, non-secret medium. The goal is to conceal the very existence of the message. Our project uses **Least Significant Bit (LSB)** steganography, one of the simplest and most common techniques.

- **How it Works**: Every pixel in a standard RGB image is represented by three 8-bit values (Red, Green, Blue). LSB steganography modifies the *last bit* (the least significant one) of each of these values to store a bit from the secret message.
- **Capacity**: For an image of `W x H` pixels, the total capacity is `W * H * 3` bits, as we can use one bit from each of the R, G, and B channels per pixel.
- **Why it's Stealthy**: Changing the LSB of a color value alters its total value by at most 1 (out of 256). This change is visually imperceptible to the human eye, making the "stego-image" look identical to the original.
- **Delimiter**: To know when the message ends during extraction, we append a unique binary sequence (`1111111111111110`) to our data. The extraction process stops once this delimiter is found.

#### 2. AES Integration for Security

LSB steganography only provides stealth, not security. If an attacker knows to look for LSB-encoded data, they can easily extract it. To protect the *content* of the message, we encrypt it before embedding.

- **Algorithm**: We chose **AES (Advanced Encryption Standard)**, the industry standard for symmetric encryption. We use a 256-bit key for strong security.
- **Key Derivation**: A user-provided password is not a secure cryptographic key on its own. We use **PBKDF2 (Password-Based Key Derivation Function 2)** to convert the password into a robust 256-bit key. PBKDF2 adds a `salt` and performs many iterations (`100,000` in our case) to make brute-force attacks against the password extremely slow.
- **Cipher Mode (CBC)**: We use **Cipher Block Chaining (CBC)** mode. In CBC, each block of plaintext is XORed with the previous ciphertext block before being encrypted. This ensures that identical plaintext blocks produce different ciphertext blocks. An **Initialization Vector (IV)** is used to randomize the encryption of the first block and is prepended to the final ciphertext so it can be used for decryption.

The overall workflow is:
`Plaintext Message` -> **AES Encrypt (with password)** -> `Encrypted Bytes` -> **LSB Embed** -> `Stego-Image`

#### 3. Security Trade-offs

- **Stealth vs. Robustness**: LSB is stealthy but fragile. Any image compression (like saving to JPEG), resizing, or color correction will destroy the hidden data. This is why we default to using and saving as PNG, a lossless format.
- **Detection**: While visually undetectable, standard sequential LSB embedding can be detected by statistical steganalysis tools that look for anomalies in the LSB plane of an image. Our implementation is vulnerable to this.
- **Content Security**: The use of AES-256 means that even if the presence of a hidden message is detected, the content remains confidential without the correct password. The security of the message relies entirely on the strength of the password and the AES algorithm.

#### 4. Future Improvements

- **Image Quality Analyzer (PSNR)**: Implement a function to calculate the Peak Signal-to-Noise Ratio (PSNR) between the original and stego-image. This provides a quantitative measure of how much the image was altered. It would require `numpy` for efficient calculations.
- **Stealth Mode (Randomized LSBs)**: Instead of embedding data sequentially, use the password to seed a random number generator. This generator would produce a reproducible, pseudo-random sequence of pixel coordinates for embedding. This makes the hidden data much harder to detect with standard steganalysis tools.
- **Support for More File Types**: Extend the logic to work with other lossless image formats (e.g., BMP, TIFF) or even other media like audio files (WAV).
- **Variable Salt**: Generate a new random salt for each encryption and prepend it to the IV and ciphertext. This is a more secure practice than using a static salt, as it prevents pre-computation attacks (like rainbow tables) on a per-message basis.
- **Error Correction Codes**: Integrate a simple error correction code (like a Reed-Solomon code) to make the hidden data more resilient to minor, accidental modifications of the stego-image.
