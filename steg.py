# StegoVault/steg.py

from PIL import Image

# A delimiter to mark the end of the hidden message
DELIMITER = "1111111111111110" # A unique binary sequence unlikely to appear in data

def text_to_binary(text):
    """Converts a string of text to a binary string."""
    if isinstance(text, bytes):
        return ''.join(format(byte, '08b') for byte in text)
    return ''.join(format(ord(char), '08b') for char in text)

def binary_to_text(binary_str):
    """Converts a binary string back to a regular string."""
    # Ensure the binary string length is a multiple of 8
    if len(binary_str) % 8 != 0:
        raise ValueError("Binary string length is not a multiple of 8")
        
    all_bytes = [binary_str[i: i+8] for i in range(0, len(binary_str), 8)]
    text = bytearray()
    for byte in all_bytes:
        text.append(int(byte, 2))
    return bytes(text)

def embed_data(image_path, data_to_hide):
    """Embeds data into the LSB of an image."""
    try:
        image = Image.open(image_path).convert('RGB')
        binary_data = text_to_binary(data_to_hide) + DELIMITER
        
        data_len = len(binary_data)
        width, height = image.size
        max_capacity = width * height * 3

        if data_len > max_capacity:
            raise ValueError("Error: Message too large for the image.")

        new_image = image.copy()
        pixels = new_image.load()
        data_index = 0

        for y in range(height):
            for x in range(width):
                if data_index < data_len:
                    r, g, b = image.getpixel((x, y))
                    
                    # Modify Red channel
                    if data_index < data_len:
                        r = (r & 0xFE) | int(binary_data[data_index])
                        data_index += 1
                    
                    # Modify Green channel
                    if data_index < data_len:
                        g = (g & 0xFE) | int(binary_data[data_index])
                        data_index += 1
                    
                    # Modify Blue channel
                    if data_index < data_len:
                        b = (b & 0xFE) | int(binary_data[data_index])
                        data_index += 1
                        
                    pixels[x, y] = (r, g, b)
                else:
                    break
            if data_index >= data_len:
                break
        
        return new_image
        
    except FileNotFoundError:
        raise FileNotFoundError(f"Error: Image file not found at {image_path}")
    except Exception as e:
        raise Exception(f"An error occurred during embedding: {e}")

def extract_data(image_path):
    """Extracts hidden data from an image's LSB."""
    try:
        image = Image.open(image_path).convert('RGB')
        width, height = image.size
         
        binary_data = ""
        for y in range(height):
            for x in range(width):
                r, g, b = image.getpixel((x, y))
                binary_data += str(r & 1)
                binary_data += str(g & 1)
                binary_data += str(b & 1)
                
                # Check for delimiter at every possible position
                if DELIMITER in binary_data:
                    # Remove the delimiter and return the message
                    message_part = binary_data.split(DELIMITER)[0]
                    return binary_to_text(message_part)
                    
        raise ValueError("Could not find the end-of-message delimiter.") 

    except FileNotFoundError:
        raise FileNotFoundError(f"Error: Image file not found at {image_path}")
    except Exception as e:
        raise Exception(f"An error occurred during extraction: {e}")