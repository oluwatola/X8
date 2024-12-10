#!/usr/bin/python3

import os
import mimetypes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Helper Functions
def save_file(filepath, data):
    """Save data to a file."""
    with open(filepath, 'wb') as file:
        file.write(data)

def load_file(filepath):
    """Load data from a file."""
    with open(filepath, 'rb') as file:
        return file.read()

def validate_file(filepath, description):
    """Ensure the file exists and is valid."""
    while not os.path.isfile(filepath):
        print(f"Error: {description} file not found: {filepath}")
        filepath = input(f"Please enter a valid path for the {description}: ")
    return filepath

def validate_directory(dirpath, description):
    """Ensure the directory exists."""
    while not os.path.isdir(dirpath):
        print(f"Error: {description} directory not found: {dirpath}")
        dirpath = input(f"Please enter a valid path for the {description}: ")
    return dirpath

def is_image_file(filepath):
    """Check if the file is an image."""
    mime_type, _ = mimetypes.guess_type(filepath)
    if mime_type and mime_type.startswith('image/'):
        return True
    print(f"Error: The file '{filepath}' is not a valid image.")
    return False

# Encryption/Decryption Functions
def generate_rsa_keys(output_path):
    """Generate RSA public and private keys."""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    save_file(f"{output_path}_private.pem", private_key)
    save_file(f"{output_path}_public.pem", public_key)
    print("RSA keys generated and saved.")

def aes_encrypt(image_path, output_path):
    """Encrypt an image using AES."""
    image_data = load_file(image_path)
    aes_key = get_random_bytes(16)  # AES-128 key
    cipher = AES.new(aes_key, AES.MODE_CBC)
    encrypted_image = cipher.encrypt(pad(image_data, AES.block_size))
    save_file(f"{output_path}_encrypted.img", encrypted_image)
    save_file(f"{output_path}_aes_key.bin", aes_key)
    save_file(f"{output_path}_aes_iv.bin", cipher.iv)
    print("Image encrypted using AES. Files saved.")

def aes_decrypt(encrypted_image_path, aes_key_path, iv_path, output_path):
    """Decrypt an image using AES."""
    encrypted_image = load_file(encrypted_image_path)
    aes_key = load_file(aes_key_path)
    iv = load_file(iv_path)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    decrypted_image = unpad(cipher.decrypt(encrypted_image), AES.block_size)
    save_file(output_path, decrypted_image)
    print("Image decrypted using AES. File saved.")

def rsa_encrypt(image_path, public_key_path, output_path):
    """Encrypt an image using RSA."""
    image_data = load_file(image_path)
    public_key = RSA.import_key(load_file(public_key_path))
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_image = cipher.encrypt(image_data)
    save_file(f"{output_path}_encrypted.img", encrypted_image)
    print("Image encrypted using RSA. File saved.")

def rsa_decrypt(encrypted_image_path, private_key_path, output_path):
    """Decrypt an image using RSA."""
    encrypted_image = load_file(encrypted_image_path)
    private_key = RSA.import_key(load_file(private_key_path))
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_image = cipher.decrypt(encrypted_image)
    save_file(output_path, decrypted_image)
    print("Image decrypted using RSA. File saved.")

def hybrid_encrypt(image_path, public_key_path, output_path):
    """Encrypt an image using hybrid encryption (AES + RSA)."""
    image_data = load_file(image_path)
    aes_key = get_random_bytes(16)  # AES-128 key
    aes_cipher = AES.new(aes_key, AES.MODE_CBC)
    encrypted_image = aes_cipher.encrypt(pad(image_data, AES.block_size))
    public_key = RSA.import_key(load_file(public_key_path))
    rsa_cipher = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = rsa_cipher.encrypt(aes_key)
    save_file(f"{output_path}_encrypted_image.img", encrypted_image)
    save_file(f"{output_path}_encrypted_aes_key.bin", encrypted_aes_key)
    save_file(f"{output_path}_aes_iv.bin", aes_cipher.iv)
    print("Image encrypted using Hybrid encryption. Files saved.")

def hybrid_decrypt(encrypted_image_path, encrypted_key_path, iv_path, private_key_path, output_path):
    """Decrypt an image using hybrid encryption (AES + RSA)."""
    encrypted_image = load_file(encrypted_image_path)
    encrypted_aes_key = load_file(encrypted_key_path)
    iv = load_file(iv_path)
    private_key = RSA.import_key(load_file(private_key_path))
    rsa_cipher = PKCS1_OAEP.new(private_key)
    aes_key = rsa_cipher.decrypt(encrypted_aes_key)
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    decrypted_image = unpad(aes_cipher.decrypt(encrypted_image), AES.block_size)
    save_file(output_path, decrypted_image)
    print("Image decrypted using Hybrid encryption. File saved.")

# Main Interface
def main():
    print("Image Encryption System")
    print("1. Generate RSA Keys")
    print("2. AES Encryption")
    print("3. AES Decryption")
    print("4. RSA Encryption (for files less than 245bytes only. For larger files, use Hybrid Encryption)")
    print("5. RSA Decryption")
    print("6. Hybrid Encryption")
    print("7. Hybrid Decryption")
    choice = input("Enter your choice (1-7): ")

    try:
        if choice == '1':
            output_path = validate_directory(input("Enter the directory to save RSA keys: "), "RSA keys")
            prefix = input("Enter a prefix for the keys: ")
            generate_rsa_keys(os.path.join(output_path, prefix))
        elif choice == '2':
            image_path = validate_file(input("Enter the path to the image: "), "Image")
            if is_image_file(image_path):
                output_path = validate_directory(input("Enter the output directory: "), "Output")
                prefix = input("Enter a prefix for encrypted files: ")
                aes_encrypt(image_path, os.path.join(output_path, prefix))
        elif choice == '3':
            encrypted_image = validate_file(input("Enter the encrypted image path: "), "Encrypted image")
            aes_key = validate_file(input("Enter the AES key path: "), "AES key")
            iv = validate_file(input("Enter the IV path: "), "AES IV")
            output_path = input("Enter the output file path for the decrypted image: ")
            aes_decrypt(encrypted_image, aes_key, iv, output_path)
        elif choice == '4':
            image_path = validate_file(input("Enter the path to the image: "), "Image")
            if is_image_file(image_path):
                public_key = validate_file(input("Enter the RSA public key path: "), "RSA public key")
                output_path = input("Enter the output file path: ")
                rsa_encrypt(image_path, public_key, output_path)
        elif choice == '5':
            encrypted_image = validate_file(input("Enter the encrypted image path: "), "Encrypted image")
            private_key = validate_file(input("Enter the RSA private key path: "), "RSA private key")
            output_path = input("Enter the output file path for the decrypted image: ")
            rsa_decrypt(encrypted_image, private_key, output_path)
        elif choice == '6':
            image_path = validate_file(input("Enter the path to the image: "), "Image")
            if is_image_file(image_path):
                public_key = validate_file(input("Enter the RSA public key path: "), "RSA public key")
                output_path = validate_directory(input("Enter the output directory: "), "Output")
                prefix = input("Enter a prefix for encrypted files: ")
                hybrid_encrypt(image_path, public_key, os.path.join(output_path, prefix))
        elif choice == '7':
            encrypted_image = validate_file(input("Enter the encrypted image path: "), "Encrypted image")
            encrypted_key = validate_file(input("Enter the encrypted AES key path: "), "Encrypted AES key")
            iv = validate_file(input("Enter the AES IV path: "), "AES IV")
            private_key = validate_file(input("Enter the RSA private key path: "), "RSA private key")
            output_path = input("Enter the output file path for the decrypted image: ")
            hybrid_decrypt(encrypted_image, encrypted_key, iv, private_key, output_path)
        else:
            print("Invalid choice. Please restart the program and select a valid option.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()

