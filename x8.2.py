#!/usr/bin/python3

import os
import sys
import logging
import tkinter
import tempfile
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from tkinter import Tk, Label, Button, Entry, filedialog, messagebox, OptionMenu, StringVar, Checkbutton, IntVar, ttk
import customtkinter as ctk
from datetime import datetime, UTC, timedelta
import subprocess
import threading
from queue import Queue

# Constants
CHUNK_SIZE_RSA = 190  # For RSA-2048, max chunk size for encryption is 190 bytes
AES_KEY_SIZE = 256  # in bits
AES_IV_SIZE = 16  # in bytes
LOG_FILE = 'encryption_log.txt'

# Setup Logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Queue for GUI updates
update_queue = Queue()

def background_worker(func):
    def wrapper(*args, **kwargs):
        thread = threading.Thread(target=func, args=args, kwargs=kwargs)
        thread.start()
        return thread
    return wrapper

# Key Management
def generate_rsa_key_pair():
    try:
        # Generate private key
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-out', 'private_key.pem', '-pkeyopt', 'rsa_keygen_bits:2048'], check=True)
        
        # Extract public key from private key
        subprocess.run(['openssl', 'rsa', '-pubout', '-in', 'private_key.pem', '-out', 'public_key.pem'], check=True)
        
        print("RSA key pair generated and saved successfully as 'private_key.pem' and 'public_key.pem'.")
        return 'private_key.pem', 'public_key.pem'
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to generate RSA key pair with OpenSSL: {e}")

def reformat_pem(pem_data):
    # Assuming pem_data is bytes, decode to string
    pem_str = pem_data.decode('utf-8')
    parts = pem_str.split('\n')
    header = next((line for line in parts if line.startswith('-----BEGIN')), None)
    footer = next((line for line in parts if line.startswith('-----END')), None)
    if header and footer:
        content = ''.join([line for line in parts if not line.startswith('-----')])
        import textwrap
        reformatted_content = textwrap.fill(content, 64)
        return (header + '\n' + reformatted_content + '\n' + footer).encode('utf-8')
    return pem_data  # If not reformatted, return original


def save_key(key_data, key_type):
    file_path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM files", "*.pem")])
    if not file_path:
        raise FileNotFoundError(f"No location selected to save {key_type} key")
    with open(file_path, "wb") as key_file:
        key_file.write(key_data)
    return file_path

def save_cert(cert_data, cert_type):
    file_path = filedialog.asksaveasfilename(defaultextension=".crt", filetypes=[("cert files", "*.crt")])
    if not file_path:
        raise FileNotFoundError(f"No location selected to save {cert_type} key")
    with open(file_path, "wb") as cert_file:
        cert_file.write(cert_data)
    return file_path

def generate_self_signed_cert(private_key_pem, common_name='localhost'):
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem, password=None, backend=default_backend()
        )
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(UTC)
        ).not_valid_after(
            datetime.now(UTC) + timedelta(days=365)
        ).sign(private_key, hashes.SHA256(), default_backend())
        return cert.public_bytes(serialization.Encoding.PEM)
    except Exception as e:
        logging.error(f"Failed to generate self-signed certificate: {e}")
        raise

def get_public_key_from_cert(cert_data):
    try:
        # Load the certificate
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        
        # Get the public key
        public_key = cert.public_key()
        
        # Serialize to PEM format
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return public_key_pem
    except Exception as e:
        logging.error(f"Failed to extract public key from certificate: {e}")

def get_certbot_cert(domain):
    try:
        result = subprocess.run(['certbot', 'certonly', '--standalone', '-d', domain], 
                                capture_output=True, text=True, check=True)
        if result.returncode != 0:
            raise RuntimeError(f"Certbot failed to get certificate: {result.stderr}")

        cert_path = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
        key_path = f"/etc/letsencrypt/live/{domain}/privkey.pem"

        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            raise FileNotFoundError("Certificate or key file not found after Certbot execution.")

        return cert_path, key_path
    except Exception as e:
        logging.error(f"Failed to get Let's Encrypt certificate: {e}")
        raise

# Encryption/Decryption
def aes_encrypt(data, aes_key):
    iv = get_random_bytes(AES_IV_SIZE)
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    print("AES encryption done")
    return iv + tag + ciphertext

def aes_decrypt(data, aes_key):
    iv = data[:AES_IV_SIZE]
    tag = data[AES_IV_SIZE:AES_IV_SIZE+16]
    ciphertext = data[AES_IV_SIZE+16:]
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=iv)
    return cipher.decrypt_and_verify(ciphertext, tag)

def rsa_encrypt_decrypt(data, key, encrypt=True):
    if encrypt:
        chunk_size = CHUNK_SIZE_RSA  # 190 for RSA-2048
        encrypted_chunks = []
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(key))
        
        total_size = len(data)
        encrypted_chunks.append(total_size.to_bytes(8, 'big'))
        
        for i in range(0, total_size, chunk_size):
            chunk = data[i:i+chunk_size]
            encrypted_chunks.append(cipher_rsa.encrypt(chunk))
        
        output = b''.join(encrypted_chunks)
        print("Image encrypted using RSA.")
        return output
    else:
        encrypted_chunks = []
        total_size = int.from_bytes(data[:8], 'big')
        for i in range(8, len(data), 256):
            encrypted_chunks.append(data[i:i+256])
        
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(key))
        decrypted_chunks = []
        
        for chunk in encrypted_chunks:
            decrypted_chunks.append(cipher_rsa.decrypt(chunk))
        
        output = b''.join(decrypted_chunks)
        output = output[:total_size]
        print("RSA decryption complete.")
        return output

def sign_data(data, private_key):
    file_hash = SHA256.new(data)
    signer = pkcs1_15.new(private_key)
    print("Signature data created")
    return signer.sign(file_hash)

def verify_signature(data, signature, public_key):
    file_hash = SHA256.new(data)
    verifier = pkcs1_15.new(public_key)
    try:
        verifier.verify(file_hash, signature)
        return True
        print("Signature verified")
    except (ValueError, TypeError):
        return False

# File Operations
@background_worker
def batch_encrypt_files(file_paths, encryption_method, public_key_path=None, private_key_path=None, cert_path=None, key_rotation=False):
    for file_path in file_paths.split(', '):
        if file_path:  # Ensure the path is not empty
            try:
                encrypt_file(file_path, encryption_method, public_key_path, private_key_path, cert_path, key_rotation)
            except Exception as e:
                logging.error(f"Encryption failed for {file_path}: {e}")
                update_queue.put(("Error", f"Encryption failed for {file_path}: {e}"))

@background_worker
def batch_decrypt_files(encrypted_file_paths, aes_key_path=None, private_key_path=None, public_key_path=None):
    for encrypted_file_path in encrypted_file_paths.split(', '):
        if encrypted_file_path:  # Ensure the path is not empty
            try:
                decrypt_file(encrypted_file_path, aes_key_path, private_key_path, public_key_path)
            except Exception as e:
                logging.error(f"Decryption failed for {encrypted_file_path}: {e}")
                update_queue.put(("Error", f"Decryption failed for {encrypted_file_path}: {e}"))

@background_worker
def encrypt_file(file_path, encryption_method, public_key_path=None, private_key_path=None, cert_path=None, key_rotation=False):
    try:
        with open(file_path, 'rb') as f:
            plaintext = f.read()
        print(f"Plaintext read from file, length: {len(plaintext)}")
        
        if encryption_method == 'AES':
            aes_key = get_random_bytes(AES_KEY_SIZE // 8)
            ciphertext = aes_encrypt(plaintext, aes_key)
            file_extension = '.aes'
            
            # Save the AES key with .key extension
            aes_key_path = file_path + '.key'
            with open(aes_key_path, 'wb') as aes_key_file:
                aes_key_file.write(aes_key)
                print(f"AES key saved to: {aes_key_path}")

            if not private_key_path:
                raise ValueError("A private key is required for signing AES encrypted files. Please provide one.")
            with open(private_key_path, 'rb') as private_key_file:
                signing_key = RSA.import_key(private_key_file.read())
        
        elif encryption_method == 'RSA':
            #if not public_key_path:
            #    private_key_path, public_key_path = generate_rsa_key_pair()
            with open(public_key_path, 'rb') as public_key_file:
                public_key = public_key_file.read()
            with open(private_key_path, 'rb') as private_key_file:
                private_key = private_key_file.read()
                signing_key = RSA.import_key(private_key)

            ciphertext = rsa_encrypt_decrypt(plaintext, public_key, encrypt=True)
            file_extension = '.rsa'

        elif encryption_method == 'Hybrid':
#            aes_key = get_random_bytes(AES_KEY_SIZE // 8)
#            ciphertext = aes_encrypt(plaintext, aes_key)
#            file_extension = '.hyb'
            
            # Encrypt the AES key with RSA
            if not public_key_path or not private_key_path:
                raise ValueError("Public key required for encrypting AES key, private key required for signing. Please provide one.")
            with open(public_key_path, 'rb') as public_key_file:
                public_key = public_key_file.read()
            with open(private_key_path, 'rb') as private_key_file:
                private_key = private_key_file.read()
                signing_key = RSA.import_key(private_key)

            aes_key = get_random_bytes(AES_KEY_SIZE // 8)
            ciphertext = aes_encrypt(plaintext, aes_key)
            file_extension = '.hyb'
            rsa_cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
            encrypted_aes_key = rsa_cipher.encrypt(aes_key)
            
            # Combine encrypted AES key with AES-encrypted data
            ciphertext = encrypted_aes_key + ciphertext
            #signing_key_path = private_key_path if private_key_path else (lambda: messagebox.showerror("Error", "Please provide private keys for signing.") or sys.exit())()
        else:
            raise ValueError("Invalid encryption method")

        # Sign the ciphertext
        #with open(signing_key_path, 'rb') as signing_key_file:
        #    signing_key = RSA.import_key(signing_key_file.read())
        signature = sign_data(ciphertext, signing_key)
        print(f"Signature created, length: {len(signature)}")

        # Prepare output
        output = ciphertext + signature  # This is the core of the encrypted data

        # If using a certificate, append it to the output
        if cert_path:
            with open(cert_path, 'rb') as cert_file:
                cert_data = cert_file.read()
            print(f"Certificate data read, length: {len(cert_data)}")
            
            # Ensure certificate data is not empty
            if not cert_data:
                raise ValueError("Certificate file is empty or could not be read.")
            
            # Append certificate length (4 bytes) and certificate data
            output += cert_data + len(cert_data).to_bytes(4, 'big')
            print(f"Certificate appended to output, total length: {len(output)}")
        else:
            print("No certificate appended.")

        output_file_path = file_path + file_extension
        with open(output_file_path, 'wb') as f:
            f.write(output)
            print(f"Encrypted file written to: {output_file_path}")
        
        update_queue.put(("Success", f"File encrypted successfully to {output_file_path}"))
    except Exception as e:
        logging.error(f"Encryption failed: {e}")
        update_queue.put(("Error", str(e)))


@background_worker
def decrypt_file(encrypted_file_path, aes_key_path=None, private_key_path=None, public_key_path=None):
    try:
        with open(encrypted_file_path, 'rb') as f:
            data = f.read()
            print(f"Data read from file, length: {len(data)}")

        # Check entire length for possibility of a certificate
        if len(data) > 256 + 4:  # Enough for signature + cert length data
            print("Possible certificate data detected.")
            
            # Check the last 4 bytes for the certificate length
            cert_length = int.from_bytes(data[-4:], 'big')
            print(f"Certificate length: {cert_length}")

            # Ensure there's enough data for the claimed certificate length
            if len(data) >= cert_length + 4 + 256:  # Cert length + length field + signature
                signature_end = len(data) - 256 - cert_length - 4
                signature = data[signature_end:signature_end + 256]
                cert_data = data[signature_end + 256:-4]  # Exclude last 4 bytes (cert length)
                ciphertext = data[:signature_end]
                
                
                try:
                    # Write certificate data to a temporary file
                    with open('temp_cert.crt', 'wb') as temp_cert_file:
                        temp_cert_file.write(cert_data)

                    # Extract the public key using OpenSSL
                    subprocess.run(['openssl', 'x509', '-pubkey', '-noout', '-in', 'temp_cert.crt'], 
                                   stdout=open('temp_pub_key.pem', 'wb'), check=True)
                    
                    print("Public key extracted and saved to temp_pub_key.pem")

                    with open('temp_pub_key.pem', 'rb') as temp_public_key_file:
                        verifying_key = RSA.import_key(temp_public_key_file.read())

                    # Call verify_signature function with extracted public key
                    if not verify_signature(ciphertext, signature, verifying_key):
                        raise ValueError("Signature verification failed.")
                    print("Signature verified successfully.")
                except Exception as e:
                    print(f"Error in signature verification: {e}")
                    raise ValueError("Signature verification failed.")
                finally:
                    # Clean up temporary files
                    if os.path.exists('temp_cert.crt'):
                        os.remove('temp_cert.crt')
                    if os.path.exists('temp_pub_key.pem'):
                        os.remove('temp_pub_key.pem')
            else:

                print("Warning: Data length does not match claimed certificate length. Assuming no certificate.")
                # Fallback to provided public key
                if public_key_path and os.path.exists(public_key_path):
                    print(f"Using provided public key at: {public_key_path}")
                    # The rest of the data is considered ciphertext, and the last 256 bytes are the signature
                    signature = data[-256:]
                    ciphertext = data[:-256]
                    
                    # Verify signature with provided public key
                    with open(public_key_path, 'rb') as public_key_file:
                        verifying_key = RSA.import_key(public_key_file.read())

                    if not verify_signature(ciphertext, signature, verifying_key):
                        raise ValueError("Signature verification failed with provided public key.")
                    print("Signature verified successfully with provided public key.")
                else:
                    raise ValueError("No certificate detected and no public key provided.")
        else:
            print("No certificate data possible due to insufficient data length.")
            # Similar to above, if public key is provided, use it
            if public_key_path and os.path.exists(public_key_path):
                print(f"Using provided public key at: {public_key_path}")
                # The rest of the data is considered ciphertext, and the last 256 bytes are the signature
                signature = data[-256:]
                ciphertext = data[:-256]
                
                # Verify signature with provided public key
                if not verify_signature(ciphertext, signature, public_key_path):
                    raise ValueError("Signature verification failed with provided public key.")
                print("Signature verified successfully with provided public key.")
            else:
                raise ValueError("No certificate detected and no public key provided.")

         # Determine encryption method from file extension
        file_ext = os.path.splitext(encrypted_file_path)[1]
        print(f"File extension detected: {file_ext}")
        if file_ext == '.aes':
            if not aes_key_path:
                raise ValueError("AES key path is required for AES decryption.")
            with open(aes_key_path, 'rb') as key_file:
                aes_key = key_file.read()
            plaintext = aes_decrypt(ciphertext, aes_key)
        
        elif file_ext == '.rsa':
            if not private_key_path:
                raise ValueError("Private key path is required for RSA decryption.")
            with open(private_key_path, 'rb') as private_key_file:
                plaintext = rsa_encrypt_decrypt(ciphertext, private_key_file.read(), encrypt=False)
        
        elif file_ext == '.hyb':
            # Extract RSA-encrypted AES key
            key_size = 256  # Assuming RSA-2048
            encrypted_aes_key = ciphertext[:key_size]
            aes_ciphertext = ciphertext[key_size:]
            
            with open(private_key_path, 'rb') as private_key_file:
                private_key = RSA.import_key(private_key_file.read())
            rsa_cipher = PKCS1_OAEP.new(private_key)
            aes_key = rsa_cipher.decrypt(encrypted_aes_key)
            plaintext = aes_decrypt(aes_ciphertext, aes_key)
                
        else:
            raise ValueError("File does not have a recognized encryption extension.")

        output_file_path = os.path.splitext(encrypted_file_path)[0]
        with open(output_file_path, 'wb') as f:
            f.write(plaintext)
        
        update_queue.put(("Success", f"File decrypted successfully to {output_file_path}"))
    except Exception as e:
        logging.error(f"Decryption failed: {e}")
        update_queue.put(("Error", str(e)))


import customtkinter as ctk
from tkinter import filedialog, messagebox
import threading
from queue import Queue

# Assuming all other imports and functions are defined above this point

def gui():
    ctk.set_appearance_mode("system")  # Modes: system (default), light, dark
    ctk.set_default_color_theme("blue")  # Themes: blue (default), dark-blue, green

    root = ctk.CTk()
    root.title("X8 Image Encryption System")
    root.geometry("600x930")

    file_path = ctk.StringVar()
    encrypted_file_path = ctk.StringVar()
    encryption_method = ctk.StringVar(value='AES')
    use_existing_keys = ctk.IntVar(value=1)
    private_key_path = ctk.StringVar()
    public_key_path = ctk.StringVar()
    aes_key_path = ctk.StringVar()
    aes_key_paths = ctk.StringVar()
    multiple_aes_keys = ctk.StringVar()
    use_certificate = ctk.IntVar()
    cert_path = ctk.StringVar()
    key_rotation = ctk.IntVar()
    cert_type = ctk.StringVar(value='self-signed')
    domain_name = ctk.StringVar()
    domain_name_entry = None
    domain_name_label = None
    mode_var = ctk.StringVar(value="System")

    progress = ctk.CTkProgressBar(root, width=200, mode='indeterminate')

    def select_files():
        paths = filedialog.askopenfilenames(filetypes=[("Image files", "*.jpg *.png")])
        if paths:
            file_path.set(', '.join(paths))
        else:
            messagebox.showerror("Error", "No file(s) selected")

    def select_encrypted_files():
        paths = filedialog.askopenfilenames(filetypes=[("Encrypted files", "*.aes *.rsa *.hyb")])
        if paths:
            encrypted_file_path.set(', '.join(paths))
        else:
            messagebox.showerror("Error", "No encrypted file(s) selected")

    def select_rsa_key(key_path_var):
        path = filedialog.askopenfilename(filetypes=[("Key files", "*.pem")])
        if path:
            key_path_var.set(path)
        else:
            messagebox.showerror("Error", "No key file(s) selected")

    def select_aes_key(key_path_var):
        paths = filedialog.askopenfilenames(filetypes=[("Key files", "*.key")])
        if paths:
            key_path_var.set(', '.join(paths))
        else:
            messagebox.showerror("Error", "No AES key file(s) selected")

    def select_cert():
        path = filedialog.askopenfilename(filetypes=[("Certificate files", "*.crt")])
        if path:
            cert_path.set(path)
        else:
            messagebox.showerror("Error", "No certificate selected")

    def generate_keys():
        try:
            private_path, public_path = generate_rsa_key_pair()
            private_key_path.set(private_path)
            public_key_path.set(public_path)
            messagebox.showinfo("Success", "New RSA keys generated and saved.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def generate_certificate():
        try:
            if not private_key_path.get():
                raise ValueError("Please generate or select a private key first.")
            
            if cert_type.get() == 'self-signed':
                with open(private_key_path.get(), 'rb') as key_file:
                    cert_data = generate_self_signed_cert(key_file.read())
                cert_path.set(save_cert(cert_data, "certificate"))
                messagebox.showinfo("Success", "New self-signed certificate generated and saved.")
            else:  # Let's Encrypt
                if not domain_name.get():
                    raise ValueError("Please enter a domain name for Let's Encrypt.")
                cert_path_result, key_path_result = get_certbot_cert(domain_name.get())
                cert_path.set(cert_path_result)
                messagebox.showinfo("Success", f"Certificate from Let's Encrypt obtained and saved.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate or retrieve certificate: {e}")

    def queue_updater():
        try:
            while True:
                message_type, message = update_queue.get_nowait()
                if message_type == "Success":
                    messagebox.showinfo("Success", message)
                elif message_type == "Error":
                    messagebox.showerror("Error", message)
                progress.stop()
        except:
            # No message in queue, continue
            pass
        root.after(100, queue_updater)

    # ... (Keep the existing functions here like batch_encrypt_files, batch_decrypt_files, perform_action, reset_all_fields)
    @background_worker
    def batch_encrypt_files(file_paths, encryption_method, public_key_path=None, private_key_path=None, cert_path=None, key_rotation=False):
        for file_path in file_paths.split(', '):
            if file_path:  # Ensure the path is not empty
                try:
                    encrypt_file(file_path, encryption_method, public_key_path, private_key_path, cert_path, key_rotation)
                except Exception as e:
                    logging.error(f"Encryption failed for {file_path}: {e}")
                    update_queue.put(("Error", f"Encryption failed for {file_path}: {e}"))

    @background_worker
    def batch_decrypt_files(encrypted_file_paths, aes_key_paths=None, private_key_path=None, public_key_path=None):
        encrypted_files = encrypted_file_paths.split(', ')
        aes_keys = aes_key_paths.split(', ') if aes_key_paths else []

        # Check if any keys were selected
        if not aes_keys and not private_key_path:
            messagebox.showerror("Error", "No keys were selected for decryption. Please select AES keys for AES files or a private key for RSA/hybrid files.")
            update_queue.put(("Error", "No keys were selected for decryption."))
            return

        # Check if all key paths exist for AES
        for key_path in aes_keys:
            if not os.path.exists(key_path):
                messagebox.showerror("Error", f"The AES key file at {key_path} does not exist. Please check your selections.")
                update_queue.put(("Error", f"The AES key file at {key_path} does not exist."))
                return

        # Check if private key path exists for RSA/hybrid
        if private_key_path and not os.path.exists(private_key_path):
            messagebox.showerror("Error", f"The private key file at {private_key_path} does not exist. Please check your selection.")
            update_queue.put(("Error", f"The private key file at {private_key_path} does not exist."))
            return

        # Check if public key path exists
        if public_key_path and not os.path.exists(public_key_path):
            messagebox.showerror("Error", f"The public key file at {public_key_path} does not exist. Please check your selection.")
            update_queue.put(("Error", f"The public key file at {public_key_path} does not exist."))
            return

        # Check if the number of keys matches the number of files for AES
        aes_files = [f for f in encrypted_files if f.endswith('.aes')]
        rsa_files = [f for f in encrypted_files if f.endswith('.rsa')]
        hybrid_files = [f for f in encrypted_files if f.endswith('.hyb')]

        if len(aes_keys) != len(aes_files) and aes_files:
            messagebox.showerror("Error", f"The number of AES keys ({len(aes_keys)}) must exactly match the number of AES encrypted files ({len(aes_files)}).")
            update_queue.put(("Error", f"The number of AES keys ({len(aes_keys)}) must exactly match the number of AES encrypted files ({len(aes_files)})."))
            return

        for encrypted_file_path in encrypted_files:
            if encrypted_file_path:  # Ensure the path is not empty
                try:
                    if encrypted_file_path.endswith('.aes'):
                        # For AES decryption
                        if not aes_keys:
                            raise ValueError("No AES keys provided for AES decryption.")
                        index = aes_files.index(encrypted_file_path)
                        aes_key_to_use = aes_keys[index]
                        decrypt_file(encrypted_file_path, aes_key_path=aes_key_to_use, private_key_path=None, public_key_path=public_key_path)
                    elif encrypted_file_path.endswith('.rsa'):
                        # For RSA decryption
                        if not private_key_path:
                            raise ValueError("No private key provided for RSA decryption.")
                        decrypt_file(encrypted_file_path, aes_key_path=None, private_key_path=private_key_path, public_key_path=public_key_path)
                    elif encrypted_file_path.endswith('.hyb'):
                        # For hybrid decryption
                        if not private_key_path:
                            raise ValueError("No private key provided for hybrid decryption.")
                        decrypt_file(encrypted_file_path, aes_key_path=None, private_key_path=private_key_path, public_key_path=public_key_path)
                    else:
                        raise ValueError(f"Unsupported file extension for decryption: {os.path.splitext(encrypted_file_path)[1]}")
                except Exception as e:
                    logging.error(f"Decryption failed for {encrypted_file_path}: {e}")
                    update_queue.put(("Error", f"Decryption failed for {encrypted_file_path}: {e}"))

    def perform_action(action):
        try:
            if action == 'encrypt':
                if not file_path.get():
                    raise FileNotFoundError("Please select image file(s) to encrypt.")
                progress.start()
            
                if encryption_method.get() == 'RSA':
                    if not public_key_path.get() or not private_key_path.get():
                        response = messagebox.askyesno("RSA Keys Required", "No RSA keys found. Do you want to generate new keys?")
                        if response:
                            private_path, public_path = generate_rsa_key_pair()
                            private_key_path.set(private_path)
                            public_key_path.set(public_path)
                            messagebox.showinfo("Success", "New RSA keys generated and saved.")
                        else:
                            messagebox.showinfo("Action Required", "Please select existing RSA keys.")
                            if not public_key_path.get() or not private_key_path.get():
                                raise ValueError("RSA keys are required for encryption but not provided.")

                batch_encrypt_files(file_path.get(), encryption_method.get(),
                                    public_key_path=public_key_path.get() if encryption_method.get() in ['RSA', 'Hybrid'] else None,
                                    private_key_path=private_key_path.get(),
                                    cert_path=cert_path.get() if use_certificate.get() else None,
                                    key_rotation=key_rotation.get())
            elif action == 'decrypt':
                if not encrypted_file_path.get():
                    raise FileNotFoundError("Please select encrypted file(s) to decrypt.")
                progress.start()
            
                file_exts = [os.path.splitext(path)[1] for path in encrypted_file_path.get().split(', ') if path]
                if all(ext == '.aes' for ext in file_exts):
                    if not aes_key_path.get():
                        raise ValueError("Please select AES key(s) for decryption.")
                    batch_decrypt_files(encrypted_file_path.get(), 
                                        aes_key_paths=aes_key_path.get(), 
                                        private_key_path=private_key_path.get(), 
                                        public_key_path=public_key_path.get())
                elif all(ext == '.rsa' for ext in file_exts):
                    if not private_key_path.get():
                        raise ValueError("Please select a private key for decryption.")
                    batch_decrypt_files(encrypted_file_path.get(), 
                                        aes_key_paths=aes_key_path.get(), 
                                        private_key_path=private_key_path.get(), 
                                        public_key_path=public_key_path.get())
                elif all(ext == '.hyb' for ext in file_exts):
                    if not private_key_path.get():
                        raise ValueError("Please select a private key for hybrid decryption.")
                    batch_decrypt_files(encrypted_file_path.get(), 
                                        aes_key_paths=None,  # No separate AES key file for hybrid
                                        private_key_path=private_key_path.get(), 
                                        public_key_path=public_key_path.get())
                else:
                    raise ValueError("All files must have the same encryption extension.")
        except Exception as e:
            logging.error(f"GUI Action failed: {e}")
            messagebox.showerror("Error", str(e))
            progress.stop()



    def reset_all_fields():
        file_path.set("")
        encrypted_file_path.set("")
        encryption_method.set('AES')
        use_existing_keys.set(1)
        private_key_path.set("")
        public_key_path.set("")
        aes_key_path.set("")
        use_certificate.set(0)
        cert_path.set("")
        key_rotation.set(0)
        cert_type.set('self-signed')
        domain_name.set("")

    def toggle_dark_mode():
        current_mode = mode_var.get()
        if current_mode == "System":
            mode_var.set("Dark")
            ctk.set_appearance_mode("dark")
        elif current_mode == "Dark":
            mode_var.set("Light")
            ctk.set_appearance_mode("light")
        else:
            mode_var.set("System")
            ctk.set_appearance_mode("system")


#    def open_settings():
#        settings_window = ctk.CTkToplevel(root)
#        settings_window.title("Settings")
#        settings_window.geometry("300x200")
        
#        def change_theme_color():
#            color = colorchooser.askcolor(title="Choose Theme Color")[1]  # Returns (RGB, Hex)
#            if color:
#                # CustomTkinter doesn't have a direct way to change theme color, 
#                # but you can change individual widget colors. Here, we'll change 
#                # the primary button color as an example.
#                ctk.set_appearance_mode(ctk.get_appearance_mode())  # Refresh theme
#                ctk.set_default_color_theme("blue")  # Reset to default to ensure consistency
#                ctk.set_widget_scaling(1.0)  # Reset scaling
#
#                # Change the color of the primary button in buttons_frame
#                for widget in buttons_frame.winfo_children():
#                    if isinstance(widget, ctk.CTkButton):
#                        widget.configure(fg_color=color)
#
#        # Adding the color picker button in settings
#        color_picker_btn = ctk.CTkButton(settings_window, text="Choose Theme Color", command=change_theme_color)
#        color_picker_btn.pack(pady=20)

    # GUI elements using CustomTkinter
    ctk.CTkLabel(root, text="Select multiple files by holding Ctrl (Cmd on Mac)", font=("Arial", 10, "italic")).pack(pady=15)

    plaintext_image_frame = ctk.CTkFrame(root)
    plaintext_image_frame.pack(pady=5)
    ctk.CTkLabel(plaintext_image_frame, text="Select Image File (for encryption):   ").pack(side=ctk.LEFT)
    ctk.CTkButton(plaintext_image_frame, text="Browse", command=select_files).pack(side=ctk.LEFT)
    ctk.CTkEntry(root, textvariable=file_path, width=400).pack(pady=5)

    ciphertext_image_frame = ctk.CTkFrame(root)
    ciphertext_image_frame.pack(pady=5)
    ctk.CTkLabel(ciphertext_image_frame, text="Select Encrypted File (for decryption):   ").pack(side=ctk.LEFT)
    ctk.CTkButton(ciphertext_image_frame, text="Browse", command=select_encrypted_files).pack(side=ctk.LEFT)
    ctk.CTkEntry(root, textvariable=encrypted_file_path, width=400).pack(pady=5)

    encryption_method_frame = ctk.CTkFrame(root)
    encryption_method_frame.pack(pady=5)
    ctk.CTkLabel(encryption_method_frame, text="Encryption Method:   ").pack(side=ctk.LEFT)
    ctk.CTkOptionMenu(encryption_method_frame, variable=encryption_method, values=['AES', 'RSA', 'Hybrid']).pack(side=ctk.LEFT)

    ctk.CTkCheckBox(root, text="Use Existing Keys", variable=use_existing_keys).pack(pady=5)

    private_key_frame = ctk.CTkFrame(root)
    private_key_frame.pack(pady=5)
    ctk.CTkLabel(private_key_frame, text="Select Private Key:   ").pack(side=ctk.LEFT) #, command=lambda: select_rsa_key(private_key_path)).pack(pady=5)
    ctk.CTkButton(private_key_frame, text="Browse", command=lambda: select_rsa_key(private_key_path)).pack(pady=5)  #select_files).pack(side=ctk.LEFT)
    ctk.CTkEntry(root, textvariable=private_key_path, width=400).pack(pady=5)

    public_key_frame = ctk.CTkFrame(root)
    public_key_frame.pack(pady=5)
    ctk.CTkLabel(public_key_frame, text="Select Public Key:   ").pack(side=ctk.LEFT)  #, command=lambda: select_rsa_key(public_key_path)).pack(pady=5)
    ctk.CTkButton(public_key_frame, text="Browse", command=lambda: select_rsa_key(public_key_path)).pack(pady=5)  #select_files).pack(side=ctk.LEFT)
    ctk.CTkEntry(root, textvariable=public_key_path, width=400).pack(pady=5)

    aes_key_frame = ctk.CTkFrame(root)
    aes_key_frame.pack(pady=5)
    ctk.CTkLabel(aes_key_frame, text="Select AES Key (for AES decryption):   ").pack(side=ctk.LEFT)
    ctk.CTkButton(aes_key_frame, text="Browse", command=lambda: select_aes_key(aes_key_path)).pack(side=ctk.LEFT)
    ctk.CTkEntry(root, textvariable=aes_key_path, width=400).pack(pady=5)

    ctk.CTkCheckBox(root, text="Use Certificate", variable=use_certificate).pack(pady=5)

    ctk.CTkButton(root, text="Select Existing Certificate", command=select_cert).pack(pady=5)
    ctk.CTkEntry(root, textvariable=cert_path, width=400).pack(pady=5)

    cert_type_frame = ctk.CTkFrame(root)
    cert_type_frame.pack(pady=10)
    ctk.CTkButton(cert_type_frame, text="Generate Certificate", command=generate_certificate).pack(side=ctk.LEFT, padx=5)
    ctk.CTkLabel(cert_type_frame, text="Type:").pack(side=ctk.LEFT)
    ctk.CTkOptionMenu(cert_type_frame, variable=cert_type, values=['self-signed', 'Trusted CA']).pack(side=ctk.LEFT)

    domain_placeholder = ctk.CTkFrame(root, height=50, width=500)
    domain_placeholder.pack(pady=5)

    domain_name_frame = ctk.CTkFrame(domain_placeholder)
    ctk.CTkLabel(domain_name_frame, text="Domain Name:   ").pack(side=ctk.LEFT)
    domain_name_entry = ctk.CTkEntry(domain_name_frame, textvariable=domain_name, width=300)
    domain_name_entry.pack(side=ctk.LEFT, padx=5)

    def toggle_domain_name(*args):
        if cert_type.get() == "Trusted CA":
            domain_name_frame.pack(padx=5, pady=5)
        else:
            domain_name_frame.pack_forget()

    cert_type.trace('w', lambda *args: toggle_domain_name())

    toggle_domain_name()

    ctk.CTkCheckBox(root, text="Rotate Keys", variable=key_rotation).pack(pady=5)

    buttons_frame = ctk.CTkFrame(root)
    buttons_frame.pack(pady=10)
    ctk.CTkButton(buttons_frame, text="Encrypt", command=lambda: perform_action('encrypt')).pack(side=ctk.LEFT, padx=5)
    ctk.CTkButton(buttons_frame, text="Decrypt", command=lambda: perform_action('decrypt')).pack(side=ctk.LEFT, padx=5)

    progress.pack(pady=5)

    bottom_frame = ctk.CTkFrame(root)
    bottom_frame.pack(side=ctk.BOTTOM, padx=5, pady=5)

    left_buttons_frame = ctk.CTkFrame(bottom_frame)
    left_buttons_frame.pack(side=ctk.LEFT)
    ctk.CTkButton(left_buttons_frame, text="Generate RSA Keys", command=generate_keys).pack(side=ctk.LEFT, padx=5)

    right_buttons_frame = ctk.CTkFrame(bottom_frame)
    right_buttons_frame.pack(side=ctk.RIGHT)
    ctk.CTkButton(right_buttons_frame, text="Clear All", command=reset_all_fields).pack(side=ctk.RIGHT, padx=5)
    ctk.CTkButton(right_buttons_frame, text="Change Theme", command=toggle_dark_mode).pack(pady=5)
#    ctk.CTkButton(right_buttons_frame, text="Settings", command=open_settings).pack(side=ctk.RIGHT, padx=5)

    queue_updater()

    root.mainloop()

if __name__ == "__main__":
    gui()
