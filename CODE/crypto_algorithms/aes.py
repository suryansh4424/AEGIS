from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import base64

def generate_random_key():
    """Generate a random 32-byte key for AES-256"""
    return os.urandom(32)  # AES-256 key length is 32 bytes

def aes_encrypt(plaintext, key=None):
    """
    Encrypts the given plaintext using AES encryption in CBC mode with PKCS7 padding.
    The function returns the encrypted text (ciphertext) and IV, both encoded in base64 for easy transmission.
    """
    # If no key is provided, generate a random one
    if key is None:
        key = generate_random_key()

    # Ensure the key length is either 16, 24, or 32 bytes
    if len(key) not in [16, 24, 32]:
        raise ValueError("Key length must be 16, 24, or 32 bytes.")

    # Generate a random 16-byte IV
    iv = os.urandom(16)

    # Pad the plaintext to be a multiple of the block size (16 bytes for AES)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    # AES encryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Base64 encode the ciphertext and IV for easier handling in the frontend
    iv_base64 = base64.b64encode(iv).decode('utf-8')
    ciphertext_base64 = base64.b64encode(ciphertext).decode('utf-8')

    # Return both IV and ciphertext as base64 strings
    return iv_base64, ciphertext_base64, base64.b64encode(key).decode('utf-8')  # Return the key as base64 as well
