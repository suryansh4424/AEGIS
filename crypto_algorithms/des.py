from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt(key, plaintext):
    # Ensure DES key is 8 bytes (64 bits)
    if len(key) != 8:
        raise ValueError("Key must be 8 bytes long for DES.")
    
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Padding plaintext to be a multiple of 8 bytes
    padded_text = plaintext.ljust(8 * ((len(plaintext) + 7) // 8))
    ciphertext = encryptor.update(padded_text.encode()) + encryptor.finalize()
    return ciphertext

def decrypt(key, ciphertext):
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_text.decode().strip()
