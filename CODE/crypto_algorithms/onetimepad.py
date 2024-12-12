import os

def encrypt_onetime_pad(plaintext: str) -> (str, str):
    key = os.urandom(len(plaintext))
    ciphertext = ''.join(chr((ord(p) ^ key[i]) % 256) for i, p in enumerate(plaintext))
    return ciphertext, key.hex()  # Return key in hexadecimal

def decrypt_onetime_pad(ciphertext: str, key: str) -> str:
    key_bytes = bytes.fromhex(key)
    decrypted = ''.join(chr((ord(c) ^ key_bytes[i]) % 256) for i, c in enumerate(ciphertext))
    return decrypted
