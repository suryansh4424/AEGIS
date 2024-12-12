def encrypt_xor(plaintext: str, key: str) -> str:
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(plaintext))

def decrypt_xor(ciphertext: str, key: str) -> str:
    return encrypt_xor(ciphertext, key)  # XOR decryption is the same as encryption
