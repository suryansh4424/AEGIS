# crypto_algorithms/vigenere.py

import string

# Function to encrypt plaintext using Vigenère Cipher
def encrypt_vigenere(plaintext: str, key: str) -> str:
    key = key.upper()
    plaintext = plaintext.upper().replace(' ', '')  # Remove spaces and make uppercase
    key_repeated = (key * ((len(plaintext) // len(key)) + 1))[:len(plaintext)]  # Repeat key to match length of plaintext
    
    ciphertext = []
    for i in range(len(plaintext)):
        # For letters A-Z, calculate shift
        if plaintext[i] in string.ascii_uppercase:
            shift = ord(key_repeated[i]) - ord('A')
            new_char = chr(((ord(plaintext[i]) - ord('A') + shift) % 26) + ord('A'))
            ciphertext.append(new_char)
        else:
            ciphertext.append(plaintext[i])  # Non-alphabetic characters are unchanged
    
    return ''.join(ciphertext)

# Function to decrypt ciphertext using Vigenère Cipher
def decrypt_vigenere(ciphertext: str, key: str) -> str:
    key = key.upper()
    ciphertext = ciphertext.upper().replace(' ', '')  # Remove spaces and make uppercase
    key_repeated = (key * ((len(ciphertext) // len(key)) + 1))[:len(ciphertext)]  # Repeat key to match length of ciphertext
    
    plaintext = []
    for i in range(len(ciphertext)):
        # For letters A-Z, calculate shift
        if ciphertext[i] in string.ascii_uppercase:
            shift = ord(key_repeated[i]) - ord('A')
            new_char = chr(((ord(ciphertext[i]) - ord('A') - shift) % 26) + ord('A'))
            plaintext.append(new_char)
        else:
            plaintext.append(ciphertext[i])  # Non-alphabetic characters are unchanged
    
    return ''.join(plaintext)
