def encrypt_scytale(plaintext: str, key: int) -> str:
    plaintext += 'X' * (key - len(plaintext) % key)  # Padding with 'X'
    ciphertext = ''
    for i in range(key):
        for j in range(i, len(plaintext), key):
            ciphertext += plaintext[j]
    return ciphertext

def decrypt_scytale(ciphertext: str, key: int) -> str:
    num_of_rows = len(ciphertext) // key
    plaintext = [''] * num_of_rows
    
    for i in range(num_of_rows):
        for j in range(key):
            index = j * num_of_rows + i
            if index < len(ciphertext):
                plaintext[i] += ciphertext[index]
    
    return ''.join(plaintext)
