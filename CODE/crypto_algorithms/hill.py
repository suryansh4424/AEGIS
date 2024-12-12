import numpy as np

def mod_inverse(a: int, m: int) -> int:
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None

def encrypt_hill(plaintext: str, key_matrix: list) -> str:
    while len(plaintext) % len(key_matrix) != 0:
        plaintext += 'X'  # Padding with 'X'
    plaintext = [ord(char) - 65 for char in plaintext.upper()]
    ciphertext = []
    
    for i in range(0, len(plaintext), len(key_matrix)):
        vector = np.array(plaintext[i:i+len(key_matrix)])
        result = np.dot(key_matrix, vector) % 26
        ciphertext.extend(result)
        
    return ''.join(chr(num + 65) for num in ciphertext)

def decrypt_hill(ciphertext: str, key_matrix: list) -> str:
    determinant = int(round(np.linalg.det(key_matrix)))
    inv_determinant = mod_inverse(determinant % 26, 26)
    adjugate_matrix = np.round(np.linalg.inv(key_matrix) * determinant).astype(int) % 26
    
    key_inverse_matrix = (inv_determinant * adjugate_matrix) % 26
    ciphertext = [ord(char) - 65 for char in ciphertext.upper()]
    plaintext = []
    
    for i in range(0, len(ciphertext), len(key_matrix)):
        vector = np.array(ciphertext[i:i+len(key_matrix)])
        result = np.dot(key_inverse_matrix, vector) % 26
        plaintext.extend(result)
        
    return ''.join(chr(num + 65) for num in plaintext)
