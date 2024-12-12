def create_polybius_square():
    square = {}
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # J is omitted
    for i in range(5):
        for j in range(5):
            square[alphabet[i * 5 + j]] = f"{i + 1}{j + 1}"
    return square

def encrypt_polybius(plaintext: str) -> str:
    square = create_polybius_square()
    return ''.join(square[char] for char in plaintext.upper() if char in square)

def decrypt_polybius(ciphertext: str) -> str:
    square = create_polybius_square()
    reverse_square = {v: k for k, v in square.items()}
    plaintext = ""
    
    for i in range(0, len(ciphertext), 2):
        pair = ciphertext[i:i + 2]
        if pair in reverse_square:
            plaintext += reverse_square[pair]
    
    return plaintext
