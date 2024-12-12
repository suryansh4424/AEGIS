# crypto_algorithms/playfair.py

import string

# Create Playfair cipher key square
def create_key_square(key: str) -> list:
    key = ''.join(sorted(set(key.upper()), key=lambda x: key.index(x)))  # Remove duplicates, maintain order
    key_square = key + ''.join([ch for ch in string.ascii_uppercase if ch != 'J' and ch not in key])
    return [key_square[i:i+5] for i in range(0, 25, 5)]

# Function to format plaintext (remove spaces and handle 'J' as 'I')
def format_text(plaintext: str) -> str:
    plaintext = plaintext.upper().replace('J', 'I').replace(' ', '')  # Replace 'J' with 'I'
    if len(plaintext) % 2 != 0:  # If odd length, append 'X' to make it even
        plaintext += 'X'
    return plaintext

# Function to find the position of a letter in the key square
def find_position(letter: str, key_square: list) -> tuple:
    for i, row in enumerate(key_square):
        if letter in row:
            return i, row.index(letter)
    return None

# Function to encrypt plaintext using Playfair Cipher
def encrypt_playfair(plaintext: str, key: str) -> str:
    key_square = create_key_square(key)
    plaintext = format_text(plaintext)
    ciphertext = []
    
    # Process each pair of characters
    for i in range(0, len(plaintext), 2):
        char1, char2 = plaintext[i], plaintext[i+1]
        row1, col1 = find_position(char1, key_square)
        row2, col2 = find_position(char2, key_square)

        if row1 == row2:
            ciphertext.append(key_square[row1][(col1 + 1) % 5])
            ciphertext.append(key_square[row2][(col2 + 1) % 5])
        elif col1 == col2:
            ciphertext.append(key_square[(row1 + 1) % 5][col1])
            ciphertext.append(key_square[(row2 + 1) % 5][col2])
        else:
            ciphertext.append(key_square[row1][col2])
            ciphertext.append(key_square[row2][col1])
    
    return ''.join(ciphertext)

# Function to decrypt ciphertext using Playfair Cipher
def decrypt_playfair(ciphertext: str, key: str) -> str:
    key_square = create_key_square(key)
    ciphertext = format_text(ciphertext)
    plaintext = []
    
    # Process each pair of characters
    for i in range(0, len(ciphertext), 2):
        char1, char2 = ciphertext[i], ciphertext[i+1]
        row1, col1 = find_position(char1, key_square)
        row2, col2 = find_position(char2, key_square)

        if row1 == row2:
            plaintext.append(key_square[row1][(col1 - 1) % 5])
            plaintext.append(key_square[row2][(col2 - 1) % 5])
        elif col1 == col2:
            plaintext.append(key_square[(row1 - 1) % 5][col1])
            plaintext.append(key_square[(row2 - 1) % 5][col2])
        else:
            plaintext.append(key_square[row1][col2])
            plaintext.append(key_square[row2][col1])

    return ''.join(plaintext).rstrip('X')  # Remove any padding X
