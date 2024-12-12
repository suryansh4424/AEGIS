def encrypt_transposition(plaintext: str, key: int) -> str:
    ciphertext = [''] * key
    for col in range(key):
        pointer = col
        while pointer < len(plaintext):
            ciphertext[col] += plaintext[pointer]
            pointer += key
    return ''.join(ciphertext)

def decrypt_transposition(ciphertext: str, key: int) -> str:
    num_of_cols = int(len(ciphertext) / key)
    num_of_rows = key
    num_shaded_boxes = (num_of_cols * num_of_rows) - len(ciphertext)

    plaintext = [''] * num_of_cols
    col, row = 0, 0
    for symbol in ciphertext:
        plaintext[col] += symbol
        col += 1
        if (col == num_of_cols) or (col == num_of_cols - 1 and row >= num_of_rows - num_shaded_boxes):
            col = 0
            row += 1
    return ''.join(plaintext)
