def encrypt_rail_fence(plaintext: str, key: int) -> str:
    rail = [['\n' for i in range(len(plaintext))]
            for j in range(key)]

    dir_down = None
    row, col = 0, 0

    for char in plaintext:
        if row == 0:
            dir_down = True
        if row == key - 1:
            dir_down = False
        rail[row][col] = char
        col += 1
        row += 1 if dir_down else -1

    encrypted = ""
    for r in rail:
        for c in r:
            if c != '\n':
                encrypted += c
    return encrypted

def decrypt_rail_fence(ciphertext: str, key: int) -> str:
    rail = [['\n' for i in range(len(ciphertext))]
            for j in range(key)]
    dir_down = None
    row, col = 0, 0

    for char in ciphertext:
        if row == 0:
            dir_down = True
        if row == key - 1:
            dir_down = False
        rail[row][col] = '*'
        col += 1
        row += 1 if dir_down else -1

    index = 0
    for i in range(key):
        for j in range(len(ciphertext)):
            if (rail[i][j] == '*' and index < len(ciphertext)):
                rail[i][j] = ciphertext[index]
                index += 1

    result = []
    row, col = 0, 0
    for i in range(len(ciphertext)):
        if row == 0:
            dir_down = True
        if row == key - 1:
            dir_down = False
        if rail[row][col] != '\n':
            result.append(rail[row][col])
            col += 1
        row += 1 if dir_down else -1

    return "".join(result)
