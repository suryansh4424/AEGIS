# Affine Cipher Implementation
def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a

def mod_inverse(a: int, m: int) -> int:
    # Extended Euclidean Algorithm for finding modular inverse
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None

def encrypt_affine(plaintext: str, a: int, b: int) -> str:
    result = ""
    for char in plaintext:
        if char.isalpha():
            shift_base = ord('A') if char.isupper() else ord('a')
            result += chr((a * (ord(char) - shift_base) + b) % 26 + shift_base)
        else:
            result += char
    return result

def decrypt_affine(ciphertext: str, a: int, b: int) -> str:
    a_inv = mod_inverse(a, 26)
    if a_inv is None:
        return "Invalid key 'a' value for decryption (no modular inverse)."
    
    result = ""
    for char in ciphertext:
        if char.isalpha():
            shift_base = ord('A') if char.isupper() else ord('a')
            result += chr((a_inv * (ord(char) - shift_base - b)) % 26 + shift_base)
        else:
            result += char
    return result
