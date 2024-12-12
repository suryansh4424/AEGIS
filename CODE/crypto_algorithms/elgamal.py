def elgamal_encrypt(prime: int, base: int, private_key: int, message: int) -> (int, int):
    import random
    k = random.randint(1, prime - 2)
    c1 = (base ** k) % prime
    c2 = (message * (pow(base, private_key, prime))) % prime
    return c1, c2

def elgamal_decrypt(prime: int, private_key: int, c1: int, c2: int) -> int:
    s = pow(c1, private_key, prime)
    message = (c2 * pow(s, prime - 2, prime)) % prime  # s^(p-2) is the modular inverse
    return message
