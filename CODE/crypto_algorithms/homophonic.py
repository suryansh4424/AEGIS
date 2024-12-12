import random

def create_homophonic_substitution(key_mapping):
    homophonic_mapping = {}
    for key, values in key_mapping.items():
        for value in values:
            homophonic_mapping[value] = key
    return homophonic_mapping

def encrypt_homophonic(plaintext: str, homophonic_mapping: dict) -> str:
    ciphertext = ""
    for char in plaintext:
        if char in homophonic_mapping:
            ciphertext += random.choice(homophonic_mapping[char])
        else:
            ciphertext += char
    return ciphertext

def decrypt_homophonic(ciphertext: str, homophonic_mapping: dict) -> str:
    reverse_mapping = {v: k for k, v in homophonic_mapping.items()}
    plaintext = ""
    for char in ciphertext:
        if char in reverse_mapping:
            plaintext += reverse_mapping[char]
        else:
            plaintext += char
    return plaintext
