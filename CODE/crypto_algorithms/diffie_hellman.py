import random

# Function to compute power of a number with modulo operation (used for Diffie-Hellman)
def mod_exp(base: int, exp: int, mod: int) -> int:
    return pow(base, exp, mod)

# Generate a random private key for Diffie-Hellman
def generate_private_key() -> int:
    return random.randint(2, 100)  # Private key is a random number between 2 and 100

# Generate the public key for Diffie-Hellman
def generate_public_key(pri_key: int, g: int, p: int) -> int:
    return mod_exp(g, pri_key, p)  # Public key = g^pri_key mod p

# Compute the shared secret key from the public key of the other party and the private key
def compute_shared_secret(other_public_key: int, pri_key: int, p: int) -> int:
    return mod_exp(other_public_key, pri_key, p)  # Shared secret = other_public_key^pri_key mod p
