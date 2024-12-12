import os
import random
from rich.console import Console
from rich.text import Text
from cryptography import aes, des, rsa  # Import your cryptographic methods

# Initialize console for rich text output
console = Console()

# ASCII Art for AEGIS
ASCII_ART = Text(
    r"""
     █████╗ ███████╗ ██████╗ ██╗███████╗
    ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝
    ███████║█████╗  ██║  ███╗██║███████╗
    ██╔══██║██╔══╝  ██║   ██║██║╚════██║
    ██║  ██║███████╗╚██████╔╝██║███████║
    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝
    """,
    style="bold purple",
)

def list_crypto_methods():
    """List available cryptographic methods."""
    return {
        '1': 'AES',
        '2': 'DES',
        '3': 'RSA'
    }

def get_user_choice():
    """Get the user's choice of cryptographic method."""
    methods = list_crypto_methods()
    print("Choose a cryptographic method:")
    for key, value in methods.items():
        print(f"{key}: {value}")
    choice = input("Enter the number corresponding to your choice: ")
    return methods.get(choice)

def main():
    """Main function to execute the application."""
    console.print(ASCII_ART)  # Print the ASCII art for AEGIS
    print("Welcome to Aegis!")
    
    word = input("Enter a word to encrypt: ")
    method = get_user_choice()

    if method == 'AES':
        key = os.urandom(16)  # Generate a random key for AES
        encrypted = aes.encrypt(key, word)
        print(f"Encrypted (AES): {encrypted}")
        decrypted = aes.decrypt(key, encrypted)
        print(f"Decrypted (AES): {decrypted}")
    
    elif method == 'DES':
        key = os.urandom(8)  # Generate a random key for DES
        encrypted = des.encrypt(key, word)
        print(f"Encrypted (DES): {encrypted}")
        decrypted = des.decrypt(key, encrypted)
        print(f"Decrypted (DES): {decrypted}")

    elif method == 'RSA':
        private_key, public_key = rsa.generate_keypair()
        encrypted = rsa.encrypt(public_key, word)
        print(f"Encrypted (RSA): {encrypted}")
        decrypted = rsa.decrypt(private_key, encrypted)
        print(f"Decrypted (RSA): {decrypted}")
    
    else:
        print("Invalid method selected.")

if __name__ == "__main__":
    main()
