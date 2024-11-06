import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Function to generate RSA keys
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()  # Export private key in PEM format (bytes)
    public_key = key.publickey().export_key()  # Export public key in PEM format (bytes)
    return private_key, public_key

# Function to encrypt data using RSA public key
def encrypt(public_key, plaintext):
    public_key = RSA.import_key(public_key)  # Import public key from PEM format (bytes)
    cipher = PKCS1_OAEP.new(public_key)
    encrypted = cipher.encrypt(plaintext.encode())  # Encrypt plaintext
    # Encode encrypted bytes to base64 for human-readable format
    encrypted_base64 = base64.b64encode(encrypted).decode('utf-8')
    return encrypted_base64

# Function to decrypt data using RSA private key
def decrypt(private_key, ciphertext):
    private_key = RSA.import_key(private_key)  # Import private key from PEM format (bytes)
    cipher = PKCS1_OAEP.new(private_key)
    # Decode from base64 to binary data
    encrypted_data = base64.b64decode(ciphertext)
    decrypted = cipher.decrypt(encrypted_data)  # Decrypt ciphertext
    return decrypted.decode()  # Return decrypted text as string

# Function to serialize the RSA key to PEM format
def serialize_key(key, private=False):
    if private:
        # Return the private key in PEM format (already in byte string format)
        return key
    else:
        # Import the key back into an RSA object before exporting the public key
        public_key = RSA.import_key(key)  # Re-import the public key from bytes
        return public_key.export_key()  # Export public key in PEM format (bytes)
