import base64

def encode(plaintext: str) -> str:
    # Encode the plaintext string to Base64
    encoded_bytes = base64.b64encode(plaintext.encode('utf-8'))
    return encoded_bytes.decode('utf-8')

def decode(ciphertext: str) -> str:
    # Decode the Base64 string back to plaintext
    decoded_bytes = base64.b64decode(ciphertext.encode('utf-8'))
    return decoded_bytes.decode('utf-8')
