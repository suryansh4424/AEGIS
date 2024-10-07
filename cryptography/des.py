from Crypto.Cipher import DES
import base64

def encrypt(key, plaintext):
    cipher = DES.new(key, DES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def decrypt(key, ciphertext):
    data = base64.b64decode(ciphertext.encode())
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = DES.new(key, DES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()
