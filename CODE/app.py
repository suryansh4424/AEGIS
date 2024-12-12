from flask import Flask, render_template, request
import os
from crypto_algorithms.hash_func import hash_data  # Import hash function
from crypto_algorithms.aes import aes_encrypt # Import your encryption modules (make sure these are correctly implemented)
from crypto_algorithms.diffie_hellman import generate_private_key, generate_public_key, compute_shared_secret
from crypto_algorithms import aes, des, rsa, diffie_hellman, affine, base64, caesar, elgamal, hash_func, hill, homophonic, morse, onetimepad, playfair, polybius, railfence, scytale, transposition, vigenere, xor

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')  # The homepage with encryption method options

# Define a route for AES encryption
@app.route('/aes', methods=['GET', 'POST'])
def aes_encryption():
    if request.method == 'POST':
        plaintext = request.form.get('plaintext')
        key = request.form.get('key', None)  # Optional key field

        # Call the AES encryption function
        iv, encrypted, key_base64 = aes_encrypt(plaintext, key)

        # Return the encrypted data in base64
        return render_template('aes.html', encrypted=encrypted, iv=iv, key=key_base64)

    return render_template('aes.html')

# Define a route for DES encryption
@app.route('/des', methods=['GET', 'POST'])
def des_encryption():
    if request.method == 'POST':
        plaintext = request.form.get('plaintext')
        key = request.form.get('key', '')  # Optional key field

        encrypted = des_encrypt(plaintext, key)
        encrypted_text = encrypted.hex()  # Convert to hex or base64 for display

        return render_template('des.html', encrypted=encrypted_text)

    return render_template('des.html')

# Define a route for RSA encryption
@app.route('/rsa', methods=['GET', 'POST'])
def rsa_page():
    if request.method == 'POST':
        plaintext = request.form['plaintext']

        # Generate keys only if not already present
        private_key, public_key = rsa.generate_rsa_keys()
        
        # Encrypt and Decrypt the text
        encrypted = rsa.encrypt(public_key, plaintext)
        decrypted = rsa.decrypt(private_key, encrypted)

        # Serialize keys to PEM format
        public_key_pem = rsa.serialize_key(public_key)
        private_key_pem = rsa.serialize_key(private_key, private=True)

        # Return the keys, encrypted, and decrypted text to the template
        return render_template('rsa.html', encrypted=encrypted, decrypted=decrypted, 
                               public_key_pem=public_key_pem.decode(), private_key_pem=private_key_pem.decode())
    return render_template('rsa.html')

# Add similar routes for other cryptographic methods
@app.route('/affine', methods=['GET', 'POST'])
def affine_page():
    if request.method == 'POST':
        word = request.form['word']
        key = request.form.get('key')
        
        # Parsing key as tuple (a,b)
        try:
            a, b = map(int, key.split(','))
        except ValueError:
            return render_template('affine.html', error="Invalid key format. Please enter two integers for 'a' and 'b' separated by a comma.")

        encrypted = affine.encrypt_affine(word, a, b)
        decrypted = affine.decrypt_affine(encrypted, a, b)
        
        return render_template('affine.html', encrypted=encrypted, decrypted=decrypted, key=key)
    
    return render_template('affine.html')

@app.route('/base64', methods=['GET', 'POST'])
def base64_page():
    if request.method == 'POST':
        word = request.form['word']
        
        # Encode and Decode the text using Base64
        encoded = base64.encode(word)
        decoded = base64.decode(encoded)
        
        # Return the encoded and decoded text to the template
        return render_template('base64.html', encrypted=encoded, decrypted=decoded)
    return render_template('base64.html')


@app.route('/caesar', methods=['GET', 'POST'])
def caesar_page():
    if request.method == 'POST':
        word = request.form['word']
        shift = int(request.form['shift'])
        
        # Encrypt and Decrypt the text using Caesar Cipher
        encrypted = caesar.encrypt(word, shift)
        decrypted = caesar.decrypt(encrypted, shift)
        
        # Return the encrypted and decrypted text to the template
        return render_template('ceaser.html', encrypted=encrypted, decrypted=decrypted)
    return render_template('ceaser.html')

@app.route('/diffie_hellman', methods=['GET', 'POST'])
def diffie_hellman_page():
    if request.method == 'POST':
        p = int(request.form['p'])  # Prime number p
        g = int(request.form['g'])  # Base number g

        # Generate private keys for two parties
        private_key_1 = generate_private_key()
        private_key_2 = generate_private_key()

        # Generate public keys for both parties
        public_key_1 = generate_public_key(private_key_1, g, p)
        public_key_2 = generate_public_key(private_key_2, g, p)

        # Compute the shared secret using each other's public keys
        shared_secret_1 = compute_shared_secret(public_key_2, private_key_1, p)
        shared_secret_2 = compute_shared_secret(public_key_1, private_key_2, p)

        # Ensure the shared secret matches for both parties
        assert shared_secret_1 == shared_secret_2

        return render_template('diffie_hellman.html', 
                               private_key=private_key_1, 
                               public_key=public_key_1, 
                               shared_secret=shared_secret_1)

    return render_template('diffie_hellman.html')

@app.route('/morse', methods=['GET', 'POST'])
def morse_page():
    if request.method == 'POST':
        text_input = request.form['textInput']
        action = request.form['action']

        if action == 'encrypt':
            encrypted = morse.encrypt_morse(text_input)
            return render_template('morse.html', encrypted=encrypted)

        elif action == 'decrypt':
            decrypted = morse.decrypt_morse(text_input)
            return render_template('morse.html', decrypted=decrypted)
    
    return render_template('morse.html')


@app.route('/playfair', methods=['GET', 'POST'])
def playfair_page():
    if request.method == 'POST':
        key = request.form['key']
        text_input = request.form['textInput']
        action = request.form['action']

        if action == 'encrypt':
            encrypted = playfair.encrypt_playfair(text_input, key)
            return render_template('playfair.html', encrypted=encrypted)

        elif action == 'decrypt':
            decrypted = playfair.decrypt_playfair(text_input, key)
            return render_template('playfair.html', decrypted=decrypted)
    
    return render_template('playfair.html')

@app.route('/vigenere', methods=['GET', 'POST'])
def vigenere_page():
    if request.method == 'POST':
        key = request.form['key']
        text_input = request.form['textInput']
        action = request.form['action']

        if action == 'encrypt':
            encrypted = vigenere.encrypt_vigenere(text_input, key)
            return render_template('vigenere.html', encrypted=encrypted)

        elif action == 'decrypt':
            decrypted = vigenere.decrypt_vigenere(text_input, key)
            return render_template('vigenere.html', decrypted=decrypted)
    
    return render_template('vigenere.html')

# Example route for Hill Cipher
@app.route('/hill', methods=['GET', 'POST'])
def hill_page():
    if request.method == 'POST':
        word = request.form['word']
        key = request.form.get('key', None)  # Ensure key handling logic is correct for Hill Cipher
        encrypted = hill.encrypt(word, key)
        decrypted = hill.decrypt(encrypted, key)
        return render_template('hill.html', encrypted=encrypted, decrypted=decrypted)
    return render_template('hill.html')

# Continue this pattern for other encryption methods...

@app.route('/xor', methods=['GET', 'POST'])
def xor_page():
    if request.method == 'POST':
        word = request.form['word']
        key = request.form.get('key', None)  # Handle XOR key
        encrypted = xor.encrypt(word, key)
        decrypted = xor.decrypt(encrypted, key)
        return render_template('xor.html', encrypted=encrypted, decrypted=decrypted, key=key)
    return render_template('xor.html')

# Main entry point to run the app
if __name__ == "__main__":
    app.run(debug=True)
