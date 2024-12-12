# crypto_algorithms/morse.py

MORSE_CODE_DICT = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.', 'G': '--.', 'H': '....',
    'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---', 'P': '.--.',
    'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..', '1': '.----', '2': '..---', '3': '...--', '4': '....-', '5': '.....',
    '6': '-....', '7': '--...', '8': '---..', '9': '----.', '0': '-----', ' ': '/'}
 
# Function to encrypt text to morse code
def encrypt_morse(plaintext: str) -> str:
    encrypted = ""
    for char in plaintext.upper():
        if char in MORSE_CODE_DICT:
            encrypted += MORSE_CODE_DICT[char] + " "
    return encrypted.strip()

# Function to decrypt morse code back to text
def decrypt_morse(morse_code: str) -> str:
    reverse_morse_dict = {v: k for k, v in MORSE_CODE_DICT.items()}
    words = morse_code.split(' / ')  # Split by spaces to separate words
    decrypted = ''
    for word in words:
        letters = word.split()  # Split each word into individual Morse code letters
        for letter in letters:
            if letter in reverse_morse_dict:
                decrypted += reverse_morse_dict[letter]
        decrypted += ' '
    return decrypted.strip()
