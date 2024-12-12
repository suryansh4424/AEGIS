import hashlib

def hash_data(data):
    """Hash data using SHA-256."""
    return hashlib.sha256(data.encode()).hexdigest()
