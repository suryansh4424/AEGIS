import hashlib

def hash_sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

def hash_md5(data: str) -> str:
    return hashlib.md5(data.encode()).hexdigest()
