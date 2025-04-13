from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import os

def generate_key_from_password_bytes(password: str, salt: bytes) -> bytes:
    """Generates a secure key from a password and salt using PBKDF2HMAC (returns bytes)."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

def encrypt(text: str, password: str):
    """Encrypts text using AES-CTR mode."""
    salt = b'\x05\xa8\xa70\x93\x1e\x02\x9a\n\x1a\x94\xba\x8f\x1c\x8c'
    key_bytes = generate_key_from_password_bytes(password, salt)
    iv = os.urandom(16)  # Generate a random 16-byte IV
    cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext_bytes = encryptor.update(text.encode()) + encryptor.finalize()

    # Return IV (Base64 encoded) + ":" + Ciphertext (Base64 encoded)
    return base64.b64encode(iv).decode('utf-8') + ":" + base64.b64encode(ciphertext_bytes).decode('utf-8')

def decrypt(encrypted_data: str, password: str):
    """Decrypts text encrypted with AES-CTR mode."""
    salt = b'\x05\xa8\xa70\x93\x1e\x02\x9a\n\x1a\x94\xba\x8f\x1c\x8c'
    key_bytes = generate_key_from_password_bytes(password, salt)

    iv_b64, ciphertext_b64 = encrypted_data.split(':')
    iv_bytes = base64.b64decode(iv_b64)
    ciphertext_bytes = base64.b64decode(ciphertext_b64)

    cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(iv_bytes), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_bytes = decryptor.update(ciphertext_bytes) + decryptor.finalize()
    return decrypted_bytes.decode('utf-8')
