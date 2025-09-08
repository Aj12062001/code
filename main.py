import os
import json
import base64
import qrcode
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())

def encrypt_message(message: str, passphrase: str) -> str:
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(passphrase, salt)

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()

    payload = {
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "expiry": 60  # default 60s countdown after decryption
    }
    return json.dumps(payload)

def main():
    text = input("Enter message to encrypt: ")
    passphrase = input("Enter passphrase: ")
    payload = encrypt_message(text, passphrase)

    img = qrcode.make(payload)
    os.makedirs("saved_qr_codes", exist_ok=True)
    img.save("saved_qr_codes/cli_qr.png")
    print("QR code saved as saved_qr_codes/cli_qr.png")

if __name__ == "__main__":
    main()
