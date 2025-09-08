# Standalone CLI tool (for testing without web)
import os
import base64
import qrcode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def generate_aes_key(length=32):
    return os.urandom(length)

def encrypt_data(data, key):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ct

def main():
    text = input("Enter text to encrypt: ")
    key = generate_aes_key()
    encrypted = encrypt_data(text, key)

    b64_key = base64.urlsafe_b64encode(key).decode()
    b64_encrypted = base64.urlsafe_b64encode(encrypted).decode()
    payload = f"key:{b64_key}\ndata:{b64_encrypted}"

    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(payload)
    qr.make(fit=True)
    img = qr.make_image(fill="black", back_color="white")
    img.save("cli_qr.png")
    print("QR code saved as cli_qr.png")

if __name__ == "__main__":
    main()
