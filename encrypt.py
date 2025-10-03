# encrypt.py
import os, base64, json, time, qrcode, threading, secrets
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

SAVE_DIR = "saved_qr_codes"
os.makedirs(SAVE_DIR, exist_ok=True)

qr_usage, qr_files, qr_expired, qr_mode = {}, {}, {}, {}

# --- Derive AES key from passphrase
def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())

# --- RSA encrypt AES key ---
def encrypt_aes_with_public(aes_key: str, pub_key_path: str) -> str:
    with open(pub_key_path, "rb") as f:
        pub_key = serialization.load_pem_public_key(f.read())
    encrypted = pub_key.encrypt(
        aes_key.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # ✅ Use unique filename for AES key
    file_name = f"aes_{secrets.token_hex(4)}.pem"
    file_path = os.path.join(SAVE_DIR, file_name)
    with open(file_path, "wb") as f:
        f.write(encrypted)

    print(f"✅ AES key encrypted and saved at {file_path}")
    return file_path

# --- Encrypt message to QR ---
def encrypt_message(message: str, aes_key: str, expiry: int, mode: str, qr_id: str) -> str:
    salt, iv = os.urandom(16), os.urandom(16)
    key = derive_key(aes_key, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()

    payload = {
        "qr_id": qr_id,
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "expiry": expiry,
        "mode": mode,
        "created_at": int(time.time())
    }
    return json.dumps(payload)

def save_qr(payload, qr_id):
    img = qrcode.make(payload)
    file_path = os.path.join(SAVE_DIR, f"{qr_id}.png")
    img.save(file_path)
    qr_files[qr_id], qr_expired[qr_id] = file_path, False
    return file_path

def encrypt_flow():
    print("\n--- Encrypt Menu ---")
    pub_key = input("Enter receiver public key file path: ").strip()
    aes_key = input("Enter AES key (any length string): ").strip()

    # Encrypt AES key and get unique file path
    aes_file_path = encrypt_aes_with_public(aes_key, pub_key)

    mode = input("Mode (normal / one-time): ").strip().lower()
    if mode not in ["normal", "one-time"]:
        mode = "normal"

    msg = input("Enter message to encrypt: ")
    expiry = 0
    if mode == "normal":
        expiry = int(input("Enter expiry time (seconds): "))

    qr_id = base64.urlsafe_b64encode(os.urandom(6)).decode()
    payload = encrypt_message(msg, aes_key, expiry, mode, qr_id)
    qr_path = save_qr(payload, qr_id)

    print("\n✅ Encryption Complete:")
    print(f"   AES key file: {aes_file_path}")
    print(f"   QR code file: {qr_path}")

if __name__ == "__main__":
    encrypt_flow()
