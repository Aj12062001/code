import os
import json
import base64
import qrcode
import cv2

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SAVE_DIR = "saved_qr_codes"
os.makedirs(SAVE_DIR, exist_ok=True)

# --- Option 1: Load RSA Key Pair by Filename ---
def load_rsa_keys_by_name():
    pub_filename = input("Enter PUBLIC key filename (e.g. rit_public.pem): ").strip()
    priv_filename = input("Enter PRIVATE key filename (e.g. ajinjose_private.pem): ").strip()

    try:
        with open(pub_filename, "r") as f:
            public_pem = f.read()
        with open(priv_filename, "r") as f:
            private_pem = f.read()

        RSA.import_key(public_pem)
        RSA.import_key(private_pem)
    except Exception:
        print("❌ Failed to load or validate RSA keys. Check filenames and formats.")
        return

    with open("host_public.pem", "w") as f:
        f.write(public_pem)
    with open("host_private.pem", "w") as f:
        f.write(private_pem)

    print("\n✅ RSA Key Pair Loaded and Saved:")
    print("Public Key → host_public.pem")
    print("Private Key → host_private.pem")

# --- Option 2: Encrypt AES Key using Receiver's Public Key ---
def encrypt_aes_key_to_qr():
    aes_key = input("Enter AES key to encrypt: ")
    pub_path = input("Enter path to receiver's public key (.pem): ").strip()

    try:
        with open(pub_path, "r") as f:
            pub_pem = f.read()
        public_key = RSA.import_key(pub_pem)
    except Exception:
        print("❌ Failed to load public key")
        return

    cipher = PKCS1_OAEP.new(public_key)
    encrypted = cipher.encrypt(aes_key.encode())
    encrypted_b64 = base64.b64encode(encrypted).decode()

    payload = json.dumps({"encrypted_key": encrypted_b64})
    qr_id = base64.urlsafe_b64encode(os.urandom(6)).decode()
    file_path = os.path.join(SAVE_DIR, f"{qr_id}_aeskey.png")
    qrcode.make(payload).save(file_path)
    print(f"🔐 AES Key QR saved as {file_path}")

# --- Option 3: Encrypt Plaintext using AES Key ---
def derive_aes_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=100_000, backend=default_backend()
    )
    return kdf.derive(passphrase.encode())

def encrypt_plaintext_to_qr():
    plaintext = input("Enter message to encrypt: ")
    aes_key = input("Enter AES key: ")
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_aes_key(aes_key, salt)

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

    payload = json.dumps({
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    })

    qr_id = base64.urlsafe_b64encode(os.urandom(6)).decode()
    file_path = os.path.join(SAVE_DIR, f"{qr_id}_msg.png")
    qrcode.make(payload).save(file_path)
    print(f"📝 Encrypted Message QR saved as {file_path}")

# --- Option 4: Decrypt AES Key using Receiver's Private Key ---
def decrypt_aes_key_from_qr():
    qr_path = input("Enter path of AES Key QR: ").strip()
    priv_path = input("Enter path to your private key (.pem): ").strip()

    try:
        with open(priv_path, "r") as f:
            priv_pem = f.read()
        private_key = RSA.import_key(priv_pem)
    except Exception:
        print("❌ Failed to load private key")
        return

    img = cv2.imread(qr_path)
    if img is None:
        print("❌ Failed to read QR image. Check the path.")
        return

    detector = cv2.QRCodeDetector()
    data_str, _, _ = detector.detectAndDecode(img)

    try:
        data = json.loads(data_str)
        encrypted_b64 = data["encrypted_key"]
        encrypted = base64.b64decode(encrypted_b64)
        cipher = PKCS1_OAEP.new(private_key)
        decrypted = cipher.decrypt(encrypted)
        print(f"✅ Decrypted AES Key: {decrypted.decode()}")
    except Exception:
        print("❌ Failed to decrypt AES Key")

# --- Option 5: Decrypt Plaintext using AES Key and QR ---
def decrypt_plaintext_from_qr():
    qr_path = input("Enter path of Message QR: ").strip()
    aes_key = input("Enter AES key: ")

    img = cv2.imread(qr_path)
    if img is None:
        print("❌ Failed to read QR image. Check the path.")
        return

    detector = cv2.QRCodeDetector()
    data_str, _, _ = detector.detectAndDecode(img)

    try:
        data = json.loads(data_str)
        salt = base64.b64decode(data["salt"])
        iv = base64.b64decode(data["iv"])
        ciphertext = base64.b64decode(data["ciphertext"])
        key = derive_aes_key(aes_key, salt)

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        print(f"✅ Decrypted Message: {decrypted.decode()}")
    except Exception:
        print("❌ Failed to decrypt message")

# --- Main Menu ---
def main():
    while True:
        print("\n--- Silent Key CLI ---")
        print("1. Load RSA Key Pair by Filename")
        print("2. Encrypt AES Key using Receiver's Public Key")
        print("3. Encrypt Plaintext using AES Key")
        print("4. Decrypt AES Key from QR using Receiver's Private Key")
        print("5. Decrypt Plaintext using AES Key and QR")
        print("6. Exit")
        choice = input("Choose option (1/2/3/4/5/6): ")

        if choice == "1":
            load_rsa_keys_by_name()
        elif choice == "2":
            encrypt_aes_key_to_qr()
        elif choice == "3":
            encrypt_plaintext_to_qr()
        elif choice == "4":
            decrypt_aes_key_from_qr()
        elif choice == "5":
            decrypt_plaintext_from_qr()
        elif choice == "6":
            print("Exiting...")
            break
        else:
            print("Invalid choice")

if __name__ == "__main__":
    main()