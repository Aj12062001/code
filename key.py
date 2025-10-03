# key.py
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

KEYS_DIR = "saved_keys"
os.makedirs(KEYS_DIR, exist_ok=True)

def generate_keys():
    pub_name = input("Enter name for public key file: ").strip()
    priv_name = input("Enter name for private key file: ").strip()

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    priv_path = os.path.join(KEYS_DIR, f"{priv_name}.pem")
    pub_path = os.path.join(KEYS_DIR, f"{pub_name}.pem")

    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(pub_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print(f"✅ Keys saved:\n  Public: {pub_path}\n  Private: {priv_path}")

if __name__ == "__main__":
    generate_keys()
