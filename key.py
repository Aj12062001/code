import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

KEYS_DIR = "saved_keys"
os.makedirs(KEYS_DIR, exist_ok=True)

def generate_keys(pub_name=None, priv_name=None):
    """
    Generate RSA key pair and save to files.
    If names are None, ask user input (for CLI usage).
    Returns paths (pub_path, priv_path)
    """
    if not pub_name:
        pub_name = input("Enter name for public key file: ").strip()
    if not priv_name:
        priv_name = input("Enter name for private key file: ").strip()

    if not pub_name or not priv_name:
        print("❌ Key names cannot be empty.")
        return None, None

    pub_path = os.path.join(KEYS_DIR, f"{pub_name}.pem")
    priv_path = os.path.join(KEYS_DIR, f"{priv_name}.pem")

    if os.path.exists(pub_path) or os.path.exists(priv_path):
        print("⚠️ A file with that name already exists. Choose different names.")
        return None, None

    # Generate RSA key pair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Save private key
    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key
    with open(pub_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print(f"\n✅ Keys generated successfully!")
    print(f"🔓 Public Key : {pub_path}")
    print(f"🔒 Private Key: {priv_path}\n")

    return pub_path, priv_path

if __name__ == "__main__":
    generate_keys()
