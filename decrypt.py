# decrypt.py
import os
import json
import base64
import time
import threading
import cv2
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

SAVE_DIR = "saved_qr_codes"
os.makedirs(SAVE_DIR, exist_ok=True)

META_SUFFIX = ".meta.json"
PBKDF2_ITERS = 100_000

# ----------------- Helpers -----------------
def meta_path_for(qr_id: str) -> str:
    return os.path.join(SAVE_DIR, f"{qr_id}{META_SUFFIX}")

def load_meta(qr_id: str) -> dict | None:
    p = meta_path_for(qr_id)
    if not os.path.exists(p):
        return None
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def save_meta(qr_id: str, meta: dict):
    p = meta_path_for(qr_id)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(meta, f)

def remove_meta(qr_id: str):
    p = meta_path_for(qr_id)
    try:
        if os.path.exists(p):
            os.remove(p)
    except Exception:
        pass

def destroy_qr_file(qr_path: str, qr_id: str, why: str):
    """Delete the QR file and update meta as expired/used."""
    try:
        if os.path.exists(qr_path):
            os.remove(qr_path)
            print(f"\n[DELETED] QR file removed ({why}): {qr_path}")
    except Exception as e:
        print(f"[WARN] Could not delete QR file: {e}")

    meta = load_meta(qr_id) or {}
    meta['expired'] = True
    if why == "one-time":
        meta['used'] = True
    save_meta(qr_id, meta)

def schedule_destruction(qr_path: str, qr_id: str, delay: int):
    def _job():
        time.sleep(delay)
        # only delete if still present
        if os.path.exists(qr_path):
            destroy_qr_file(qr_path, qr_id, "time-expired")
    t = threading.Thread(target=_job, daemon=True)
    t.start()

def live_countdown(remaining_seconds: int, qr_path: str, qr_id: str):
    try:
        for sec in range(remaining_seconds, 0, -1):
            # If file already gone or meta expired — stop
            meta = load_meta(qr_id) or {}
            if meta.get('expired'):
                print("\n[COUNTDOWN STOPPED] QR already expired.")
                return
            print(f"\r⏳ Remaining Time: {sec} seconds", end="", flush=True)
            time.sleep(1)
        print("\n[COUNTDOWN FINISHED]")
    except KeyboardInterrupt:
        print("\n[COUNTDOWN INTERRUPTED BY USER]")

# ----------------- Crypto Helpers -----------------
def load_private_key(path: str):
    with open(path, "rb") as f:
        data = f.read()
    return serialization.load_pem_private_key(data, password=None)

def decrypt_aes_with_private(priv_path: str, enc_aes_path: str) -> bytes:
    with open(enc_aes_path, "rb") as f:
        enc_bytes = f.read()
    priv = load_private_key(priv_path)
    aes_key_bytes = priv.decrypt(
        enc_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key_bytes

def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERS,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())

# ----------------- QR / Payload -----------------
def read_qr_payload(qr_path: str) -> dict | None:
    if not os.path.exists(qr_path):
        print("❌ QR file not found:", qr_path)
        return None
    img = cv2.imread(qr_path)
    if img is None:
        print("❌ Could not open image (is it a valid image file?)")
        return None
    detector = cv2.QRCodeDetector()
    data_str, points, _ = detector.detectAndDecode(img)
    if not data_str:
        print("❌ No QR data found in image.")
        return None
    try:
        return json.loads(data_str)
    except Exception:
        print("❌ QR payload is not valid JSON.")
        return None

def decrypt_payload_with_aes(payload: dict, aes_passphrase: str) -> str:
    try:
        salt = base64.b64decode(payload["salt"])
        iv = base64.b64decode(payload["iv"])
        ciphertext = base64.b64decode(payload["ciphertext"])
    except Exception:
        raise ValueError("Invalid QR payload fields")

    key = derive_key(aes_passphrase, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plain = decryptor.update(ciphertext) + decryptor.finalize()
    return plain.decode()

# ----------------- Main flow -----------------
def decrypt_flow():
    print("\n--- Decrypt AES Key (RSA) ---")
    private_key_path = input("Enter private key file path: ").strip()
    enc_aes_path = input("Enter encrypted AES key file path: ").strip()

    if not os.path.exists(private_key_path):
        print("❌ Private key file does not exist.")
        return
    if not os.path.exists(enc_aes_path):
        print("❌ Encrypted AES file does not exist.")
        return

    try:
        aes_key_bytes = decrypt_aes_with_private(private_key_path, enc_aes_path)
    except Exception as e:
        print("❌ Failed to decrypt AES key with provided private key:", e)
        return

    # Show the decrypted AES key in plaintext if possible
    aes_passphrase_str = None
    try:
        aes_passphrase_str = aes_key_bytes.decode().strip()
        print("✅ AES key decrypted.")
        print("🔑 Decrypted AES key (plain text):", aes_passphrase_str)
    except Exception:
        # fallback: show base64 if raw bytes
        b64 = base64.b64encode(aes_key_bytes).decode()
        print("✅ AES key decrypted (binary).")
        print("🔑 Decrypted AES key (base64):", b64)
        aes_passphrase_str = None

    # Ask for QR to decrypt
    qr_path = input("\nEnter QR file path to decrypt: ").strip()
    payload = read_qr_payload(qr_path)
    if payload is None:
        return

    # required fields
    qr_id = payload.get("qr_id")
    expiry = int(payload.get("expiry", 0))
    mode = payload.get("mode", "normal")

    if not qr_id:
        print("❌ QR payload missing qr_id.")
        return

    # allow user to override AES passphrase (or press Enter to use decrypted one)
    use_choice = input("\nEnter AES key to use for QR decryption (press Enter to use decrypted AES key): ").strip()
    if use_choice:
        aes_pass = use_choice
    else:
        if aes_passphrase_str is None:
            # decrypted AES key was binary; ask user to provide one
            print("⚠️ Decrypted AES key is binary; you must paste the AES passphrase to use for decrypting the QR.")
            aes_pass = input("Enter AES passphrase to use: ").strip()
        else:
            aes_pass = aes_passphrase_str

    # --------- Mode handling ----------
    meta = load_meta(qr_id) or {"qr_id": qr_id, "first_use": None, "used": False, "expired": False}

    if mode == "one-time":
        if meta.get("used"):
            print("❌ QR already used and destroyed (one-time mode).")
            return

        # Decrypt message
        try:
            message = decrypt_payload_with_aes(payload, aes_pass)
        except Exception:
            print("❌ Wrong AES key or corrupted QR.")
            return

        # Show message, then destroy instantly
        print("\n✅ Decrypted message (one-time):")
        print(message)

        # mark used and delete file
        meta['used'] = True
        meta['expired'] = True
        save_meta(qr_id, meta)
        try:
            if os.path.exists(qr_path):
                os.remove(qr_path)
                print(f"[ONE-TIME] QR destroyed: {qr_path}")
        except Exception as e:
            print(f"[WARN] Could not remove QR file: {e}")
        return

    # normal mode
    if meta.get("expired"):
        print("❌ QR code permanently expired.")
        return

    now = int(time.time())
    if meta.get("first_use"):
        first_use = int(meta["first_use"])
        elapsed = now - first_use
        remaining = expiry - elapsed
        if remaining <= 0:
            # expired, delete & mark
            meta['expired'] = True
            save_meta(qr_id, meta)
            if os.path.exists(qr_path):
                try:
                    os.remove(qr_path)
                    print("[AUTO-DELETE] QR removed due to expiry.")
                except Exception:
                    pass
            print("❌ QR expired")
            return
        else:
            # decrypt and show (within remaining time)
            try:
                message = decrypt_payload_with_aes(payload, aes_pass)
            except Exception:
                print("❌ Wrong AES key or corrupted QR.")
                return

            print("\n✅ Decrypted message:")
            print(message)
            print(f"\n⏳ Remaining Time (resumed): {remaining} seconds")
            # schedule deletion after remaining seconds
            schedule_destruction(qr_path, qr_id, remaining)
            live_countdown(remaining, qr_path, qr_id)
            return
    else:
        # first time use: set first_use now and start countdown
        meta['first_use'] = now
        save_meta(qr_id, meta)
        remaining = expiry

        # decrypt now
        try:
            message = decrypt_payload_with_aes(payload, aes_pass)
        except Exception:
            # If decryption fails, clear first_use (allow retry) to avoid starting timer incorrectly
            meta['first_use'] = None
            save_meta(qr_id, meta)
            print("❌ Wrong AES key or corrupted QR.")
            return

        print("\n✅ Decrypted message (first use):")
        print(message)
        print(f"\n⏳ Remaining Time: {remaining} seconds")

        # schedule deletion and show live countdown
        schedule_destruction(qr_path, qr_id, remaining)
        live_countdown(remaining, qr_path, qr_id)
        return

if __name__ == "__main__":
    decrypt_flow()
