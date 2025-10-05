# decrypt.py
import os
import json
import base64
import time
import threading
import cv2
from typing import Optional, Tuple, Dict, Any
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Ensure project-local save directory (resolves relative to file)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAVE_DIR = os.path.join(BASE_DIR, "saved_qr_codes")
os.makedirs(SAVE_DIR, exist_ok=True)

META_SUFFIX = ".meta.json"
PBKDF2_ITERS = 100_000  # keep parity with encrypt.py

# ----------------- Helpers -----------------
def meta_path_for(qr_id: str) -> str:
    return os.path.join(SAVE_DIR, f"{qr_id}{META_SUFFIX}")

def load_meta(qr_id: str) -> Optional[dict]:
    p = meta_path_for(qr_id)
    if not os.path.exists(p):
        return None
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def save_meta(qr_id: str, meta: dict) -> None:
    p = meta_path_for(qr_id)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(meta, f)

def remove_meta(qr_id: str) -> None:
    p = meta_path_for(qr_id)
    try:
        if os.path.exists(p):
            os.remove(p)
    except Exception:
        pass

def destroy_qr_file(qr_path: str, qr_id: str, why: str) -> None:
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

def schedule_destruction(qr_path: str, qr_id: str, delay: int) -> None:
    def _job():
        time.sleep(delay)
        if os.path.exists(qr_path):
            destroy_qr_file(qr_path, qr_id, "time-expired")
    t = threading.Thread(target=_job, daemon=True)
    t.start()

def live_countdown(remaining_seconds: int, qr_path: str, qr_id: str) -> None:
    try:
        for sec in range(remaining_seconds, 0, -1):
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
def read_qr_payload(qr_path: str) -> Optional[dict]:
    """Read QR image and return parsed JSON payload or None."""
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

# ----------------- Programmatic API -----------------
def decrypt_qr_with_private(
    private_key_path: str,
    enc_aes_path: str,
    qr_path: str,
    override_aes_pass: Optional[str] = None
) -> Tuple[bool, Dict[str, Any]]:
    """
    Decrypt workflow in programmatic form.
    Returns (success, info_dict). info_dict contains keys:
      - message (decrypted message) on success
      - error (error message) on failure
      - meta (meta dict) for status (used/expired/first_use)
      - aes_key (plaintext or base64) when available
    """
    info: Dict[str, Any] = {"meta": None}
    # basic checks
    if not os.path.exists(private_key_path):
        return False, {"error": "Private key file does not exist."}
    if not os.path.exists(enc_aes_path):
        return False, {"error": "Encrypted AES file does not exist."}
    if not os.path.exists(qr_path):
        return False, {"error": "QR file does not exist."}

    # decrypt AES
    try:
        aes_key_bytes = decrypt_aes_with_private(private_key_path, enc_aes_path)
    except Exception as e:
        return False, {"error": f"Failed to decrypt AES key: {e}"}

    aes_passphrase_str: Optional[str] = None
    try:
        aes_passphrase_str = aes_key_bytes.decode().strip()
        info["aes_key"] = aes_passphrase_str
    except Exception:
        # binary key; return base64 and require override
        info["aes_key_base64"] = base64.b64encode(aes_key_bytes).decode()
        aes_passphrase_str = None

    payload = read_qr_payload(qr_path)
    if payload is None:
        return False, {"error": "Failed to read QR payload."}

    qr_id = payload.get("qr_id")
    expiry = int(payload.get("expiry", 0))
    mode = payload.get("mode", "normal")
    if not qr_id:
        return False, {"error": "QR payload missing qr_id."}

    # choose AES passphrase
    if override_aes_pass:
        aes_pass = override_aes_pass
    else:
        if aes_passphrase_str is None:
            return False, {"error": "Decrypted AES key is binary; supply override_aes_pass (or base64->raw).",
                           "aes_key_base64": info.get("aes_key_base64")}
        aes_pass = aes_passphrase_str

    # handle modes
    meta = load_meta(qr_id) or {"qr_id": qr_id, "first_use": None, "used": False, "expired": False}
    info["meta"] = meta

    # one-time
    if mode == "one-time":
        if meta.get("used"):
            return False, {"error": "QR already used (one-time mode)."}
        try:
            message = decrypt_payload_with_aes(payload, aes_pass)
        except Exception:
            return False, {"error": "Wrong AES key or corrupted QR."}
        # mark used and delete file
        meta['used'] = True
        meta['expired'] = True
        save_meta(qr_id, meta)
        try:
            if os.path.exists(qr_path):
                os.remove(qr_path)
        except Exception as e:
            # non-fatal
            print(f"[WARN] Could not remove QR file: {e}")
        return True, {"message": message, "meta": meta}

    # normal mode
    if meta.get("expired"):
        return False, {"error": "QR code permanently expired."}

    now = int(time.time())
    if meta.get("first_use"):
        first_use = int(meta["first_use"])
        elapsed = now - first_use
        remaining = expiry - elapsed
        if remaining <= 0:
            meta['expired'] = True
            save_meta(qr_id, meta)
            try:
                if os.path.exists(qr_path):
                    os.remove(qr_path)
            except Exception:
                pass
            return False, {"error": "QR expired", "meta": meta}
        else:
            try:
                message = decrypt_payload_with_aes(payload, aes_pass)
            except Exception:
                return False, {"error": "Wrong AES key or corrupted QR."}
            # schedule deletion after remaining seconds
            schedule_destruction(qr_path, qr_id, remaining)
            return True, {"message": message, "remaining": remaining, "meta": meta}
    else:
        # first time use
        meta['first_use'] = now
        save_meta(qr_id, meta)
        remaining = expiry
        try:
            message = decrypt_payload_with_aes(payload, aes_pass)
        except Exception:
            meta['first_use'] = None
            save_meta(qr_id, meta)
            return False, {"error": "Wrong AES key or corrupted QR."}
        # schedule deletion and start countdown (if used interactively, caller can show countdown)
        schedule_destruction(qr_path, qr_id, remaining)
        return True, {"message": message, "remaining": remaining, "meta": meta}

# ----------------- CLI wrapper (preserves original flow) -----------------
def decrypt_flow():
    print("\n--- Decrypt AES Key (RSA) ---")
    private_key_path = input("Enter private key file path: ").strip()
    enc_aes_path = input("Enter encrypted AES key file path: ").strip()

    success, result = None, None
    success, result = None, None
    ok, res = decrypt_qr_interactive(private_key_path, enc_aes_path)
    # decrypt_qr_interactive prints and returns nothing (keeps previous UX)
    return

def decrypt_qr_interactive(private_key_path: str, enc_aes_path: str) -> Tuple[bool, Dict[str, Any]]:
    """Interactive helper for CLI (keeps similar prompts to original)."""
    if not os.path.exists(private_key_path):
        print("❌ Private key file does not exist.")
        return False, {"error": "no private key"}
    if not os.path.exists(enc_aes_path):
        print("❌ Encrypted AES file does not exist.")
        return False, {"error": "no enc aes"}

    try:
        aes_key_bytes = decrypt_aes_with_private(private_key_path, enc_aes_path)
    except Exception as e:
        print("❌ Failed to decrypt AES key with provided private key:", e)
        return False, {"error": str(e)}

    aes_passphrase_str = None
    try:
        aes_passphrase_str = aes_key_bytes.decode().strip()
        print("✅ AES key decrypted.")
        print("🔑 Decrypted AES key (plain text):", aes_passphrase_str)
    except Exception:
        b64 = base64.b64encode(aes_key_bytes).decode()
        print("✅ AES key decrypted (binary).")
        print("🔑 Decrypted AES key (base64):", b64)
        aes_passphrase_str = None

    qr_path = input("\nEnter QR file path to decrypt: ").strip()
    payload = read_qr_payload(qr_path)
    if payload is None:
        return False, {"error": "invalid qr"}

    qr_id = payload.get("qr_id")
    expiry = int(payload.get("expiry", 0))
    mode = payload.get("mode", "normal")
    if not qr_id:
        print("❌ QR payload missing qr_id.")
        return False, {"error": "no qr_id"}

    use_choice = input("\nEnter AES key to use for QR decryption (press Enter to use decrypted AES key): ").strip()
    if use_choice:
        aes_pass = use_choice
    else:
        if aes_passphrase_str is None:
            print("⚠️ Decrypted AES key is binary; you must paste the AES passphrase to use for decrypting the QR.")
            aes_pass = input("Enter AES passphrase to use: ").strip()
        else:
            aes_pass = aes_passphrase_str

    success, info = decrypt_qr_with_private(private_key_path, enc_aes_path, qr_path, override_aes_pass=aes_pass)
    if not success:
        print("❌", info.get("error"))
        return False, info

    # success path prints result similar to original UX
    msg = info.get("message", "")
    if mode == "one-time":
        print("\n✅ Decrypted message (one-time):")
        print(msg)
        print("[ONE-TIME] QR destroyed if present.")
    else:
        print("\n✅ Decrypted message:")
        print(msg)
        rem = info.get("remaining")
        if rem is not None:
            print(f"\n⏳ Remaining Time: {rem} seconds")
            live_countdown(rem, qr_path, qr_id)
    return True, info

if __name__ == "__main__":
    # run the interactive wrapper to preserve existing behavior
    decrypt_flow()
