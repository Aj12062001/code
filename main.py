import os
import json
import base64
import qrcode
import time
import cv2
import threading
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


SAVE_DIR = "saved_qr_codes"
os.makedirs(SAVE_DIR, exist_ok=True)

qr_usage = {}    # { qr_id: first_decryption_time }
qr_files = {}    # { qr_id: file_path }
qr_expired = {}  # { qr_id: True/False }
qr_mode = {}     # { qr_id: "normal" / "one-time" }


# --- Derive AES Key ---
def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())


# --- Encrypt Message ---
def encrypt_message(message: str, passphrase: str, expiry: int, mode: str, qr_id: str) -> str:
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(passphrase, salt)

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()

    payload = {
        "qr_id": qr_id,   # include ID inside payload
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "expiry": expiry,
        "mode": mode
    }
    return json.dumps(payload)


# --- Auto Destruction (Normal mode) ---
def schedule_destruction(qr_id, delay):
    time.sleep(delay)
    qr_expired[qr_id] = True
    file_path = qr_files.get(qr_id)
    if file_path and os.path.exists(file_path):
        os.remove(file_path)
        print(f"\n[AUTO-DESTRUCT] QR file {file_path} deleted.")
    qr_files.pop(qr_id, None)
    qr_usage.pop(qr_id, None)
    qr_mode.pop(qr_id, None)


# --- One-Time Immediate Destruction ---
def destroy_now(qr_id):
    qr_expired[qr_id] = True
    file_path = qr_files.get(qr_id)
    if file_path and os.path.exists(file_path):
        os.remove(file_path)
        print(f"\n[ONE-TIME] QR file {file_path} deleted instantly.")
    qr_files.pop(qr_id, None)
    qr_usage.pop(qr_id, None)
    qr_mode.pop(qr_id, None)


# --- Live Countdown ---
def live_countdown(expiry, start_time, qr_id):
    while True:
        elapsed = int(time.time()) - start_time
        remaining = expiry - elapsed
        if remaining <= 0 or qr_expired.get(qr_id, False):
            break
        print(f"\r⏳ Time left: {remaining} seconds", end="", flush=True)
        time.sleep(1)
    print("\n[COUNTDOWN FINISHED]")


# --- Decrypt Message ---
def decrypt_message(payload: str, passphrase: str, qr_id: str, file_path: str) -> str:
    try:
        data = json.loads(payload)
        salt = base64.b64decode(data["salt"])
        iv = base64.b64decode(data["iv"])
        ciphertext = base64.b64decode(data["ciphertext"])
        expiry = int(data["expiry"])
        mode = data.get("mode", "normal")
    except Exception:
        return "Invalid QR payload"

    if qr_expired.get(qr_id, False):
        return "❌ QR code permanently expired"

    if mode == "one-time":
        if qr_id in qr_usage:
            return "❌ QR already used and destroyed"
        qr_usage[qr_id] = int(time.time())
        destroy_now(qr_id)
        countdown_info = "[ONE-TIME] QR destroyed instantly."
    else:
        now = int(time.time())
        if qr_id in qr_usage:
            first_use = qr_usage[qr_id]
            elapsed = now - first_use
            if elapsed > expiry:
                qr_expired[qr_id] = True
                return "❌ QR code permanently expired"
            remaining = expiry - elapsed
        else:
            qr_usage[qr_id] = now
            remaining = expiry
            # start destruction and countdown
            threading.Thread(target=schedule_destruction, args=(qr_id, expiry), daemon=True).start()
            threading.Thread(target=live_countdown, args=(expiry, now, qr_id), daemon=True).start()
        countdown_info = f"⏳ Remaining Time: {remaining} seconds"

    try:
        key = derive_key(passphrase, salt)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        return f"✅ Message: {decrypted.decode()}\n{countdown_info}"
    except Exception:
        return "❌ Wrong passphrase or corrupted QR"


# --- Save QR ---
def encrypt_to_qr():
    text = input("Enter message to encrypt: ")
    passphrase = input("Enter passphrase: ")
    expiry = int(input("Enter expiry time in seconds: "))
    mode = input("Choose mode (normal / one-time): ").strip().lower()
    if mode not in ["normal", "one-time"]:
        mode = "normal"

    qr_id = base64.urlsafe_b64encode(os.urandom(6)).decode()
    payload = encrypt_message(text, passphrase, expiry, mode, qr_id)

    img = qrcode.make(payload)
    file_path = os.path.join(SAVE_DIR, f"{qr_id}.png")
    img.save(file_path)

    qr_files[qr_id] = file_path
    qr_expired[qr_id] = False
    qr_mode[qr_id] = mode

    print(f"QR code saved as {file_path}")


# --- Decrypt from QR using OpenCV ---
def decrypt_from_qr():
    qr_path = input("Enter path of QR image to decrypt: ")
    passphrase = input("Enter passphrase: ")

    img = cv2.imread(qr_path)
    detector = cv2.QRCodeDetector()
    data_str, points, _ = detector.detectAndDecode(img)

    if not data_str:
        print("❌ No QR code found in image!")
        return

    try:
        data = json.loads(data_str)
        qr_id = data["qr_id"]   # use stored ID
    except Exception:
        print("❌ Invalid QR payload")
        return

    file_path = qr_files.get(qr_id, qr_path)  # fallback

    result = decrypt_message(data_str, passphrase, qr_id, file_path)
    print(result)


# --- Main Menu ---
def main():
    while True:
        print("\n--- Silent Key CLI ---")
        print("1. Encrypt Message to QR")
        print("2. Decrypt Message from QR")
        print("3. Exit")
        choice = input("Choose option (1/2/3): ")

        if choice == "1":
            encrypt_to_qr()
        elif choice == "2":
            decrypt_from_qr()
        elif choice == "3":
            print("Exiting...")
            break
        else:
            print("Invalid choice")


if __name__ == "__main__":
    main()
