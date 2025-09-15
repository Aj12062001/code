from flask import Flask, request, jsonify, send_file, send_from_directory
import os
import base64
import json
import time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import qrcode
import cv2
import numpy as np

app = Flask(__name__, static_folder="static")

SAVE_DIR = "saved_qr_codes"
os.makedirs(SAVE_DIR, exist_ok=True)

# Dictionary to track QR usage (first decryption start time)
qr_usage = {}  # { qr_id: first_decryption_time }


def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())


def encrypt_message(message: str, passphrase: str, expiry: int) -> str:
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
        "expiry": expiry,
    }
    return json.dumps(payload)


def decrypt_message(payload: dict, passphrase: str, qr_id: str):
    try:
        salt = base64.b64decode(payload["salt"])
        iv = base64.b64decode(payload["iv"])
        ciphertext = base64.b64decode(payload["ciphertext"])
        expiry = int(payload["expiry"])
    except Exception:
        return {"error": "Invalid QR data"}

    now = int(time.time())
    if qr_id in qr_usage:
        first_use = qr_usage[qr_id]
        elapsed = now - first_use
        if elapsed > expiry:
            return {"error": "QR code expired"}
        remaining = expiry - elapsed
    else:
        qr_usage[qr_id] = now
        remaining = expiry

    try:
        key = derive_key(passphrase, salt)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        return {"message": decrypted.decode(), "remaining": remaining}
    except Exception:
        return {"error": "Wrong passphrase or corrupted QR"}


# Serve main page from static
@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/encrypt", methods=["POST"])
def encrypt():
    text = request.form["text"]
    expiry = int(request.form["expiry"])
    passphrase = request.form["passphrase"]

    payload = encrypt_message(text, passphrase, expiry)

    qr_id = base64.urlsafe_b64encode(os.urandom(6)).decode()
    img = qrcode.make(payload)
    file_path = os.path.join(SAVE_DIR, f"{qr_id}.png")
    img.save(file_path)

    return send_file(file_path, mimetype="image/png")


@app.route("/decrypt", methods=["POST"])
def decrypt():
    if "qrfile" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    qrfile = request.files["qrfile"].read()
    passphrase = request.form["passphrase"]

    np_img = np.frombuffer(qrfile, np.uint8)
    img = cv2.imdecode(np_img, cv2.IMREAD_COLOR)

    detector = cv2.QRCodeDetector()
    data_str, points, _ = detector.detectAndDecode(img)

    if not data_str:
        return jsonify({"error": "No QR code detected"}), 400

    try:
        payload = json.loads(data_str)
    except Exception:
        return jsonify({"error": "Invalid QR payload"}), 400

    qr_id = base64.urlsafe_b64encode(
        (payload["salt"] + payload["iv"] + payload["ciphertext"]).encode()
    ).decode()[:12]

    result = decrypt_message(payload, passphrase, qr_id)
    return jsonify(result)


if __name__ == "__main__":
    print("Starting Flask server...")
    app.run(debug=True)