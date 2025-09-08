print("Starting Flask server...")
from flask import Flask, request, send_file, jsonify, send_from_directory
import io
import base64
import os
import qrcode
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import cv2
import numpy as np

app = Flask(__name__, static_folder="static")

# --------------------------
# Routes
# --------------------------
@app.route("/")
def root():
    return send_from_directory(app.static_folder, "index.html")

@app.route("/static/<path:filename>")
def static_files(filename):
    return send_from_directory(app.static_folder, filename)

# --------------------------
# Crypto functions
# --------------------------
def derive_key(passphrase, salt, iterations=100_000, length=32):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    )
    return kdf.derive(passphrase.encode())

def encrypt_data(data, key):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ct  # prepend IV

def decrypt_data(enc_data, key):
    iv = enc_data[:16]
    ct = enc_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data.decode()

# --------------------------
# QR Encrypt Endpoint
# --------------------------
@app.route("/encrypt", methods=["POST"])
def encrypt():
    text = request.form["text"]
    passphrase = request.form["passphrase"]
    expiry = int(request.form["expiry"])  # seconds
    expiry_timestamp = int(time.time()) + expiry

    salt = os.urandom(16)
    key = derive_key(passphrase, salt)
    encrypted = encrypt_data(text, key)

    b64_salt = base64.urlsafe_b64encode(salt).decode()
    b64_encrypted = base64.urlsafe_b64encode(encrypted).decode()

    payload = f"salt:{b64_salt}\ndata:{b64_encrypted}\nexp:{expiry_timestamp}"

    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(payload)
    qr.make(fit=True)
    img = qr.make_image(fill="black", back_color="white")

    # Save to memory
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)

    # Save to folder "saved_qr_codes"
    os.makedirs("saved_qr_codes", exist_ok=True)
    filename = f"saved_qr_codes/qr_{int(time.time())}.png"
    img.save(filename)

    return send_file(buf, mimetype="image/png")

# --------------------------
# QR Decrypt Endpoint
# --------------------------
@app.route("/decrypt", methods=["POST"])
def decrypt():
    file = request.files["qrfile"]
    passphrase = request.form["passphrase"]
    if not file:
        return jsonify({"error": "No file provided"}), 400

    file_bytes = file.read()
    np_arr = np.frombuffer(file_bytes, np.uint8)
    img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
    if img is None:
        return jsonify({"error": "Could not decode image"}), 400

    # Decode QR using OpenCV
    detector = cv2.QRCodeDetector()
    data, points, _ = detector.detectAndDecode(img)
    if not data:
        return jsonify({"error": "No QR code found"}), 400

    # Parse QR payload
    qr_data = {}
    for line in data.splitlines():
        line = line.strip()
        if line.startswith("salt:"):
            qr_data["salt"] = line[5:]
        elif line.startswith("data:"):
            qr_data["data"] = line[5:]
        elif line.startswith("exp:"):
            qr_data["exp"] = line[4:]

    if not all(k in qr_data for k in ["salt", "data", "exp"]):
        return jsonify({"error": "Invalid QR code format"}), 400

    try:
        salt = base64.urlsafe_b64decode(qr_data["salt"])
        encrypted = base64.urlsafe_b64decode(qr_data["data"])
        expiry = int(qr_data["exp"])
        now = int(time.time())

        if now > expiry:
            return jsonify({"error": "QR code expired"}), 400

        key = derive_key(passphrase, salt)
        decrypted = decrypt_data(encrypted, key)

        remaining = expiry - now
        return jsonify({"message": decrypted, "remaining": remaining})

    except Exception as e:
        return jsonify({"error": f"Decryption failed: {str(e)}"}), 400
if __name__ == "__main__":
    app.run(debug=True)
