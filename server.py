from flask import Flask, request, jsonify, send_file, send_from_directory
import os, base64, json, time, threading
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import qrcode, cv2, numpy as np

app = Flask(__name__, static_folder="static")

SAVE_DIR = "saved_qr_codes"
os.makedirs(SAVE_DIR, exist_ok=True)

qr_usage = {}     # { qr_id: first_decryption_time }
qr_expired = {}   # { qr_id: True/False }
qr_mode = {}      # { qr_id: "normal" / "one-time" }
qr_files = {}     # { qr_id: file_path }

# --- Key Derivation ---
def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())

# --- Auto Destruction ---
def schedule_destruction(qr_id, delay):
    time.sleep(delay)
    qr_expired[qr_id] = True
    file_path = qr_files.get(qr_id)
    if file_path and os.path.exists(file_path):
        os.remove(file_path)
        print(f"[AUTO-DESTRUCT] QR file {file_path} deleted.")
    qr_files.pop(qr_id, None)
    qr_usage.pop(qr_id, None)
    qr_mode.pop(qr_id, None)

def destroy_now(qr_id):
    qr_expired[qr_id] = True
    file_path = qr_files.get(qr_id)
    if file_path and os.path.exists(file_path):
        os.remove(file_path)
        print(f"[ONE-TIME] QR file {file_path} deleted instantly.")
    qr_files.pop(qr_id, None)
    qr_usage.pop(qr_id, None)
    qr_mode.pop(qr_id, None)

# --- Encryption ---
def encrypt_message(message: str, passphrase: str, expiry: int, mode: str, qr_id: str) -> str:
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(passphrase, salt)

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()

    payload = {
        "qr_id": qr_id,
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "expiry": expiry,
        "mode": mode
    }
    return json.dumps(payload)

# --- Decryption ---
def decrypt_message(payload: dict, passphrase: str, qr_id: str):
    try:
        salt = base64.b64decode(payload["salt"])
        iv = base64.b64decode(payload["iv"])
        ciphertext = base64.b64decode(payload["ciphertext"])
        expiry = int(payload["expiry"])
        mode = payload.get("mode", "normal")
    except Exception:
        return {"error": "Invalid QR data"}

    if qr_expired.get(qr_id, False):
        return {"error": "QR code permanently expired"}

    now = int(time.time())
    if mode == "one-time":
        if qr_id in qr_usage:
            return {"error": "QR already used and destroyed"}
        qr_usage[qr_id] = now
        destroy_now(qr_id)
        countdown_info = "[ONE-TIME] QR destroyed instantly."
    else:
        if qr_id in qr_usage:
            first_use = qr_usage[qr_id]
            elapsed = now - first_use
            if elapsed > expiry:
                qr_expired[qr_id] = True
                return {"error": "QR code permanently expired"}
            remaining = expiry - elapsed
        else:
            qr_usage[qr_id] = now
            remaining = expiry
            threading.Thread(target=schedule_destruction, args=(qr_id, expiry), daemon=True).start()
        countdown_info = f"⏳ Remaining Time: {remaining} seconds"

    try:
        key = derive_key(passphrase, salt)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        return {"message": decrypted.decode(), "info": countdown_info}
    except Exception:
        return {"error": "Wrong passphrase or corrupted QR"}

# --- Routes ---
@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")

@app.route("/encrypt", methods=["POST"])
def encrypt():
    text = request.form["text"]
    expiry = int(request.form["expiry"])
    passphrase = request.form["passphrase"]
    mode = request.form.get("mode", "normal").strip().lower()
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
        qr_id = payload["qr_id"]
    except Exception:
        return jsonify({"error": "Invalid QR payload"}), 400

    result = decrypt_message(payload, passphrase, qr_id)
    return jsonify(result)

if __name__ == "__main__":
    print("Starting Flask server...")
    app.run(debug=True)