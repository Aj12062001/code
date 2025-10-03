from flask import Flask, request, jsonify, render_template, send_file
import os, base64, json, time, threading, qrcode
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from flask import Flask, send_from_directory

app = Flask(__name__, static_folder="static")
SAVE_KEYS = "saved_keys"
SAVE_QR = "saved_qr_codes"
os.makedirs(SAVE_KEYS, exist_ok=True)
os.makedirs(SAVE_QR, exist_ok=True)

# --- In-memory tracking for QR expiration ---
qr_usage = {}     # { qr_id: first_use_time }
qr_expired = {}   # { qr_id: True/False }
qr_mode = {}      # { qr_id: "normal"/"one-time" }
qr_files = {}     # { qr_id: file_path }

# ---------------- Key Generation ----------------
@app.route("/generate_keys", methods=["POST"])
def generate_keys():
    pub_name = request.form.get("pub_name", "public")
    priv_name = request.form.get("priv_name", "private")

    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    priv_path = os.path.join(SAVE_KEYS, f"{priv_name}.pem")
    pub_path = os.path.join(SAVE_KEYS, f"{pub_name}.pem")

    priv_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(priv_path, "wb") as f:
        f.write(priv_bytes)
    with open(pub_path, "wb") as f:
        f.write(pub_bytes)

    return jsonify({
        "message": f"✅ Keys saved:\nPublic: {pub_path}\nPrivate: {priv_path}"
    })

# ---------------- Helper Functions ----------------
def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())

def schedule_deletion(qr_id, delay):
    time.sleep(delay)
    if qr_id in qr_files and os.path.exists(qr_files[qr_id]):
        os.remove(qr_files[qr_id])
    qr_expired[qr_id] = True
    qr_files.pop(qr_id, None)
    qr_usage.pop(qr_id, None)
    qr_mode.pop(qr_id, None)

# ---------------- Encryption ----------------
@app.route("/encrypt", methods=["POST"])
def encrypt():
    pub_file = request.files.get("pub_file")
    aes_key = request.form.get("aes_key", "")
    mode = request.form.get("mode", "normal")
    message = request.form.get("message", "")
    expiry = int(request.form.get("expiry", "60"))

    if not pub_file or not aes_key or not message:
        return jsonify({"error": "Missing input"}), 400

    # Save AES key file encrypted with public key
    pub_key = serialization.load_pem_public_key(pub_file.read(), backend=default_backend())
    encrypted_aes = pub_key.encrypt(
        aes_key.encode(),
        serialization.padding.OAEP(
            mgf=serialization.padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    aes_file_name = f"aes_{base64.urlsafe_b64encode(os.urandom(4)).decode()}.pem"
    aes_path = os.path.join(SAVE_QR, aes_file_name)
    with open(aes_path, "wb") as f:
        f.write(encrypted_aes)

    # Encrypt message to QR
    salt = os.urandom(16)
    iv = os.urandom(16)
    key_bytes = derive_key(aes_key, salt)
    cipher = Cipher(algorithms.AES(key_bytes), modes.CFB(iv), backend=default_backend())
    ct = cipher.encryptor().update(message.encode()) + cipher.encryptor().finalize()

    qr_id = base64.urlsafe_b64encode(os.urandom(6)).decode()
    payload = {
        "qr_id": qr_id,
        "mode": mode,
        "expiry": expiry,
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ct).decode()
    }

    qr_file_name = f"{qr_id}.png"
    qr_path = os.path.join(SAVE_QR, qr_file_name)
    img = qrcode.make(json.dumps(payload))
    img.save(qr_path)
    qr_files[qr_id] = qr_path
    qr_mode[qr_id] = mode

    if mode == "normal":
        threading.Thread(target=schedule_deletion, args=(qr_id, expiry), daemon=True).start()

    return jsonify({
        "message": "✅ Encryption Complete",
        "aes_file": aes_path,
        "qr_file": qr_path
    })

# ---------------- Decryption ----------------
@app.route("/decrypt", methods=["POST"])
def decrypt():
    priv_file = request.files.get("priv_file")
    aes_file = request.files.get("aes_file")
    qr_file = request.files.get("qr_file")
    aes_input = request.form.get("aes_key", "")

    if not priv_file or not aes_file or not qr_file:
        return jsonify({"error": "Missing input"}), 400

    priv_key = serialization.load_pem_private_key(priv_file.read(), password=None, backend=default_backend())
    encrypted_aes = aes_file.read()
    aes_key_bytes = priv_key.decrypt(
        encrypted_aes,
        serialization.padding.OAEP(
            mgf=serialization.padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    aes_key = aes_key_bytes.decode()

    if aes_input.strip() != "":
        aes_key = aes_input.strip()

    # Read QR and decrypt
    import cv2, numpy as np
    np_img = np.frombuffer(qr_file.read(), np.uint8)
    img = cv2.imdecode(np_img, cv2.IMREAD_COLOR)
    detector = cv2.QRCodeDetector()
    data_str, _, _ = detector.detectAndDecode(img)
    if not data_str:
        return jsonify({"error": "Invalid QR file"}), 400

    payload = json.loads(data_str)
    qr_id = payload["qr_id"]
    if qr_mode.get(qr_id) == "one-time":
        qr_expired[qr_id] = True
        if qr_id in qr_files and os.path.exists(qr_files[qr_id]):
            os.remove(qr_files[qr_id])
        qr_files.pop(qr_id, None)

    salt = base64.b64decode(payload["salt"])
    iv = base64.b64decode(payload["iv"])
    ciphertext = base64.b64decode(payload["ciphertext"])

    key_bytes = derive_key(aes_key, salt)
    cipher = Cipher(algorithms.AES(key_bytes), modes.CFB(iv), backend=default_backend())
    decrypted = cipher.decryptor().update(ciphertext) + cipher.decryptor().finalize()
    decrypted_text = decrypted.decode()

    info = ""
    if payload["mode"] == "normal":
        first_use = qr_usage.get(qr_id, int(time.time()))
        qr_usage[qr_id] = first_use
        remaining = payload["expiry"] - (int(time.time()) - first_use)
        info = f"⏳ Remaining Time: {remaining if remaining>0 else 0} seconds"
        if remaining <= 0 and qr_id in qr_files and os.path.exists(qr_files[qr_id]):
            os.remove(qr_files[qr_id])
            info += f"\n[DELETED] QR file removed (time-expired): {qr_files[qr_id]}"

    return jsonify({
        "aes_key": aes_key,
        "message": decrypted_text,
        "info": info
    })

# ---------------- Frontend ----------------
@app.route("/")
def index():
    # Serve index.html directly from static folder
    return send_from_directory(app.static_folder, "index.html")

if __name__ == "__main__":
    print("Starting Flask server...")
    app.run(debug=True)
