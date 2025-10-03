# server_combined.py
from flask import Flask, request, jsonify, send_file, send_from_directory
import os, base64, json, time, threading
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import qrcode, cv2, numpy as np

# PyCryptodome RSA
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

app = Flask(__name__, static_folder="static")

SAVE_DIR = "saved_qr_codes"
os.makedirs(SAVE_DIR, exist_ok=True)

qr_usage = {}     # { qr_id: first_decryption_time }
qr_expired = {}   # { qr_id: True/False }
qr_mode = {}      # { qr_id: "normal" / "one-time" / "rsa" }
qr_files = {}     # { qr_id: file_path }

# --- Key Derivation (for legacy/passphrase mode) ---
def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())

# --- Usage / Expiry handling (shared) ---
def schedule_destruction(qr_id, delay):
    time.sleep(delay)
    qr_expired[qr_id] = True
    file_path = qr_files.get(qr_id)
    if file_path and os.path.exists(file_path):
        try:
            os.remove(file_path)
        except Exception:
            pass
        print(f"[AUTO-DESTRUCT] QR file {file_path} deleted.")
    qr_files.pop(qr_id, None)
    qr_usage.pop(qr_id, None)
    qr_mode.pop(qr_id, None)

def destroy_now(qr_id):
    qr_expired[qr_id] = True
    file_path = qr_files.get(qr_id)
    if file_path and os.path.exists(file_path):
        try:
            os.remove(file_path)
        except Exception:
            pass
        print(f"[ONE-TIME] QR file {file_path} deleted instantly.")
    qr_files.pop(qr_id, None)
    qr_usage.pop(qr_id, None)
    qr_mode.pop(qr_id, None)

def handle_usage_and_countdown(qr_id, expiry, mode):
    """Return (ok:bool, info_or_error:str) — manages usage/expiry/threads."""
    if qr_expired.get(qr_id, False):
        return False, "QR code permanently expired"

    now = int(time.time())
    if mode == "one-time":
        if qr_id in qr_usage:
            return False, "QR already used and destroyed"
        qr_usage[qr_id] = now
        destroy_now(qr_id)
        return True, "[ONE-TIME] QR destroyed instantly."
    else:
        if qr_id in qr_usage:
            first_use = qr_usage[qr_id]
            elapsed = now - first_use
            if elapsed > expiry:
                qr_expired[qr_id] = True
                return False, "QR code permanently expired"
            remaining = expiry - elapsed
        else:
            qr_usage[qr_id] = now
            remaining = expiry
            # schedule deletion
            threading.Thread(target=schedule_destruction, args=(qr_id, expiry), daemon=True).start()
        return True, f"⏳ Remaining Time: {remaining} seconds"

# --- Encryption helpers ---
def create_qr_from_payload(payload_dict, qr_id):
    payload_json = json.dumps(payload_dict)
    img = qrcode.make(payload_json)
    file_path = os.path.join(SAVE_DIR, f"{qr_id}.png")
    img.save(file_path)
    qr_files[qr_id] = file_path
    qr_expired[qr_id] = False
    return file_path

# --- Routes ---
@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")

@app.route("/encrypt", methods=["POST"])
def encrypt():
    """
    Supports three modes:
    - normal / one-time: use passphrase (PBKDF2 -> AES-GCM) [legacy: previously CFB]
      required form fields: text, passphrase, expiry, mode (optional)
    - rsa: recipient_pub (file) must be uploaded. The server:
        - generates a random AES key (32 bytes),
        - encrypts plaintext with AES-GCM,
        - encrypts AES key with recipient's RSA public key (PKCS1_OAEP),
        - payload contains encrypted_key + nonce + ciphertext, expiry, mode='rsa'
      required form fields: text, expiry, mode=rsa, recipient_pub (file)
    """
    text = request.form.get("text", "")
    expiry = int(request.form.get("expiry", "60"))
    mode = request.form.get("mode", "normal").strip().lower()
    if mode not in ["normal", "one-time", "rsa"]:
        mode = "normal"

    qr_id = base64.urlsafe_b64encode(os.urandom(6)).decode()

    if mode == "rsa":
        # RSA wrapping mode -> require recipient public key file
        if "recipient_pub" not in request.files:
            return jsonify({"error": "Recipient public key file 'recipient_pub' is required for rsa mode"}), 400
        pub_file = request.files["recipient_pub"].read()
        try:
            recipient_pub = RSA.import_key(pub_file)
        except Exception as e:
            return jsonify({"error": f"Failed to load recipient public key: {str(e)}"}), 400

        # generate AES key and encrypt plaintext with AES-GCM
        aes_key = os.urandom(32)  # AES-256 key
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)  # GCM nonce
        ciphertext = aesgcm.encrypt(nonce, text.encode(), None)  # includes tag

        # encrypt AES key with recipient RSA public key (OAEP)
        rsa_cipher = PKCS1_OAEP.new(recipient_pub)
        enc_key = rsa_cipher.encrypt(aes_key)

        payload = {
            "qr_id": qr_id,
            "mode": "rsa",
            "expiry": expiry,
            "encrypted_key": base64.b64encode(enc_key).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode()
        }

        file_path = create_qr_from_payload(payload, qr_id)
        qr_mode[qr_id] = "rsa"
        # schedule destruction maintained by handle on first decrypt (same as others)
        return send_file(file_path, mimetype="image/png")

    else:
        # normal / one-time passphrase-based. Use PBKDF2 + AES-GCM (safer than CFB)
        passphrase = request.form.get("passphrase", "")
        if passphrase == "":
            return jsonify({"error": "passphrase is required for normal/one-time modes"}), 400

        salt = os.urandom(16)
        # derive key
        key = derive_key(passphrase, salt)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, text.encode(), None)

        payload = {
            "qr_id": qr_id,
            "mode": mode,
            "expiry": expiry,
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode()
        }

        file_path = create_qr_from_payload(payload, qr_id)
        qr_mode[qr_id] = mode
        return send_file(file_path, mimetype="image/png")

@app.route("/decrypt", methods=["POST"])
def decrypt():
    """
    Decrypts a QR image uploaded in 'qrfile'.
    For:
      - normal/one-time: requires 'passphrase' form field.
      - rsa: requires 'private_key' file upload (the receiver's private key).
    Returns JSON with either {"message": "...", "info": "..."} or {"error": "..."}
    """
    if "qrfile" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    qrfile = request.files["qrfile"].read()
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

    mode = payload.get("mode", "normal")

    # Handle usage/expiry/one-time logic first
    expiry = int(payload.get("expiry", 60))
    ok, info = handle_usage_and_countdown(qr_id, expiry, mode)
    if not ok:
        return jsonify({"error": info}), 400

    # RSA mode: need private key to decrypt AES key first
    if mode == "rsa":
        if "private_key" not in request.files:
            return jsonify({"error": "Private key file 'private_key' required for rsa mode"}), 400
        priv_file = request.files["private_key"].read()
        try:
            private_key = RSA.import_key(priv_file)
        except Exception as e:
            return jsonify({"error": f"Failed to load private key: {str(e)}"}), 400

        try:
            enc_key_b64 = payload["encrypted_key"]
            nonce_b64 = payload["nonce"]
            ct_b64 = payload["ciphertext"]

            enc_key = base64.b64decode(enc_key_b64)
            nonce = base64.b64decode(nonce_b64)
            ciphertext = base64.b64decode(ct_b64)

            rsa_cipher = PKCS1_OAEP.new(private_key)
            aes_key = rsa_cipher.decrypt(enc_key)

            aesgcm = AESGCM(aes_key)
            decrypted = aesgcm.decrypt(nonce, ciphertext, None)
            message = decrypted.decode()
            return jsonify({"message": message, "info": info})
        except Exception as e:
            return jsonify({"error": "Failed to decrypt rsa-mode QR: " + str(e)}), 400

    else:
        # normal / one-time: passphrase-based PBKDF2 key derivation + AES-GCM
        passphrase = request.form.get("passphrase", "")
        if passphrase == "":
            return jsonify({"error": "passphrase is required for normal/one-time modes"}), 400
        try:
            salt = base64.b64decode(payload["salt"])
            nonce = base64.b64decode(payload["nonce"])
            ciphertext = base64.b64decode(payload["ciphertext"])
            key = derive_key(passphrase, salt)
            aesgcm = AESGCM(key)
            decrypted = aesgcm.decrypt(nonce, ciphertext, None)
            message = decrypted.decode()
            return jsonify({"message": message, "info": info})
        except Exception as e:
            return jsonify({"error": "Failed to decrypt message: " + str(e)}), 400

if __name__ == "__main__":
    print("Starting Flask server with RSA/AES QR support...")
    app.run(debug=True)
