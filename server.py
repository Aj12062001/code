from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os, base64, json, time, qrcode, secrets, threading, traceback
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import time

app = Flask(__name__)
CORS(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
KEY_DIR = os.path.join(BASE_DIR, "saved_keys")
QR_DIR = os.path.join(BASE_DIR, "saved_qr_codes")
os.makedirs(KEY_DIR, exist_ok=True)
os.makedirs(QR_DIR, exist_ok=True)


# ---------------- DERIVE AES KEY ----------------
def derive_key(aes_key, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(aes_key.encode())


# ---------------- KEY GENERATION ----------------
@app.route('/generate_keys', methods=['POST'])
def generate_keys():
    data = request.json
    pub_name = data.get('pub_name')
    priv_name = data.get('priv_name')
    if not pub_name or not priv_name:
        return "Provide both public and private key names", 400

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    priv_path = os.path.join(KEY_DIR, f"{priv_name}.pem")
    pub_path = os.path.join(KEY_DIR, f"{pub_name}.pem")

    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))
    with open(pub_path, "wb") as f:
        f.write(public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    return f"✅ Keys saved:\nPublic: {pub_path}\nPrivate: {priv_path}"


# ---------------- LIST KEYS ----------------
@app.route('/list_keys')
def list_keys():
    files = os.listdir(KEY_DIR)
    pem_files = [f for f in files if f.endswith('.pem')]
    return jsonify({'keys': pem_files})


# ---------------- ENCRYPTION ----------------
@app.route('/encrypt', methods=['POST'])
def encrypt_message():
    data = request.json
    pub_file = data.get('pub_file')
    aes_key = data.get('aes_key')
    mode = data.get('mode', 'normal')
    message = data.get('message')

    # safe parse expiry
    try:
        expiry_after_decrypt = int(data.get('expiry_after_decrypt', 0))
    except (ValueError, TypeError):
        expiry_after_decrypt = 0

    if not all([pub_file, aes_key, message]):
        return "Missing required fields", 400

    # load public key
    pub_path = os.path.join(KEY_DIR, pub_file)
    if not os.path.exists(pub_path):
        return "Public key file not found", 400
    with open(pub_path, "rb") as f:
        pub = serialization.load_pem_public_key(f.read())

    # Encrypt AES key and save server-side AES file
    enc_aes = pub.encrypt(aes_key.encode(), padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))
    aes_file_name = f"aes_{secrets.token_hex(6)}.pem"
    aes_file_path = os.path.join(QR_DIR, aes_file_name)
    with open(aes_file_path, "wb") as f:
        f.write(enc_aes)

    # Encrypt message to QR (AES-derived key)
    salt = os.urandom(16)
    iv = os.urandom(16)
    key_bytes = derive_key(aes_key, salt)
    cipher = Cipher(algorithms.AES(key_bytes), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()

    qr_id = secrets.token_urlsafe(8)
    payload = {
        "qr_id": qr_id,
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "mode": mode,
        "expiry_after_decrypt": expiry_after_decrypt,
        "aes_file": aes_file_name,            # include AES filename so decrypt can delete it
        "created_at": int(time.time())
    }

    qr_file_name = f"{qr_id}.png"
    qr_file_path = os.path.join(QR_DIR, qr_file_name)
    qrcode.make(json.dumps(payload)).save(qr_file_path)

    # Note: no deletion scheduled here — deletion starts after successful decryption
    return jsonify({
        'aes_file': aes_file_name,
        'qr_file': qr_file_name,
        'qr_id': qr_id
    })


# ---------------- DECRYPTION ----------------
@app.route('/decrypt', methods=['POST'])
def decrypt_endpoint():
    if not request.content_type.startswith('multipart/form-data'):
        return "Invalid request", 400

    priv_file = request.files.get('priv_file')
    enc_aes_file = request.files.get('enc_aes_file')
    qr_file = request.files.get('qr_file')
    aes_key_override = request.form.get('aes_key', None)

    if not qr_file:
        return "QR file is required", 400

    try:
        # AES Key retrieval
        if aes_key_override:
            aes_key = aes_key_override
            server_aes_path = None
        else:
            if not priv_file or not enc_aes_file:
                return "Private key and encrypted AES key files are required", 400

            # Save encrypted AES file temporarily
            server_aes_path = os.path.join(QR_DIR, enc_aes_file.filename)
            enc_aes_bytes = enc_aes_file.read()
            with open(server_aes_path, "wb") as f:
                f.write(enc_aes_bytes)

            # Load private key and decrypt
            priv = serialization.load_pem_private_key(priv_file.read(), password=None)
            aes_key = priv.decrypt(enc_aes_bytes, padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )).decode()

        # Save QR temporarily
        qr_file_real_path = os.path.join(QR_DIR, qr_file.filename)
        qr_file.save(qr_file_real_path)

        # Decode QR
        import cv2
        img = cv2.imread(qr_file_real_path)
        data_str, _, _ = cv2.QRCodeDetector().detectAndDecode(img)
        if not data_str:
            safe_remove(qr_file_real_path)
            safe_remove(server_aes_path)
            return "Failed to decode QR code", 400

        payload = json.loads(data_str)
        salt = base64.b64decode(payload["salt"])
        iv = base64.b64decode(payload["iv"])
        ciphertext = base64.b64decode(payload["ciphertext"])
        key_bytes = derive_key(aes_key, salt)
        cipher = Cipher(algorithms.AES(key_bytes), modes.CFB(iv), backend=default_backend())
        message = cipher.decryptor().update(ciphertext) + cipher.decryptor().finalize()
        message = message.decode()

        mode = payload.get("mode")
        expiry_after_decrypt = int(payload.get("expiry_after_decrypt", 0))

        # Safe delete function
        def safe_remove(path, retries=5, delay=0.1):
            for _ in range(retries):
                try:
                    if path and os.path.exists(path):
                        os.remove(path)
                        print(f"[AUTO-DELETE] File deleted: {path}")
                    return
                except PermissionError:
                    time.sleep(delay)
            print(f"[AUTO-DELETE] Failed to delete: {path}")

        # ONE-TIME mode: delete immediately after decryption
        if mode == "one-time":
            # Run in thread to ensure no file handles are active
            threading.Thread(
                target=lambda: (
                    safe_remove(server_aes_path),
                    safe_remove(qr_file_real_path)
                ),
                daemon=True
            ).start()

        # NORMAL mode: delete after expiry
        elif mode == "normal" and expiry_after_decrypt > 0:
            threading.Thread(
                target=lambda: (
                    time.sleep(expiry_after_decrypt),
                    safe_remove(server_aes_path),
                    safe_remove(qr_file_real_path)
                ),
                daemon=True
            ).start()

        return jsonify({
            'aes_key': aes_key,
            'message': message,
            'qr_mode': mode,
            'expiry_after_decrypt': expiry_after_decrypt,
            'qr_deleted': mode == "one-time"
        })

    except Exception as e:
        return f"=== Decryption error ===\n{traceback.format_exc()}", 400


# ---------------- STATIC ----------------
@app.route('/saved_qr_codes/<filename>')
def serve_qr(filename):
    return send_from_directory(QR_DIR, filename)

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory(STATIC_DIR, path)


@app.route('/')
def index():
    return send_from_directory(STATIC_DIR, 'index.html')


if __name__ == "__main__":
    app.run(debug=True)
