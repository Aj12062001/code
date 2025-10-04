# F:\mini project\code\server.py

import os
import json
from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_cors import CORS # For development, allows frontend from different origin if needed
import threading
import time

# Import our modular crypto functions
from key import generate_rsa_key_pair, load_private_key # Also load_private_key for decryption
from encrypt import perform_encryption_flow, SAVE_DIR as QR_SAVE_DIR # Reuse SAVE_DIR from encrypt for qr codes
from decrypt import perform_decryption_flow, SAVE_DIR as DECRYPT_SAVE_DIR, load_qr_metadata, save_qr_metadata, destroy_qr_assets

# Assume KEYS_DIR from key.py is the correct path for saved_keys
from key import KEYS_DIR 

app = Flask(__name__, static_folder='static', template_folder='static')
CORS(app) # Enable CORS for development

# Ensure directories exist
os.makedirs(KEYS_DIR, exist_ok=True)
os.makedirs(QR_SAVE_DIR, exist_ok=True) # Both encrypt and decrypt use this


# --- Helper to list files in a directory ---
def list_files_in_dir(directory):
    try:
        # Filter for .pem (keys) and .png (qrcodes) and .bin (encrypted aes keys)
        return [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f)) and 
                (f.endswith('.pem') or f.endswith('.png') or f.endswith('.bin'))]
    except FileNotFoundError:
        return []
    except Exception as e:
        app.logger.error(f"Error listing files in {directory}: {e}")
        return []

# --- Custom Countdown Thread for Decryption UI Update ---
# This is a bit more complex for web, as frontend should manage its own countdown.
# However, to mirror your CLI countdown, we can send updates via a websocket
# or have the frontend poll. For simplicity, we'll let the frontend manage it
# based on the initial expiry info, and the backend handles the actual destruction.
# The `schedule_destruction` in `decrypt.py` already handles backend file deletion.

# Helper for the frontend to show QR image
@app.route('/qrcodes/<filename>')
def serve_qrcode(filename):
    return send_from_directory(QR_SAVE_DIR, filename)

# Helper for the frontend to show encrypted AES key
@app.route('/aes_keys/<filename>')
def serve_aes_key(filename):
    # This might not be directly "shown" but downloaded or referenced
    # It's in the same SAVE_DIR as QRs, as per your structure
    return send_from_directory(QR_SAVE_DIR, filename)


# --- Frontend Routes ---
@app.route('/')
def index():
    return render_template('index.html')

# --- API Endpoints ---

@app.route('/api/list_keys')
def api_list_keys():
    public_keys = [f for f in list_files_in_dir(KEYS_DIR) if f.startswith('pub_') and f.endswith('.pem')]
    private_keys = [f for f in list_files_in_dir(KEYS_DIR) if f.startswith('priv_') and f.endswith('.pem')]
    return jsonify({
        "public_keys": public_keys,
        "private_keys": private_keys
    })

@app.route('/api/list_qr_files')
def api_list_qr_files():
    qr_files = [f for f in list_files_in_dir(QR_SAVE_DIR) if f.endswith('.png')]
    encrypted_aes_keys = [f for f in list_files_in_dir(QR_SAVE_DIR) if f.startswith('aes_key_') and f.endswith('.bin')]
    return jsonify({
        "qr_files": qr_files,
        "encrypted_aes_keys": encrypted_aes_keys
    })

@app.route('/api/generate_keys', methods=['POST'])
def api_generate_keys():
    data = request.json
    pub_name = data.get('publicKeyName')
    priv_name = data.get('privateKeyName')
    password = data.get('privateKeyPassword') # Optional

    if not pub_name or not priv_name:
        return jsonify({"status": "error", "message": "Public and Private key names are required."}), 400

    try:
        result = generate_rsa_key_pair(pub_name, priv_name, password)
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/encrypt', methods=['POST'])
def api_encrypt():
    data = request.json
    receiver_public_key_file = data.get('receiverPublicKeyFile') # e.g., 'ajin.pem'
    aes_passphrase = data.get('aesPassphrase')
    message = data.get('message')
    mode = data.get('mode')
    expiry = data.get('expiry') # In seconds

    if not all([receiver_public_key_file, aes_passphrase, message, mode]):
        return jsonify({"status": "error", "message": "All encryption fields are required."}), 400

    receiver_public_key_path = os.path.join(KEYS_DIR, receiver_public_key_file)
    
    try:
        result = perform_encryption_flow(
            receiver_public_key_path,
            aes_passphrase,
            message,
            mode,
            int(expiry) if mode == "normal" else 0
        )
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Encryption error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/decrypt', methods=['POST'])
def api_decrypt():
    data = request.json
    private_key_file = data.get('privateKeyFile') # e.g., 'jose.pem'
    private_key_password = data.get('privateKeyPassword') # Optional
    encrypted_aes_key_file = data.get('encryptedAesKeyFile') # e.g., 'aes_ea029657.bin'
    qr_image_file = data.get('qrImageFile') # e.g., 'heIKshBZ.png'
    aes_passphrase_override = data.get('aesPassphraseOverride') # Optional

    if not all([private_key_file, encrypted_aes_key_file, qr_image_file]):
        return jsonify({"status": "error", "message": "All decryption files are required."}), 400

    private_key_path = os.path.join(KEYS_DIR, private_key_file)
    encrypted_aes_key_path = os.path.join(QR_SAVE_DIR, encrypted_aes_key_file) # Stored in QR_SAVE_DIR
    qr_image_path = os.path.join(QR_SAVE_DIR, qr_image_file)

    try:
        result = perform_decryption_flow(
            private_key_path,
            encrypted_aes_key_path,
            qr_image_path,
            private_key_password,
            aes_passphrase_override
        )
        # For one-time and expired QRs, the frontend might need to know to refresh its list
        if result["status"] == "success" and (result["qr_metadata"].get("used") or result["qr_metadata"].get("expired")):
            # Schedule a short delay to allow frontend to process, then delete from list
            pass # The backend `schedule_destruction` handles actual file removal
        
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Decryption error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    # Start Flask app
    app.run(debug=True, port=5000)