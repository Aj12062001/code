// F:\mini project\code\static\script.js

const API_BASE_URL = window.location.origin; // Dynamically get base URL

document.addEventListener('DOMContentLoaded', () => {
    refreshKeys('all');
    refreshQrFiles('all');
    toggleExpiryInput(); // Initialize expiry input visibility
});

// --- Utility Functions ---
async function fetchData(url, method = 'GET', data = null) {
    const options = {
        method: method,
        headers: {
            'Content-Type': 'application/json',
        },
    };
    if (data) {
        options.body = JSON.stringify(data);
    }

    try {
        const response = await fetch(url, options);
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error('Fetch error:', error);
        return { status: 'error', message: error.message };
    }
}

function displayOutput(elementId, result, qrImageUrl = null, countdownTime = null) {
    const outputDiv = document.getElementById(elementId);
    outputDiv.innerHTML = ''; // Clear previous output

    let content = '';
    if (result.status === 'success') {
        content += `<span class="status-success">✅ ${result.message}</span><br>`;
        if (result.public_key_path) content += `Public: ${result.public_key_path}<br>`;
        if (result.private_key_path) content += `Private: ${result.private_key_path}<br>`;
        if (result.encrypted_aes_passphrase_file) content += `AES key file: ${result.encrypted_aes_passphrase_file}<br>`;
        if (result.qr_image_path) content += `QR code file: ${result.qr_image_path}<br>`;
        if (result.decrypted_aes_passphrase_plain) content += `🔑 Decrypted AES key (plain text): ${result.decrypted_aes_passphrase_plain}<br>`;
        if (result.decrypted_message) content += `✅ Decrypted message (${result.qr_metadata.mode}): ${result.decrypted_message}<br>`;
        if (result.qr_metadata && result.qr_metadata.mode === 'normal' && countdownTime !== null) {
            startDecryptionCountdown(countdownTime, outputDiv, result.qr_image_path, result.qr_metadata.qr_id);
        }
    } else {
        content += `<span class="status-error">❌ ${result.message}</span>`;
    }
    outputDiv.innerHTML = content;

    if (qrImageUrl) {
        const qrDisplayDiv = document.getElementById('qrCodeDisplay');
        qrDisplayDiv.innerHTML = `<img src="${qrImageUrl}" alt="Generated QR Code">`;
    } else if (elementId === 'encryptionOutput') {
        document.getElementById('qrCodeDisplay').innerHTML = ''; // Clear QR display if no image
    }
}

// --- Key Generation ---
async function generateKeys() {
    const publicKeyName = document.getElementById('publicKeyName').value.trim();
    const privateKeyName = document.getElementById('privateKeyName').value.trim();
    const privateKeyPassword = document.getElementById('privateKeyPasswordGen').value;

    const data = { publicKeyName, privateKeyName };
    if (privateKeyPassword) {
        data.privateKeyPassword = privateKeyPassword;
    }

    const result = await fetchData(`${API_BASE_URL}/api/generate_keys`, 'POST', data);
    displayOutput('keyGenerationOutput', result);
    if (result.status === 'success') {
        refreshKeys('all');
    }
}

async function refreshKeys(type) {
    const result = await fetchData(`${API_BASE_URL}/api/list_keys`);
    if (result.status === 'error') {
        console.error('Error fetching keys:', result.message);
        return;
    }

    const publicSelect = document.getElementById('receiverPublicKey');
    const privateSelect = document.getElementById('privateKeyDec');

    const populateSelect = (selectElement, keysArray) => {
        selectElement.innerHTML = '<option value="">Select a key</option>';
        keysArray.forEach(key => {
            const option = document.createElement('option');
            option.value = key;
            option.textContent = key;
            selectElement.appendChild(option);
        });
    };

    if (type === 'public' || type === 'all') {
        populateSelect(publicSelect, result.public_keys);
    }
    if (type === 'private' || type === 'all') {
        populateSelect(privateSelect, result.private_keys);
    }
}

// --- Encryption ---
function toggleExpiryInput() {
    const mode = document.getElementById('encryptionMode').value;
    const expiryGroup = document.getElementById('expiryInputGroup');
    if (mode === 'normal') {
        expiryGroup.style.display = 'block';
    } else {
        expiryGroup.style.display = 'none';
    }
}

async function encryptMessage() {
    const receiverPublicKeyFile = document.getElementById('receiverPublicKey').value;
    const aesPassphrase = document.getElementById('aesPassphraseEnc').value;
    const message = document.getElementById('messageToEncrypt').value;
    const mode = document.getElementById('encryptionMode').value;
    const expiry = document.getElementById('expiryTime').value;

    const data = {
        receiverPublicKeyFile,
        aesPassphrase,
        message,
        mode,
        expiry: mode === 'normal' ? expiry : 0
    };

    const result = await fetchData(`${API_BASE_URL}/api/encrypt`, 'POST', data);
    let qrImageUrl = null;
    if (result.status === 'success' && result.qr_image_path) {
        const qrFilename = result.qr_image_path.split('\\').pop().split('/').pop(); // Extract filename
        qrImageUrl = `${API_BASE_URL}/qrcodes/${qrFilename}`;
        refreshQrFiles('all'); // Refresh decryption selects
    }
    displayOutput('encryptionOutput', result, qrImageUrl);
}

// --- Decryption ---
async function refreshQrFiles(type) {
    const result = await fetchData(`${API_BASE_URL}/api/list_qr_files`);
    if (result.status === 'error') {
        console.error('Error fetching QR files:', result.message);
        return;
    }

    const encryptedAesKeySelect = document.getElementById('encryptedAesKeyFile');
    const qrImageFileSelect = document.getElementById('qrImageFile');

    const populateSelect = (selectElement, filesArray) => {
        selectElement.innerHTML = '<option value="">Select a file</option>';
        filesArray.forEach(file => {
            const option = document.createElement('option');
            option.value = file;
            option.textContent = file;
            selectElement.appendChild(option);
        });
    };

    if (type === 'aes' || type === 'all') {
        populateSelect(encryptedAesKeySelect, result.encrypted_aes_keys);
    }
    if (type === 'qr' || type === 'all') {
        populateSelect(qrImageFileSelect, result.qr_files);
    }
}

async function decryptMessage() {
    const privateKeyFile = document.getElementById('privateKeyDec').value;
    const privateKeyPassword = document.getElementById('privateKeyPasswordDec').value;
    const encryptedAesKeyFile = document.getElementById('encryptedAesKeyFile').value;
    const qrImageFile = document.getElementById('qrImageFile').value;
    const aesPassphraseOverride = document.getElementById('aesPassphraseOverride').value;

    const data = {
        privateKeyFile,
        encryptedAesKeyFile,
        qrImageFile,
    };
    if (privateKeyPassword) {
        data.privateKeyPassword = privateKeyPassword;
    }
    if (aesPassphraseOverride) {
        data.aesPassphraseOverride = aesPassphraseOverride;
    }

    const result = await fetchData(`${API_BASE_URL}/api/decrypt`, 'POST', data);
    
    // Check if QR needs to be removed from lists
    if (result.status === 'success' && result.qr_metadata && 
        (result.qr_metadata.mode === 'one-time' || result.qr_metadata.expired || result.qr_metadata.used)) {
        // Give a slight delay for the user to see the output before refreshing the list
        setTimeout(() => refreshQrFiles('all'), 1000);
    }

    let countdownTime = null;
    if (result.status === 'success' && result.qr_metadata && result.qr_metadata.mode === 'normal') {
        const now = Math.floor(Date.now() / 1000);
        const firstUse = result.qr_metadata.first_use || now; // Use current time if first_use not set yet
        const created_at = result.qr_metadata.created_at || now; // Fallback
        const expiry = result.qr_metadata.expiry || 0;
        
        // Calculate remaining based on server's first_use and original expiry
        const elapsedSinceFirstUse = now - firstUse;
        countdownTime = Math.max(0, expiry - elapsedSinceFirstUse);
    }

    displayOutput('decryptionOutput', result, null, countdownTime);
}

// --- Live Countdown for Decryption ---
let countdownInterval = null;

function startDecryptionCountdown(initialSeconds, outputDiv, qrPath, qrId) {
    if (countdownInterval) {
        clearInterval(countdownInterval);
    }

    let remainingSeconds = initialSeconds;
    const countdownDiv = document.getElementById('decryptionCountdown');
    countdownDiv.style.display = 'block';

    countdownInterval = setInterval(async () => {
        if (remainingSeconds <= 0) {
            clearInterval(countdownInterval);
            countdownDiv.innerHTML = '<span class="status-error">[COUNTDOWN FINISHED] QR expired.</span>';
            // Trigger a refresh of QR files after expiry to remove it from the dropdown
            setTimeout(() => refreshQrFiles('all'), 1000); 
            return;
        }

        countdownDiv.innerHTML = `<span class="status-info">⏳ Remaining Time: ${remainingSeconds} seconds</span>`;
        remainingSeconds--;
    }, 1000);