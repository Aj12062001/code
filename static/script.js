// --- Key Generation ---
document.getElementById("genKeys").addEventListener("click", async () => {
    const pub_name = document.getElementById("pub_name").value;
    const priv_name = document.getElementById("priv_name").value;
    const formData = new FormData();
    formData.append("pub_name", pub_name);
    formData.append("priv_name", priv_name);

    const res = await fetch("/generate_keys", { method: "POST", body: formData });
    const data = await res.json();
    document.getElementById("keyResult").textContent = data.message;
});

// --- Encryption ---
document.getElementById("encryptBtn").addEventListener("click", async () => {
    const pub_file = document.getElementById("recipientPub").files[0];
    const aes_key = document.getElementById("aes_key").value;
    const message = document.getElementById("message").value;
    const expiry = document.getElementById("expiry").value;
    const mode = document.getElementById("mode").value;

    const formData = new FormData();
    formData.append("pub_file", pub_file);
    formData.append("aes_key", aes_key);
    formData.append("message", message);
    formData.append("expiry", expiry);
    formData.append("mode", mode);

    const res = await fetch("/encrypt", { method: "POST", body: formData });
    const data = await res.json();
    document.getElementById("qrResult").textContent =
        `✅ AES file: ${data.aes_file}\n✅ QR file: ${data.qr_file}`;
});

// --- Decryption ---
let countdownInterval;

document.getElementById("decryptBtn").addEventListener("click", async () => {
    const priv_file = document.getElementById("privateKey").files[0];
    const aes_file = document.getElementById("aesFile").files[0];
    const qr_file = document.getElementById("qrFile").files[0];
    const aesInput = document.getElementById("aesInput").value;

    const formData = new FormData();
    formData.append("priv_file", priv_file);
    formData.append("aes_file", aes_file);
    formData.append("qr_file", qr_file);
    formData.append("aes_key", aesInput);

    const res = await fetch("/decrypt", { method: "POST", body: formData });
    const data = await res.json();
    document.getElementById("decryptedResult").textContent = `✅ Decrypted message:\n${data.message}`;

    // Clear previous countdown
    if (countdownInterval) clearInterval(countdownInterval);

    if (data.info && data.info.includes("Remaining Time")) {
        let seconds = parseInt(data.info.match(/\d+/)[0]);
        const timerEl = document.getElementById("timer");
        timerEl.textContent = `⏳ Remaining Time: ${seconds}s`;

        countdownInterval = setInterval(() => {
            seconds--;
            if (seconds > 0) {
                timerEl.textContent = `⏳ Remaining Time: ${seconds}s`;
            } else {
                timerEl.textContent = `[COUNTDOWN FINISHED]`;
                clearInterval(countdownInterval);
            }
        }, 1000);
    } else {
        document.getElementById("timer").textContent = "";
    }
});
    