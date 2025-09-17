const encryptForm = document.getElementById("encryptForm");
const decryptForm = document.getElementById("decryptForm");

encryptForm.addEventListener("submit", async e => {
    e.preventDefault();
    const text = document.getElementById("text").value;
    const passphrase = document.getElementById("passphrase").value;
    const expiry = document.getElementById("expiry").value;
    const mode = document.getElementById("mode").value;

    const formData = new FormData();
    formData.append("text", text);
    formData.append("passphrase", passphrase);
    formData.append("expiry", expiry);
    formData.append("mode", mode);

    const res = await fetch("/encrypt", { method: "POST", body: formData });
    if (res.ok) {
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        document.getElementById("qrResult").innerHTML = `<img src="${url}" alt="QR Code" />`;
    } else {
        document.getElementById("qrResult").textContent = "❌ Encryption failed.";
    }
});

decryptForm.addEventListener("submit", async e => {
    e.preventDefault();
    const file = document.getElementById("qrfile").files[0];
    const passphrase = document.getElementById("decryptPassphrase").value;

    const formData = new FormData();
    formData.append("qrfile", file);
    formData.append("passphrase", passphrase);

    const res = await fetch("/decrypt", { method: "POST", body: formData });
    const data = await res.json();

    if (data.message) {
        document.getElementById("decryptedResult").textContent = data.message;
        if (data.info && data.info.includes("Remaining Time")) {
            const seconds = parseInt(data.info.match(/\d+/)[0]);
            startTimer(seconds);
        } else {
            document.getElementById("timer").textContent = data.info || "";
        }
    } else {
        document.getElementById("decryptedResult").textContent = data.error || "❌ Decryption failed.";
        document.getElementById("timer").textContent = "";
    }
});

function startTimer(seconds) {
    let remaining = seconds;
    document.getElementById("timer").textContent = `⏳ Message will disappear in ${remaining}s`;
    const interval = setInterval(() => {
        remaining--;
        if (remaining > 0) {
            document.getElementById("timer").textContent = `⏳ Message will disappear in ${remaining}s`;
        } else {
            clearInterval(interval);
            document.getElementById("decryptedResult").textContent = "";
            document.getElementById("timer").textContent = "⏱️ Message expired";
        }
    }, 1000);
}