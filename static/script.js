// Encrypt Form
document.getElementById("encryptForm").addEventListener("submit", async function (e) {
  e.preventDefault();
  const formData = new FormData();
  formData.append("text", document.getElementById("text").value);
  formData.append("expiry", document.getElementById("expiry").value);
  formData.append("passphrase", document.getElementById("passphrase").value);

  const res = await fetch("/encrypt", { method: "POST", body: formData });
  if (res.ok) {
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    document.getElementById("qrResult").innerHTML = `<img src="${url}" alt="QR Code" />`;
  } else {
    document.getElementById("qrResult").textContent = "Encryption failed.";
  }
});

// Decrypt Form
document.getElementById("decryptForm").addEventListener("submit", async function (e) {
  e.preventDefault();
  const formData = new FormData();
  formData.append("qrfile", document.getElementById("qrfile").files[0]);
  formData.append("passphrase", document.getElementById("decryptPassphrase").value);

  const res = await fetch("/decrypt", { method: "POST", body: formData });
  const resultDiv = document.getElementById("decryptedResult");
  const timerDiv = document.getElementById("timer");

  if (res.ok) {
    const data = await res.json();
    resultDiv.textContent = "Decrypted Message: " + data.message;

    let timeLeft = data.remaining;
    if (timeLeft <= 0) {
      timerDiv.textContent = "QR code already expired.";
      resultDiv.textContent = "";
      return;
    }

    timerDiv.textContent = `Time left: ${timeLeft}s`;
    const countdown = setInterval(() => {
      timeLeft--;
      if (timeLeft > 0) {
        timerDiv.textContent = `Time left: ${timeLeft}s`;
      } else {
        clearInterval(countdown);
        timerDiv.textContent = "Expired. QR code can’t be used again.";
        resultDiv.textContent = "";
      }
    }, 1000);
  } else {
    const err = await res.json();
    resultDiv.textContent = "Error: " + (err.error || "Decryption failed.");
    timerDiv.textContent = "";
  }
});
