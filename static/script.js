async function encrypt() {
  const text = document.getElementById("text").value;
  const passphrase = document.getElementById("passphrase").value;
  const expiry = document.getElementById("expiry").value;
  const mode = document.getElementById("mode").value;

  if (!text || !passphrase) {
    alert("Please enter message and passphrase!");
    return;
  }

  const formData = new FormData();
  formData.append("text", text);
  formData.append("passphrase", passphrase);
  formData.append("expiry", expiry);
  formData.append("mode", mode);

  const response = await fetch("/encrypt", { method: "POST", body: formData });
  if (response.ok) {
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    document.getElementById("qrResult").innerHTML =
      `<p>QR Generated (${mode} mode):</p><img src="${url}" width="250"/>`;
  } else {
    alert("Encryption failed!");
  }
}

async function decrypt() {
  const fileInput = document.getElementById("qrfile");
  const passphrase = document.getElementById("decryptPass").value;

  if (fileInput.files.length === 0 || !passphrase) {
    alert("Please upload QR and enter passphrase!");
    return;
  }

  const formData = new FormData();
  formData.append("qrfile", fileInput.files[0]);
  formData.append("passphrase", passphrase);

  const response = await fetch("/decrypt", { method: "POST", body: formData });
  const result = await response.json();

  if (result.error) {
    document.getElementById("decrypted").innerHTML = "❌ " + result.error;
  } else {
    let msg = "✅ Message: " + result.message;
    if (result.remaining !== undefined) {
      msg += `<br/>⏳ Remaining time: ${result.remaining}s`;
    }
    document.getElementById("decrypted").innerHTML = msg;
  }
}
