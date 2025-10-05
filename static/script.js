function fileToFormData(id) {
    const input = document.getElementById(id);
    return input.files.length > 0 ? input.files[0] : null;
}

// Populate public keys
fetch('/list_keys').then(r => r.json()).then(data => {
    const sel = document.getElementById('pubKeySelect');
    sel.innerHTML = '';
    data.keys.forEach(f => {
        const opt = document.createElement('option');
        opt.value = f; opt.text = f;
        sel.appendChild(opt);
    });
});

async function generateKeys() {
    const pub_name = document.getElementById('pub_name').value;
    const priv_name = document.getElementById('priv_name').value;
    const res = await fetch('/generate_keys', {
        method: 'POST', headers: {'Content-Type':'application/json'},
        body: JSON.stringify({pub_name, priv_name})
    });
    const text = await res.text();
    document.getElementById('keygen_result').innerText = text;

    // Refresh keys
    fetch('/list_keys').then(r => r.json()).then(data => {
        const sel = document.getElementById('pubKeySelect');
        sel.innerHTML = '';
        data.keys.forEach(f => {
            const opt = document.createElement('option');
            opt.value = f; opt.text = f;
            sel.appendChild(opt);
        });
    });
}

async function encryptMessage() {
    const pub_file = document.getElementById('pubKeySelect').value;
    const aes_key = document.getElementById('aes_key').value;
    const mode = document.getElementById('mode').value;
    const message = document.getElementById('message').value;
    const expiry_after_decrypt = document.getElementById('expiry_after_decrypt').value;

    const res = await fetch('/encrypt', {
        method: 'POST', headers: {'Content-Type':'application/json'},
        body: JSON.stringify({pub_file, aes_key, mode, message, expiry_after_decrypt})
    });

    const data = await res.json();
    const out = `✅ AES file: ${data.aes_file}\n✅ QR code: ${data.qr_file}`;
    document.getElementById('encrypt_result').innerText = out;

    // Show share button
    window.lastEncrypt = data; // save files for sharing
    document.getElementById('share_btn').style.display = 'block';
}

async function shareFiles() {
    if (!window.lastEncrypt) return alert("Nothing to share!");
    try {
        const files = [
            new File([await fetch('/saved_qr_codes/' + window.lastEncrypt.qr_file).then(r => r.blob())], window.lastEncrypt.qr_file, {type:'image/png'}),
            new File([await fetch('/saved_qr_codes/' + window.lastEncrypt.aes_file).then(r => r.blob())], window.lastEncrypt.aes_file)
        ];
        if (navigator.canShare && navigator.canShare({files})) {
            await navigator.share({files, title:"Silent Key QR & AES", text:"Encrypted QR & AES key"});
        } else {
            alert("Sharing not supported on this device. Files are saved in server folder.");
        }
    } catch(e){ console.error(e); alert("Share failed: "+e); }
}

async function decryptMessage() {
    const formData = new FormData();
    const priv_file = fileToFormData('priv_file');
    const enc_aes_file = fileToFormData('enc_aes_file');
    const qr_file = fileToFormData('qr_file');
    const aes_key = document.getElementById('aes_override').value;

    if (!qr_file) { alert("QR file is required!"); return; }
    if (priv_file) formData.append('priv_file', priv_file);
    if (enc_aes_file) formData.append('enc_aes_file', enc_aes_file);
    formData.append('qr_file', qr_file);
    if (aes_key) formData.append('aes_key', aes_key);

    const res = await fetch('/decrypt', {method: 'POST', body: formData});
    const data = await res.json();

    const out = `🔑 AES key: ${data.aes_key}\n✅ Decrypted message${data.qr_mode==='one-time'?' (one-time)':' (normal)'}: ${data.message}\n`;
    const resultEl = document.getElementById('decrypt_result');

    let rem = data.expiry_after_decrypt;
    if(rem > 0){
        const interval = setInterval(()=>{
            if(rem <= 0){
                resultEl.innerText = out + `⏳ QR expired and deleted`;
                clearInterval(interval);
                return;
            }
            resultEl.innerText = out + `⏳ Remaining time before deletion: ${rem} sec`;
            rem--;
        },1000);
    } else {
        resultEl.innerText = out + `QR destroyed (one-time or immediate deletion)`;
    }
}
