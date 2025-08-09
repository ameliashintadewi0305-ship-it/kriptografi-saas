async function kirimPesan(pengirim) {
    const pesanInput = document.getElementById('messageA');
    const pesan = pesanInput.value;

    if (!pesan) {
        alert("Pesan tidak boleh kosong!");
        return;
    }
    
    // Kirim pesan ke API untuk dienkripsi dan ditandatangani
    const response = await fetch('/api/encrypt', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ plaintext: pesan })
    });

    const data = await response.json();
    document.getElementById('sentMessageA').textContent = JSON.stringify(data, null, 2);
    
    // Simulasikan pesan diterima oleh User B
    terimaPesan('B', data);
}

async function terimaPesan(penerima, dataPesan) {
    // Kirim pesan yang terenkripsi ke API untuk didekripsi dan diverifikasi
    const response = await fetch('/api/decrypt', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(dataPesan)
    });
    
    const data = await response.json();
    
    const pesanDiterima = document.getElementById('receivedMessageB');
    if (data.status === 'success') {
        pesanDiterima.textContent = data.plaintext;
    } else {
        pesanDiterima.textContent = 'Verifikasi atau dekripsi gagal: ' + data.error;
    }
}