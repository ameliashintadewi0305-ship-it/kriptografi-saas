from flask import Flask, render_template, request, jsonify
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.asymmetric import rsa

app = Flask(__name__)

# Kunci dummy untuk User A dan B.
# Ini harus dibuat sekali dan disimpan dengan aman.
private_key_a = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key_a = private_key_a.public_key()

private_key_b = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key_b = private_key_b.public_key()

def get_public_keys():
    """Mengembalikan kunci publik dalam format yang bisa dikirimkan."""
    return {
        'A': public_key_a.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8'),
        'B': public_key_b.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/encrypt', methods=['POST'])
def encrypt_message():
    data = request.json
    plaintext = data.get('plaintext').encode('utf-8')
    
    # 1. Generate AES key dan nonce
    aes_key = os.urandom(32)
    nonce = os.urandom(16)
    
    # 2. Enkripsi plaintext dengan AES
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    
    # 3. Enkripsi AES key dengan public key User B
    encrypted_aes_key = public_key_b.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 4. Tanda tangani ciphertext dengan private key User A
    signature = private_key_a.sign(
        ciphertext,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return jsonify({
        'encrypted_aes_key': b64encode(encrypted_aes_key).decode('utf-8'),
        'nonce': b64encode(nonce).decode('utf-8'),
        'ciphertext': b64encode(ciphertext).decode('utf-8'),
        'tag': b64encode(tag).decode('utf-8'),
        'signature': b64encode(signature).decode('utf-8')
    })

@app.route('/api/decrypt', methods=['POST'])
def decrypt_message():
    data = request.json
    encrypted_aes_key = b64decode(data.get('encrypted_aes_key'))
    nonce = b64decode(data.get('nonce'))
    ciphertext = b64decode(data.get('ciphertext'))
    tag = b64decode(data.get('tag'))
    signature = b64decode(data.get('signature'))
    
    try:
        # 1. Verifikasi tanda tangan menggunakan public key User A
        public_key_a.verify(
            signature,
            ciphertext,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # 2. Dekripsi AES key menggunakan private key User B
        aes_key = private_key_b.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 3. Dekripsi pesan
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return jsonify({
            'plaintext': plaintext.decode('utf-8'),
            'status': 'success'
        })
    except Exception as e:
        return jsonify({'status': 'failed', 'error': str(e)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)