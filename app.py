from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64

app = Flask(__name__)

# Generate AES Key (for demonstration, in a real app, manage keys securely)
def generate_aes_key():
    return AES.get_random_bytes(16) # 128-bit key

# Generate RSA Key Pair (for demonstration, in a real app, manage keys securely)
def generate_rsa_key():
    key = RSA.generate(2048) # 2048-bit key
    public_key = key.publickey().export_key().decode('utf-8')
    private_key = key.export_key().decode('utf-8')
    return private_key, public_key

# --- EaaS: Encryption as a Service ---
@app.route('/encrypt', methods=['POST'])
def encrypt_data():
    data = request.json.get('plaintext')
    if not data:
        return jsonify({"error": "Missing 'plaintext' in request"}), 400

    try:
        key = generate_aes_key() # Generate a new key for each request
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(pad(data.encode('utf-8'), AES.block_size))

        return jsonify({
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "tag": base64.b64encode(tag).decode('utf-8'),
            "nonce": base64.b64encode(cipher.nonce).decode('utf-8'),
            "aes_key": base64.b64encode(key).decode('utf-8') # Send key back (for demo ONLY)
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# EaaS: Decryption as a Service
@app.route('/decrypt', methods=['POST'])
def decrypt_data():
    ciphertext_b64 = request.json.get('ciphertext')
    tag_b64 = request.json.get('tag')
    nonce_b64 = request.json.get('nonce')
    aes_key_b64 = request.json.get('aes_key')

    if not all([ciphertext_b64, tag_b64, nonce_b64, aes_key_b64]):
        return jsonify({"error": "Missing required data for decryption"}), 400

    try:
        ciphertext = base64.b64decode(ciphertext_b64)
        tag = base64.b64decode(tag_b64)
        nonce = base64.b64decode(nonce_b64)
        aes_key = base64.b64decode(aes_key_b64)

        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        plaintext = unpad(cipher.decrypt_and_verify(ciphertext, tag), AES.block_size)

        return jsonify({"plaintext": plaintext.decode('utf-8')}), 200
    except Exception as e:
        return jsonify({"error": f"Decryption failed: {str(e)}. Check key, nonce, tag, and ciphertext."}), 400


# --- Signing as a Service (SaaS - Digital Signature) ---
@app.route('/sign', methods=['POST'])
def sign_data():
    data = request.json.get('data')
    if not data:
        return jsonify({"error": "Missing 'data' to sign"}), 400

    try:
        private_key_pem, public_key_pem = generate_rsa_key()
        private_key = RSA.import_key(private_key_pem)

        h = SHA256.new(data.encode('utf-8'))
        signature = pkcs1_15.new(private_key).sign(h)

        return jsonify({
            "signature": base64.b64encode(signature).decode('utf-8'),
            "public_key": public_key_pem,
            "private_key": private_key_pem # NEVER DO THIS IN PRODUCTION!
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- Verify Signing as a Service (VaaS) ---
@app.route('/verify', methods=['POST'])
def verify_signature():
    data = request.json.get('data')
    signature_b64 = request.json.get('signature')
    public_key_pem = request.json.get('public_key')

    if not all([data, signature_b64, public_key_pem]):
        return jsonify({"error": "Missing 'data', 'signature', or 'public_key' for verification"}), 400

    try:
        signature = base64.b64decode(signature_b64)
        public_key = RSA.import_key(public_key_pem)

        h = SHA256.new(data.encode('utf-8'))
        pkcs1_15.new(public_key).verify(h, signature)

        return jsonify({"message": "Signature is valid"}), 200
    except (ValueError, TypeError) as e:
        return jsonify({"message": f"Signature is invalid: {str(e)}"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)