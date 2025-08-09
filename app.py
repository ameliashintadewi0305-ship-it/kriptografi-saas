from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
import os
import secrets
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-very-secret-key-that-should-be-strong'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/site.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    public_key = db.Column(db.String(2048), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_first_request
def create_tables():
    db.create_all()

@app.route('/')
def home():
    if current_user.is_authenticated:
        users = User.query.filter(User.id != current_user.id).all()
        return render_template('dashboard.html', users=users)
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Login Failed. Check username and password.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Generate new RSA key pair for the user
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        
        # Serialize public key to string
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        user = User(username=username, public_key=public_key_pem)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Endpoint API untuk enkripsi/dekripsi, sekarang membutuhkan otentikasi
@app.route('/api/encrypt/<username>', methods=['POST'])
@login_required
def encrypt_message(username):
    recipient = User.query.filter_by(username=username).first()
    if not recipient:
        return jsonify({'error': 'Recipient not found'}), 404
    
    data = request.json
    plaintext = data.get('plaintext').encode('utf-8')
    
    aes_key = os.urandom(32)
    nonce = os.urandom(16)
    
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    
    return jsonify({
        'aes_key': b64encode(aes_key).decode('utf-8'),
        'nonce': b64encode(nonce).decode('utf-8'),
        'ciphertext': b64encode(ciphertext).decode('utf-8'),
        'tag': b64encode(tag).decode('utf-8'),
        'recipient_public_key': recipient.public_key
    })

# Endpoint untuk sign (tanda tangan)
@app.route('/api/sign', methods=['POST'])
@login_required
def sign_message():
    data = request.json
    ciphertext = b64decode(data.get('ciphertext'))
    # Private key should be managed securely, this is for demonstration
    private_key_pem = "your_private_key_here" # Placeholder, get from user session
    # ... your signing logic here ...
    signature = b"dummy_signature"

    return jsonify({
        'signature': b64encode(signature).decode('utf-8')
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)