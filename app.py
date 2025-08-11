import os
import sys
import traceback
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# Inisialisasi Aplikasi Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
db_path = os.environ.get('DATABASE_PATH', '/data/site.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Inisialisasi database saat startup
# Ini adalah perbaikan penting.
with app.app_context():
    try:
        db.create_all()
        print("Database tables created successfully.", file=sys.stderr)
    except Exception as e:
        print(f"Error creating database tables: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)

# Konfigurasi Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- Model Database ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# --- Fungsi Kriptografi Sederhana ---
def encrypt_aes(plaintext, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    return b64encode(nonce + tag + ciphertext).decode('utf-8')

def decrypt_aes(encrypted_text, key):
    try:
        data = b64decode(encrypted_text)
        nonce = data[:16]
        tag = data[16:32]
        ciphertext = data[32:]
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        decrypted_text = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted_text.decode('utf-8')
    except (ValueError, KeyError):
        return "Decryption failed. Invalid key or encrypted text."

# --- Fungsi User Loader untuk Flask-Login ---
@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(int(user_id))

# --- Rute Aplikasi ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        try:
            existing_user = db.session.query(User).filter_by(username=username).first()
            if existing_user:
                flash('Username already exists. Please choose a different one.')
                return redirect(url_for('register'))

            new_user = User(username=username)
            new_user.set_password(password)

            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! You can now log in.')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            print(f"Error during registration: {e}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            flash('Registration failed due to a server error. Please try again.')
            return redirect(url_for('register'))
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = db.session.query(User).filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    encrypted_text = None
    decrypted_text = None
    original_text = None
    key = b'mysecretpassword'

    if request.method == 'POST':
        action = request.form.get('action')
        input_text = request.form.get('text_input')
        
        if action == 'encrypt':
            original_text = input_text
            if original_text:
                encrypted_text = encrypt_aes(original_text, key)
                flash("Text encrypted successfully using AES.")
        
        elif action == 'decrypt':
            encrypted_text = input_text
            if encrypted_text:
                decrypted_text = decrypt_aes(encrypted_text, key)
                flash("Text decrypted successfully using AES.")
            
    return render_template('dashboard.html', original_text=original_text, encrypted_text=encrypted_text, decrypted_text=decrypted_text)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
