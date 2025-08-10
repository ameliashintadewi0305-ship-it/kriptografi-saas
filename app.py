import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from base64 import b64encode, b64decode
import traceback

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
db_path = os.environ.get('DATABASE_PATH', '/data/site.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    private_key = db.Column(db.Text, nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encrypted_message = db.Column(db.Text, nullable=False)
    signature = db.Column(db.Text, nullable=False)
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref='received_messages')

def create_keys():
    key = RSA.generate(2048)
    private_key = key.export_key().decode('utf-8')
    public_key = key.publickey().export_key().decode('utf-8')
    return private_key, public_key

def encrypt_message(message, public_key):
    recipient_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(recipient_key)
    encrypted_message = cipher.encrypt(message.encode('utf-8'))
    return b64encode(encrypted_message).decode('utf-8')

def decrypt_message(encrypted_message, private_key):
    try:
        private_key_obj = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(private_key_obj)
        decrypted_message = cipher.decrypt(b64decode(encrypted_message))
        return decrypted_message.decode('utf-8')
    except Exception as e:
        print(f"Decryption error: {e}")
        traceback.print_exc()
        return "Failed to decrypt message."

def sign_message(message, private_key):
    key = RSA.import_key(private_key)
    h = SHA256.new(message.encode('utf-8'))
    signature = pkcs1_15.new(key).sign(h)
    return b64encode(signature).decode('utf-8')

@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(int(user_id))

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

            private_key, public_key = create_keys()
            
            new_user = User(username=username, public_key=public_key, private_key=private_key)
            new_user.set_password(password)

            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! You can now log in.')
            return redirect(url_for('login'))
        except Exception as e:
            print(f"Error during registration: {e}")
            traceback.print_exc()
            db.session.rollback()
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

@app.route('/dashboard')
@login_required
def dashboard():
    users = db.session.query(User).filter(User.id != current_user.id).all()
    return render_template('dashboard.html', users=users)

@app.route('/chat/<recipient_id>', methods=['GET', 'POST'])
@login_required
def chat(recipient_id):
    recipient = db.session.query(User).get_or_404(recipient_id)
    sent_messages = db.session.query(Message).filter_by(sender_id=current_user.id, recipient_id=recipient.id).all()
    received_messages = db.session.query(Message).filter_by(sender_id=recipient.id, recipient_id=current_user.id).all()
    
    all_messages = sorted(sent_messages + received_messages, key=lambda msg: msg.id)

    if request.method == 'POST':
        message_text = request.form.get('message')
        public_key_recipient = recipient.public_key
        
        try:
            encrypted_message_text = encrypt_message(message_text, public_key_recipient)
            signature = sign_message(message_text, current_user.private_key)
            
            new_message = Message(sender_id=current_user.id, recipient_id=recipient.id, encrypted_message=encrypted_message_text, signature=signature)
            db.session.add(new_message)
            db.session.commit()
            return redirect(url_for('chat', recipient_id=recipient.id))
        except Exception as e:
            print(f"Encryption/Signature Error: {e}")
            traceback.print_exc()
            db.session.rollback()
            flash("Failed to send message.")
            return redirect(url_for('chat', recipient_id=recipient.id))

    return render_template('chat.html', recipient=recipient, messages=all_messages, decrypt_message=decrypt_message)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)