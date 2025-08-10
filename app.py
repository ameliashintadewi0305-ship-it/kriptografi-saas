from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.PublicKey import RSA
from base64 import b64encode, b64decode
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-is-here'
# Mengubah lokasi database ke direktori yang dapat ditulis oleh aplikasi
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////app/site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    private_key = db.Column(db.Text, nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encrypted_message = db.Column(db.Text, nullable=False)

def create_keys():
    key = RSA.generate(2048)
    private_key = key.export_key().decode('utf-8')
    public_key = key.publickey().export_key().decode('utf-8')
    return public_key, private_key

with app.app_context():
    # Pastikan direktori database ada sebelum membuat file
    db_dir = os.path.dirname(app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:////', ''))
    if not os.path.exists(db_dir):
        os.makedirs(db_dir)
    db.create_all()

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        hashed_password = generate_password_hash(password)

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))
        
        public_key, private_key = create_keys()
        
        new_user = User(username=username, password_hash=hashed_password, public_key=public_key, private_key=private_key)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('chat'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')

@app.route('/chat')
def chat():
    if 'username' not in session:
        return redirect(url_for('login'))

    users = User.query.all()
    user_private_key = User.query.filter_by(username=session['username']).first().private_key
    messages = Message.query.filter((Message.sender_id == session['user_id']) | (Message.recipient_id == session['user_id'])).all()
    
    return render_template('chat.html', users=users, username=session['username'], user_private_key=user_private_key, messages=messages)

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'username' not in session:
        return redirect(url_for('login'))

    recipient_username = request.form.get('recipient')
    message_content = request.form.get('message')

    recipient = User.query.filter_by(username=recipient_username).first()
    if not recipient:
        flash('Recipient not found.', 'danger')
        return redirect(url_for('chat'))

    sender = User.query.filter_by(username=session['username']).first()
    public_key = RSA.import_key(recipient.public_key)
    encrypted_message = public_key.encrypt(message_content.encode(), 32)[0]
    encrypted_message_b64 = b64encode(encrypted_message).decode('utf-8')

    new_message = Message(sender_id=sender.id, recipient_id=recipient.id, encrypted_message=encrypted_message_b64)
    db.session.add(new_message)
    db.session.commit()

    flash('Message sent successfully!', 'success')
    return redirect(url_for('chat'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)