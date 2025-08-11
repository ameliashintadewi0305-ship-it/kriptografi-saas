import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# Inisialisasi aplikasi tanpa memulai server
app = Flask(__name__)
db_path = os.environ.get('DATABASE_PATH', '/data/site.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Mendefinisikan model User di sini agar db.create_all() dapat menemukannya
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

# Membuat semua tabel database
with app.app_context():
    try:
        db.create_all()
        print("Database tables created successfully.")
    except Exception as e:
        print(f"Error creating database tables: {e}")
