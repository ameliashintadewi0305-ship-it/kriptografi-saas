from app import app, db
import os

with app.app_context():
    # Coba untuk membuat tabel jika belum ada
    try:
        db.create_all()
        print("Database tables created successfully!")
    except Exception as e:
        print(f"Error creating database tables: {e}")