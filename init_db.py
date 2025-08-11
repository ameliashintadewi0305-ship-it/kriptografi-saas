from app import app, db
import os
# Membuat direktori /data jika belum ada
if not os.path.exists('/data'):
    os.makedirs('/data')
with app.app_context():
    try:
        db.create_all()
        print("Database tables created successfully!")
    except Exception as e:
        print(f"Error creating database tables: {e}")