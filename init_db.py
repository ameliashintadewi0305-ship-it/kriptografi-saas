from app import app, db
import os

db_path = os.environ.get('DATABASE_PATH', '/data/site.db')
db_dir = os.path.dirname(db_path)

with app.app_context():
    if not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
    db.create_all()
    print("Database tables created successfully!")