#!/bin/sh

# Ini adalah skrip startup untuk memastikan database sudah siap sebelum aplikasi dimulai.

# Jalankan inisialisasi database
# Pastikan nama file Python-nya sesuai dengan nama file utama Anda (app.py)
python -c 'from app import db, app; with app.app_context(): db.create_all()'

# Jalankan Gunicorn untuk aplikasi
# Gunakan 'exec' agar sinyal dari OpenShift (misal: SIGTERM) diteruskan ke Gunicorn
exec gunicorn --bind 0.0.0.0:5000 app:app
