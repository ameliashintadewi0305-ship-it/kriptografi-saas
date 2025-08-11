FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# Membuat direktori /data dan memberikan izin tulis universal
RUN mkdir -p /data && chmod -R 777 /data

# Perintah CMD yang diperbaiki. Ini akan menjalankan skrip inisialisasi
# dan kemudian memulai gunicorn.
CMD ["/bin/sh", "-c", "python -c 'from app import db, app, User; with app.app_context(): db.create_all()' && gunicorn --bind 0.0.0.0:5000 app:app"]
