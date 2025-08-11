FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# Membuat direktori data dengan izin yang benar
RUN mkdir -p /data && chown -R 1001:0 /data && chmod -R g+rwX /data

# Menjalankan skrip Python untuk membuat tabel database
RUN python init_db.py

# Mengatur user untuk menjalankan aplikasi
USER 1001
EXPOSE 5000
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--error-logfile", "-", "app:app"]