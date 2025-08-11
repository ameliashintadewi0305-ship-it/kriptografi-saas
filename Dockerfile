FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# Membuat direktori /data dan memberikan izin tulis universal
RUN mkdir -p /data && chmod -R 777 /data

# Menjalankan skrip inisialisasi database sebelum memulai aplikasi
# Ini adalah langkah kunci untuk mengatasi error startup
RUN python db_init.py

# Mengatur user untuk menjalankan aplikasi
USER 1001
EXPOSE 5000
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--error-logfile", "-", "app:app"]
