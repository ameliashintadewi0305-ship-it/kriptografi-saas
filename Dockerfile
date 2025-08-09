# Gunakan image Python 3.13 versi slim
FROM python:3.13-slim

# Atur direktori kerja di dalam container
WORKDIR /app

# Salin file requirements.txt
COPY requirements.txt .

# Install semua dependensi dari requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Pastikan modul cryptography terpasang
# (Ini bisa jadi langkah yang berlebihan, tapi untuk memastikan)
RUN pip install --no-cache-dir cryptography

# Salin semua file kode aplikasi
COPY . .

# Beri tahu Docker bahwa container akan mendengarkan di port 5000
EXPOSE 5000

# Jalankan aplikasi Anda
CMD ["python", "app.py"]