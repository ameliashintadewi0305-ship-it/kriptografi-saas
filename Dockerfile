# Gunakan image Python 3.13 versi slim
FROM python:3.13-slim

# Atur direktori kerja di dalam container
WORKDIR /app

# Salin file requirements.txt dan install dependensi
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Salin semua file kode aplikasi (termasuk folder templates dan static)
COPY . .

# Beri tahu Docker bahwa container akan mendengarkan di port 5000
EXPOSE 5000

# Jalankan aplikasi Anda
CMD ["python", "app.py"]