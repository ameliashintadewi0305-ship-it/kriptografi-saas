FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Perbaikan: Membuat tabel database secara eksplisit di Dockerfile
# Ini akan memastikan tabel 'user' ada sebelum aplikasi dijalankan
RUN python -c "from app import app, db; app.app_context().push(); db.create_all();"

EXPOSE 5000

CMD ["python", "app.py"]