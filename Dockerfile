FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# Membuat direktori data dan database saat build
RUN mkdir -p /data && chown -R 1001:0 /data && chmod -R g+rwX /data
RUN python -c "from app import app, db; with app.app_context(): db.create_all()"

# Mengatur user untuk menjalankan aplikasi
USER 1001
EXPOSE 5000
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--error-logfile", "-", "app:app"]