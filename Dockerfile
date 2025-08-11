FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# Membuat direktori /data dan memberikan izin tulis universal
RUN mkdir -p /data && chmod -R 777 /data

# Membuat skrip startup menjadi executable
COPY wrapper.sh .
RUN chmod +x wrapper.sh

EXPOSE 5000

# Perintah startup menggunakan skrip wrapper
CMD ["./wrapper.sh"]
