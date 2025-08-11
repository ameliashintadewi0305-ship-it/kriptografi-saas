FROM python:3.9-slim
WORKDIR /app

# Menginstal paket-paket yang diperlukan, termasuk Apache dan mod_wsgi
RUN apt-get update && apt-get install -y --no-install-recommends \
    apache2 \
    libapache2-mod-wsgi-py3 \
    && rm -rf /var/lib/apt/lists/*

# Menginstal dependensi Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Menyiapkan direktori database
RUN mkdir -p /data && chmod -R 777 /data

# Menyalin file aplikasi
COPY . .

# Membuat konfigurasi Apache untuk menjalankan aplikasi Flask
RUN echo "WSGIDaemonProcess app user=www-data group=www-data threads=5" >> /etc/apache2/sites-available/000-default.conf
RUN echo "WSGIScriptAlias / /app/wsgi.py" >> /etc/apache2/sites-available/000-default.conf
RUN echo "<Directory /app>" >> /etc/apache2/sites-available/000-default.conf
RUN echo "    WSGIProcessGroup app" >> /etc/apache2/sites-available/000-default.conf
RUN echo "    WSGIApplicationGroup %{GLOBAL}" >> /etc/apache2/sites-available/000-default.conf
RUN echo "    Require all granted" >> /etc/apache2/sites-available/000-default.conf
RUN echo "</Directory>" >> /etc/apache2/sites-available/000-default.conf

# Membuat file wsgi.py untuk Apache
RUN echo "import sys" > wsgi.py
RUN echo "sys.path.insert(0, '/app')" >> wsgi.py
RUN echo "from app import app as application" >> wsgi.py

# Membuka port
EXPOSE 80

# Perintah startup
CMD ["apache2ctl", "-D", "FOREGROUND"]
