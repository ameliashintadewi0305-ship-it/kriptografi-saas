FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN chown -R 1001:0 /app && chmod -R g+rwX /app
USER 1001
COPY . .
EXPOSE 5000
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--error-logfile", "-", "app:app"]