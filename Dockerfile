FROM python:3.9-slim
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create a temporary app to initialize the database
COPY app.py .
RUN python -c "from app import app, db; with app.app_context(): db.create_all()"

# Final setup
COPY . .
RUN chown -R 1001:0 /app && chmod -R g+rwX /app
USER 1001
EXPOSE 5000
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--error-logfile", "-", "app:app"]