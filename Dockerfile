# Base Image: Python 3.11 Slim
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000 \
    TESSERACT_PATH=/usr/bin/tesseract

# Set working directory
WORKDIR /app

# Install system dependencies: Tesseract OCR and OpenCV runtime libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    tesseract-ocr-eng \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies first for Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the full application code
COPY . .

# Expose container port (Render assigns $PORT dynamically)
EXPOSE 8000

# Start Uvicorn bound to 0.0.0.0 using Render's dynamic $PORT (fallback 8000)
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
