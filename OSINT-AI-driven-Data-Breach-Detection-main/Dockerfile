# Use official lightweight Python image
FROM python:3.11-slim

# Install system dependencies needed for OpenCV, Glib, etc.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libgl1-mesa-glx \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir gunicorn

# Copy all application files
COPY . .

# Expose default Flask port
EXPOSE 5000

# Start Gunicorn server binding to port 5000
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "main:app"]
