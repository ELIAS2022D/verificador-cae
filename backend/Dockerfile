FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    tesseract-ocr \
    tesseract-ocr-spa \
    libzbar0 \
    poppler-utils \
    openssl \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT}"]
