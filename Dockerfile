FROM python:3.9-slim

RUN apt-get update && apt-get install -y \
    gcc \
    git \
    libffi-dev \
    libssl-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --upgrade pip && \
    pip install "setuptools<70.0.0" wheel && \
    pip install --no-cache-dir ryu eventlet==0.33.3

WORKDIR /app

COPY src/ . 

CMD ["ryu-manager", "main.py"]