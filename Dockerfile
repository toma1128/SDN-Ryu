FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3-ryu \
    python3-dnspython \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install scapy

WORKDIR /app

COPY src/ .

CMD ["ryu-manager", "main.py"]