FROM python:3.10-slim

WORKDIR /app

COPY exporter.py /app/async-exporter.py

RUN pip3 install asyncio requests prometheus_client aiohttp
SHELL ["/bin/bash", "-c"]

# Устанавливаем timezone
ENV TZ="Europe/Moscow"

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && \
    echo $TZ > /etc/timezone

CMD ["python3", "/app/async-exporter.py"]

