FROM python:3.8-slim-buster

COPY . /app

RUN sed -i 's/deb.debian.org/archive.debian.org/g' /etc/apt/sources.list && \
    sed -i '/security.debian.org/d' /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends graphviz && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /storage
RUN pip install /app
ENV PMAPPER_STORAGE /storage

CMD ["sh"]
