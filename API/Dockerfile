FROM python:3.11-bookworm

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    traceroute \
    curl \
    git \
    perl \
    libjson-perl \
    libxml-writer-perl \
    && git clone --depth 1 https://github.com/sullo/nikto.git /nikto \
    && chmod +x /nikto/program/nikto.pl \
    && ln -s /nikto/program/nikto.pl /usr/local/bin/nikto \
    && ln -s /nikto/program /nikto/latest \
    && apt-get purge -y --auto-remove git \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/nikto/program:${PATH}"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY run.py .
COPY SecOpsConfig.json .
COPY alembic.ini .
COPY alembic/ ./alembic/
COPY resources/ ./resources/

RUN mkdir -p /app/data/themis/output /app/data/themis/csv /app/data/aegis/output /app/data/aegis/stack /app/data/iris/output /app/temp /app/logs

EXPOSE 5000

# E5: sin USER no-root — el nmap de Debian (7.93, sin libcap-ng) exige UID 0
# real para escaneos SYN pase lo que pase con las capabilities del binario
# (verificado: setcap cap_net_raw+eip + usuario no-root → "requires root
# privileges" incluso con --cap-add=NET_RAW). Bajar privilegios aquí
# rompería el escaneo Nmap en silencio; requiere una imagen de nmap con
# soporte libcap-ng (no la de Debian) antes de poder hacerlo con seguridad.
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/system/say-hello', timeout=3)" || exit 1

# ponytail: 1 worker process (gthread, 8 hilos) en vez de N workers gunicorn —
# el scheduler (APScheduler) y la reconciliación de huérfanos en create_app()
# son en memoria por proceso; con >1 worker se duplicarían. Escalar a más
# procesos exige antes un lock distribuido (Redis) para ambos.
CMD ["gunicorn", "--factory", "run:app_factory", "--bind", "0.0.0.0:5000", \
     "--workers", "1", "--threads", "8", "--timeout", "60"]
