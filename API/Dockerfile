FROM python:3.11-bookworm

WORKDIR /app

# Versión fijada (no "latest") para que la imagen sea reproducible — revisar
# periódicamente en https://github.com/projectdiscovery/nuclei/releases.
# Q_NUCLEI: verificar los flags de este Dockerfile contra `nuclei -h` de la
# versión fijada antes de asumir que siguen siendo correctos (roadmap Fase U1):
# `-update-templates` es el nombre largo de v3; una imagen que acabe en v2
# necesitaría ajustar solo este bloque.
ARG NUCLEI_VERSION=3.3.7

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    traceroute \
    curl \
    unzip \
    git \
    perl \
    libjson-perl \
    libxml-writer-perl \
    && git clone --depth 1 https://github.com/sullo/nikto.git /nikto \
    && chmod +x /nikto/program/nikto.pl \
    && ln -s /nikto/program/nikto.pl /usr/local/bin/nikto \
    && ln -s /nikto/program /nikto/latest \
    && curl -sL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -o /tmp/nuclei.zip \
    && unzip -q /tmp/nuclei.zip -d /usr/local/bin nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip \
    && apt-get purge -y --auto-remove git unzip \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/nikto/program:${PATH}"

# Plantillas horneadas en build (roadmap Fase U1): sin sincronización en
# tiempo de ejecución — una llamada de red a mitad de un escaneo dentro de un
# worker sería latencia y un fallo posible nuevo, así que NucleiScanTask
# siempre pasa `-duc`. Consecuencia consciente: el feed envejece hasta el
# siguiente build de esta imagen; no hay cron de refresco todavía (deuda
# documentada en el roadmap — el patrón a seguir cuando se cierre es el mismo
# que `KbSyncManager` ya tiene para la KB de Lybra). La versión resultante se
# vuelca a un fichero que `config_reading.get_nuclei_templates_version()` lee
# como fallback, para no depender solo del valor estático de SecOpsConfig.json.
RUN nuclei -update-templates -duc \
    && mkdir -p /app/resources \
    && (nuclei -version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | tail -1 > /app/resources/nuclei_templates_version.txt || true)

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
# La fábrica se declara con la sintaxis de llamada `módulo:invocable()`, no con
# el flag --factory: requirements.txt pide `gunicorn>=21.2.0` y a partir de la
# 26 ese flag ya no existe, así que cualquier build reciente moría al arrancar
# con "unrecognized arguments: --factory". La sintaxis de llamada la entienden
# todas las versiones desde la 20.1.
CMD ["gunicorn", "run:create_app()", "--bind", "0.0.0.0:5000", \
     "--workers", "1", "--threads", "8", "--timeout", "60"]
