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
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 https://github.com/sullo/nikto.git /nikto \
    && chmod +x /nikto/program/nikto.pl \
    && ln -s /nikto/program/nikto.pl /usr/local/bin/nikto \
    && ln -s /nikto/program /nikto/latest

ENV PATH="/nikto/program:${PATH}"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY run.py .
COPY SecOpsConfig.json .
COPY alembic.ini .
COPY alembic/ ./alembic/
COPY resources/ ./resources/

RUN mkdir -p /app/data/sentinel/output /app/data/aegis/output /app/data/aegis/stack /app/temp /app/logs

EXPOSE 5000

CMD ["python", "run.py"]
