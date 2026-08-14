#!/bin/sh
# Renueva el certificado de Let's Encrypt y recarga nginx si cambió algo.
#
# Pensado para el cron del HOST, no para correr dentro de un contenedor: solo
# él tiene el docker compose a mano para invocar "run" y "exec" sobre los
# contenedores del proyecto. Un cron:
#
#   0 3 * * * cd /ruta/a/EllysiaServer && ./web/ssl/renew.sh >> /var/log/hygeia-renew.log 2>&1
#
# certbot ya trae su propio control de "todavía no toca" (no reemite si al
# certificado le quedan más de 30 días), así que ejecutarlo a diario no gasta
# cuota del rate limit de Let's Encrypt.
set -e
cd "$(dirname "$0")/../.."

docker compose --profile container run --rm certbot renew --webroot -w /var/www/certbot

# Copiar a las rutas fijas que lee nginx.conf (ellysia.crt/ellysia.key), no
# symlinks a live/: el volumen ./web/ssl se monta :ro dentro de "web" y
# certbot guarda cada renovación en un directorio nuevo (live/ -> archive/N/)
# — un symlink roto ahí sería un fallo silencioso hasta el próximo reinicio
# del contenedor.
# Nombre del LINAJE (`--cert-name`), no necesariamente un dominio cubierto por
# el certificado. Se fija al emitir para que esta ruta sea estable aunque la
# lista de `-d` cambie: en el VPS de destino el certificado cubre ellysia.es,
# www y api, pero un host sin IP fija tiene que emitir sin el apex (no puede
# resolver: un apex no admite CNAME). Con el linaje pinchado, este script no
# se entera de la diferencia. Ver el README, "SSL certificates (production)".
DOMAIN=ellysia.es
LE_LIVE="web/ssl/letsencrypt/live/$DOMAIN"
if [ -f "$LE_LIVE/fullchain.pem" ]; then
    cp "$LE_LIVE/fullchain.pem" web/ssl/ellysia.crt
    cp "$LE_LIVE/privkey.pem" web/ssl/ellysia.key
    docker compose --profile container exec web nginx -s reload
    echo "$(date -Iseconds) certificado renovado y nginx recargado"
else
    echo "$(date -Iseconds) sin cambios (certificado aún vigente)"
fi
