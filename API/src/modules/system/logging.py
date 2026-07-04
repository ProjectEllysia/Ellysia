"""
system/logging.py — Configuración central del logging de Ellysia.

Convención (estilo stdlib):
    * Los handlers se configuran UNA sola vez al arrancar cada proceso
      (API y worker) mediante ``configure_logging()``.
    * En cada módulo se obtiene el logger con
      ``logger = logging.getLogger(__name__)``; el nombre jerárquico
      (``src.modules.<modulo>...``) aparece en cada línea gracias a
      ``%(name)s`` en el formato.

No instanciar loggers con handlers propios por su cuenta: todo cuelga del
root logger configurado aquí.
"""

import logging

from pathlib import Path


# Formato humano legible. Incluye %(name)s para saber qué módulo emite la línea.
_LOG_FORMAT = "[+] [%(levelname)s] (%(asctime)s) %(name)s: %(message)s"

# Librerías de terceros demasiado verbosas: se bajan a WARNING para no ahogar
# los logs propios de la aplicación.
_NOISY_LOGGERS = (
    "ddgs", "curl_cffi", "httpx", "httpcore", "h2", "hyper",
    "redis", "rq", "rq.scheduler",
)

# Guard de idempotencia: evita duplicar handlers si se llama más de una vez.
_configured = False


def configure_logging(level: int | None = None) -> None:
    """
    Configura el root logger del proceso (idempotente).

    Instala un handler de consola y otro de fichero (``secops.log``) con un
    formato común, fija el nivel global y silencia los loggers ruidosos de
    terceros. Debe llamarse una vez al arrancar la API (``create_app``) y el
    worker de tareas.

    Args:
        level: Nivel explícito. Si es ``None`` se usa ``DEBUG`` en desarrollo
               e ``INFO`` en el resto de entornos.
    """
    global _configured

    import src.modules.system.config_reading as CR

    if level is None:
        level = logging.DEBUG if CR.is_development() else logging.INFO

    root = logging.getLogger()
    root.setLevel(level)

    if not _configured:
        formatter = logging.Formatter(_LOG_FORMAT)

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        root.addHandler(console_handler)

        log_dir = Path(CR.get_directory_of(CR.DirectoryType.LOG)).resolve()
        log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_dir / "secops.log")
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)

        _configured = True

    for noisy in _NOISY_LOGGERS:
        logging.getLogger(noisy).setLevel(logging.WARNING)


