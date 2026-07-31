"""El almacén de plantillas de Nuclei — la única copia, con acceso centralizado.

Themis tiene **un solo árbol de plantillas de Nuclei**, y este módulo es su
única autoridad. La restricción no es estética: con la Fase U1 ya entregada hay
(o habrá) tres consumidores distintos del mismo árbol, y ninguno debe clonar,
copiar ni resolver la ruta por su cuenta.

- ``NucleiScanTask`` (U1/U2) — solo necesita la ruta, para pasársela al binario
  por ``-templates``. Es el consumidor que ya existía.
- La ingesta de plantillas al ``CheckRuntime`` propio (Fase R) — necesita
  *leer* y parsear ese mismo árbol.
- El censo de ingestibilidad (Fase U4) — necesita medir sobre ese mismo árbol,
  y no sobre un clon aparte del repositorio upstream: así el número medido
  corresponde a la versión que de verdad corre en producción.

**Por qué la resolución de ruta vive aquí y no en ``config_reading``.**
``themis.nuclei.templatesDir`` admite la cadena vacía, que significa "deja que
el binario use su ubicación por defecto". Ese contrato lo entiende el binario,
pero Python no puede leer un directorio que no sabe nombrar. En cuanto hay un
consumidor que lee ficheros en vez de pasar un flag, hace falta una resolución
explícita — que es :func:`resolve_templates_dir`. ``config_reading`` sigue
siendo un lector fino de configuración; la política de "dónde están de verdad"
es de este módulo.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Iterator, Optional

import yaml

import src.modules.system.config_reading as CR

logger = logging.getLogger(__name__)

def _default_locations() -> tuple:
    """Ubicaciones por defecto de Nuclei, resueltas en el momento de llamar.

    Se calculan aquí y no en una constante de módulo a propósito: ``Path.home()``
    en una constante se congelaría en el momento de importar, y entonces ni un
    test podría simular otro ``HOME`` ni un worker heredaría un entorno distinto
    al del proceso que lo importó. En la imagen Docker esto resuelve a
    ``/root/.local/nuclei-templates``, que es donde el ``nuclei -update-templates``
    del Dockerfile las deja.
    """
    home = Path.home()
    return (home / ".local" / "nuclei-templates", home / "nuclei-templates")

# Directorios del árbol que nunca contienen una plantilla ejecutable: metadatos
# de git y el directorio de workflows (que son orquestaciones de plantillas,
# no plantillas — otro lenguaje, fuera del alcance de la ingesta).
_SKIPPED_DIRECTORIES = {".git", ".github", "workflows"}

_TEMPLATE_SUFFIXES = {".yaml", ".yml"}


def resolve_templates_dir() -> Optional[Path]:
    """Resuelve el directorio efectivo de plantillas, o ``None`` si no hay ninguno.

    Orden de prioridad, de más explícito a más implícito:

    1. ``themis.nuclei.templatesDir`` en ``SecOpsConfig.json`` (o su override
       por entorno). Es el valor que el Dockerfile fija, y el que garantiza que
       binario y lector miren al mismo sitio.
    2. La variable de entorno ``NUCLEI_TEMPLATES_DIR``, que el propio binario
       también respeta.
    3. Las ubicaciones por defecto de Nuclei (``~/.local/nuclei-templates``...).

    Returns:
        La ruta al árbol de plantillas, o ``None`` si ninguna candidata existe
        en disco. Nunca se devuelve una ruta inventada: un ``None`` explícito
        deja que el llamador decida (``NucleiScanTask`` omite ``-templates`` y
        deja que el binario use su propio criterio; un lector no puede hacer
        nada y debe decirlo).
    """
    configured = (CR.get_nuclei_templates_dir() or "").strip()
    if configured:
        path = Path(configured)
        if path.is_dir():
            return path
        # Una ruta configurada que no existe es un error de despliegue, no algo
        # que deba degradarse en silencio a otra ubicación: se avisa y se sigue
        # buscando, para no dejar un escaneo sin plantillas sin explicación.
        logger.warning(
            "themis.nuclei.templatesDir apunta a '%s', que no existe; "
            "se buscarán las ubicaciones por defecto de Nuclei", configured
        )

    from_environment = (os.environ.get("NUCLEI_TEMPLATES_DIR") or "").strip()
    if from_environment and Path(from_environment).is_dir():
        return Path(from_environment)

    for candidate in _default_locations():
        if candidate.is_dir():
            return candidate
    return None


class NucleiTemplateStore:
    """Acceso de solo lectura al único árbol de plantillas de Themis.

    Args:
        path: Ruta al árbol. Si se omite, se resuelve con
            :func:`resolve_templates_dir`. Inyectable para que los tests
            trabajen sobre un árbol de mentira en un directorio temporal, sin
            necesitar plantillas reales instaladas.
    """

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = path if path is not None else resolve_templates_dir()

    @property
    def path(self) -> Optional[Path]:
        """El directorio de plantillas, o ``None`` si no se pudo resolver."""
        return self._path

    @property
    def is_available(self) -> bool:
        """Si hay un árbol de plantillas legible en disco."""
        return self._path is not None and self._path.is_dir()

    @property
    def version(self) -> str:
        """La versión del feed de plantillas, para sellar la procedencia.

        Delega en ``config_reading``, que ya implementa la cadena de fallbacks
        (fichero horneado en build → configuración → marcador de desconocido).
        """
        return CR.get_nuclei_templates_version()

    def iter_template_paths(self) -> Iterator[Path]:
        """Itera las rutas de todas las plantillas del árbol.

        Se saltan los directorios de metadatos y de workflows
        (:data:`_SKIPPED_DIRECTORIES`) y todo fichero que no sea YAML.

        Yields:
            Cada ruta de plantilla, en orden estable (alfabético) para que dos
            ejecuciones del censo sobre el mismo árbol den el mismo resultado.
        """
        if not self.is_available:
            return
        for path in sorted(self._path.rglob("*")):
            if path.suffix.lower() not in _TEMPLATE_SUFFIXES or not path.is_file():
                continue
            if any(part in _SKIPPED_DIRECTORIES for part in path.relative_to(self._path).parts):
                continue
            yield path

    def load_template(self, path: Path) -> Optional[dict]:
        """Carga una plantilla, devolviendo ``None`` si no es utilizable.

        Tolerante a propósito: el árbol upstream tiene miles de ficheros y
        cambia a diario, así que un YAML malformado o un documento que no sea
        un mapa se registra y se salta — nunca aborta la iteración completa.

        Args:
            path: La ruta de la plantilla.

        Returns:
            El documento parseado, o ``None`` si no se pudo leer o no es un mapa.
        """
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as err:
            logger.debug("Plantilla de Nuclei ilegible en %s: %s", path, err)
            return None
        if not isinstance(document, dict):
            return None
        return document

    def iter_templates(self) -> Iterator[tuple]:
        """Itera ``(ruta, documento)`` de cada plantilla legible del árbol.

        Yields:
            Pares ``(Path, dict)``, saltando las plantillas que
            :meth:`load_template` no pudo usar.
        """
        for path in self.iter_template_paths():
            document = self.load_template(path)
            if document is not None:
                yield path, document
