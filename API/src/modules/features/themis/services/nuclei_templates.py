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

**Dónde está el árbol no se decide aquí.** La ruta efectiva la resuelve
``config_reading.NucleiConfig.templates_dir``, junto a su propiedad hermana
``templates_version`` y con la misma cadena de respaldos que el resto de ese
módulo ya usa. Este módulo no es la autoridad sobre *dónde* están las
plantillas, sino sobre *cómo se recorren y se leen*.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterator, Optional

import yaml

import src.modules.system.config_reading as CR

logger = logging.getLogger(__name__)

# Directorios del árbol que nunca contienen una plantilla ejecutable: metadatos
# de git y el directorio de workflows (que son orquestaciones de plantillas,
# no plantillas — otro lenguaje, fuera del alcance de la ingesta).
_SKIPPED_DIRECTORIES = {".git", ".github", "workflows"}

_TEMPLATE_SUFFIXES = {".yaml", ".yml"}


class NucleiTemplateStore:
    """Acceso de solo lectura al único árbol de plantillas de Themis.

    Args:
        path: Ruta al árbol. Si se omite, se pide a
            ``config_reading.nuclei_config().templates_dir``. Inyectable para que
            los tests trabajen sobre un árbol de mentira en un directorio
            temporal, sin necesitar plantillas reales instaladas.
    """

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = path if path is not None else CR.nuclei_config().templates_dir

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
        return CR.nuclei_config().templates_version

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
