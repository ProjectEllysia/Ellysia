"""
scribe.catalog
──────────────
Qué modelos puede usar este despliegue, preguntándoselo a los proveedores.

Existe para que el panel de configuración ofrezca un desplegable con los
modelos que de verdad hay disponibles, en vez de un campo de texto en el que
hay que escribir ``gpt-4.1-2025-04-14`` sin equivocarse. Un identificador mal
escrito no falla al guardar: falla más tarde, dentro de un job de fondo, y lo
único que ve el usuario es que el informe no se generó.

La consulta se hace por estrategia y **cada una falla por su cuenta**: que
OpenAI esté caído o sin credenciales no es motivo para no poder elegir modelo
de Ollama, así que un proveedor inalcanzable devuelve su error en su fila en
lugar de romper la respuesta entera.
"""

from __future__ import annotations

import logging

import src.modules.system.config_reading as CR

from .strategies import ModelStrategy

logger = logging.getLogger(__name__)


def strategy_catalog() -> list[dict]:
    """Una fila por estrategia registrada, con su modelo elegido y su catálogo.

    Returns:
        Lista de diccionarios con las claves ``strategy`` (el nombre del
        proveedor), ``configuredModel`` (lo que hoy dice
        ``tools.scribe.strategies.<proveedor>.model``, vacío si se delega en
        el ``.env``), ``models`` (lo que el proveedor sirve ahora mismo),
        ``isReachable`` y ``error``.
    """
    scribe = CR.scribe_config()
    catalog = []

    for strategy_name in ModelStrategy.registered_names():
        row = {
            "strategy": strategy_name,
            "configuredModel": scribe.options_for(strategy_name).get("model") or "",
            "models": [],
            "isReachable": False,
            "error": "",
        }
        try:
            row["models"] = ModelStrategy.resolve_class(strategy_name).available_models()
            row["isReachable"] = True
        except Exception as exc:  # noqa: BLE001 — se reporta, no se propaga
            # Falta de credenciales, servidor apagado, versión de librería que
            # no trae el listado: todo se ve igual desde aquí y todo tiene la
            # misma respuesta útil, que es decírselo al usuario en su fila.
            logger.info("[scribe/catalog] %s no responde: %s", strategy_name, exc)
            row["error"] = str(exc)

        catalog.append(row)

    return catalog
