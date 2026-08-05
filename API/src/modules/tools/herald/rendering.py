"""
herald.rendering
────────────────
Capa de plantillas de los correos.

Un correo se compone renderizando ``<nombre>.html.j2`` (y, si existe, su
gemelo ``<nombre>.txt.j2`` para la alternativa en texto plano). Las plantillas
del paquete viven en ``templates/``; ``tools.herald.templatesDir`` permite
sobreescribir cualquiera de ellas desde fuera sin tocar el código — el
``ChoiceLoader`` mira primero ese directorio y cae al del paquete.

El autoescape está activo: los datos que llegan de la BD (nombres de
destinatario, títulos de píldora, hostnames) se escapan solos.
"""

from __future__ import annotations

import logging
from pathlib import Path

from jinja2 import ChoiceLoader, Environment, FileSystemLoader, TemplateNotFound

import src.modules.system.config_reading as CR

logger = logging.getLogger(__name__)

_PACKAGE_TEMPLATES = Path(__file__).parent / "templates"

#: Marca por defecto. La config solo tiene que declarar lo que quiera cambiar.
_DEFAULT_BRAND = {
    "productName": "Ellysia",
    "accentColor": "#d4a04a",
    "logoUrl": "",
    "supportEmail": "",
    "footerNote": "",
}

#: (templatesDir configurado, entorno) — se reconstruye si la config cambia.
_env_cache: tuple[str, Environment] | None = None


def _autoescape(template_name: str | None) -> bool:
    """Escapa solo el HTML. En el gemelo ``.txt.j2`` escapar sobraría: saldrían
    ``&amp;`` y ``&#39;`` literales en un correo de texto plano."""
    return bool(template_name and ".html." in template_name)


def _environment() -> Environment:
    global _env_cache  # pylint: disable=global-statement

    override_dir = CR.herald_config().templates_dir
    if _env_cache is not None and _env_cache[0] == override_dir:
        return _env_cache[1]

    search_paths = [_PACKAGE_TEMPLATES]
    if override_dir and Path(override_dir).is_dir():
        search_paths.insert(0, Path(override_dir))

    env = Environment(
        loader=ChoiceLoader([FileSystemLoader(str(search_path)) for search_path in search_paths]),
        autoescape=_autoescape,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    _env_cache = (override_dir, env)
    return env


def render_email(template: str, **context) -> tuple[str, str | None]:
    """
    Renderiza un correo.

    Args:
        template: Nombre base de la plantilla, sin extensión ('campaign').
        **context: Variables de la plantilla. ``brand`` se inyecta sola desde
            ``tools.herald.branding`` si el llamante no la pasa.

    Returns:
        ``(html, text)``. ``text`` es None si la plantilla no tiene gemelo
        ``.txt.j2`` — en ese caso la estrategia SMTP deriva el texto del HTML.
    """
    env = _environment()
    context.setdefault("brand", {**_DEFAULT_BRAND, **CR.herald_config().branding})

    html = env.get_template(f"{template}.html.j2").render(**context)

    try:
        text = env.get_template(f"{template}.txt.j2").render(**context)
    except TemplateNotFound:
        text = None

    return html, text
