"""
scribe.tools
────────────
Herramientas de function calling reutilizables por el generador.

La única herramienta de uso general es ``web_search`` (DuckDuckGo). Se expone
tanto la implementación (``web_search``) como su definición en formato OpenAI
(``WEB_SEARCH_TOOL``), compartido por todas las estrategias.
"""

import logging

logger = logging.getLogger(__name__)


WEB_SEARCH_TOOL: dict = {
    "type": "function",
    "function": {
        "name": "web_search",
        "description": "Busca información actualizada sobre vulnerabilidades, CVEs o guías de seguridad.",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Términos de búsqueda"}
            },
            "required": ["query"],
        },
    },
}


def web_search(query: str, max_results: int = 5) -> str:
    """
    Realiza una búsqueda web con DuckDuckGo.

    Devuelve los resultados formateados (título, extracto y URL). Ante cualquier
    fallo devuelve un mensaje de error en texto, nunca lanza, para no romper el
    bucle de tool-calling.

    Args:
        query: Cadena de búsqueda.
        max_results: Número máximo de resultados (por defecto 5).

    Returns:
        Resultados formateados o un mensaje de error/sin resultados.
    """
    from ddgs import DDGS

    try:
        with DDGS() as ddgs:
            results = list(ddgs.text(query, max_results=max_results))
        if not results:
            return f"[BÚSQUEDA] Sin resultados para: {query}"
        lines = [f"### Resultados de búsqueda: '{query}'\n"]
        for i, r in enumerate(results, 1):
            lines.append(
                f"{i}. **{r.get('title', 'Sin título')}**\n"
                f"   {r.get('body', '')[:200]}\n"
                f"   URL: {r.get('href', '')}\n"
            )
        return "\n".join(lines)
    except Exception as exc:
        logger.error("Error búsqueda web: %s", exc, exc_info=True)
        return f"[ERROR BÚSQUEDA] {exc}"
