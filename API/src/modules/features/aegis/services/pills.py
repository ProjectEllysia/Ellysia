"""
aegis_pills.py
─────────────
Lógica de generación de píldoras de concienciación.

Contiene:
    — Dataclasses de tránsito: AegisTipData, AegisContent, AegisAlert
    — Decoradores de resiliencia: retry_on_failure, circuit_breaker
    — AegisAlertFetcher: fetch concurrente de INCIBE y CIRCL
    — AegisAIWriter: generación de píldoras delegando en un scribe AIGenerator
"""

from __future__ import annotations

import hashlib
import html
import json
import logging
import random
import re
import threading
import time
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from enum import Enum
from functools import wraps
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

import src.modules.system.config_reading as CR
from src.modules.tools.scribe import AIInput, AIGenerator, build_generator, web_search, WEB_SEARCH_TOOL

logger = logging.getLogger(__name__)
from src.modules.features.aegis.exceptions import (
    AegisValidationError,
    AegisInsufficientContentError,
    AegisFetchError,
)

from ..model import Topic


# ============================================================================
# CONSTANTES
# ============================================================================

class SeverityLevel(str, Enum):
    CRITICA = "crítica"
    ALTA    = "alta"
    MEDIA   = "media"
    BAJA    = "baja"
    INFO    = "informativa"


class AlertSource(str, Enum):
    INCIBE = "incibe"
    CIRCL  = "circl"


MAX_BRANDS         = 5
MAX_RETRIES        = 3
RETRY_DELAY_BASE   = 1.5  # segundos, backoff exponencial

FALLBACK_BRANDS: list[str] = [
    "Microsoft", "Google", "Cisco", "Apple", "Adobe",
    "Oracle", "SAP", "VMware", "Fortinet", "Palo Alto",
    "Juniper", "IBM", "Linux", "Android", "Chrome",
]

COMPANY_SIZE_LABELS: dict[str, str] = {
    "micro":    "microempresa (menos de 10 empleados)",
    "pequeña":  "pequeña empresa (10-50 empleados)",
    "mediana":  "empresa mediana (50-250 empleados)",
}

FEW_SHOT_EXAMPLES = """
Ejemplo de output válido para tema "Phishing Empresarial":

{
    "subtitle": "No muerdas el anzuelo: Protección contra el phishing moderno",
    "intro": "El phishing representa una de las amenazas cibernéticas más persistentes y evolutivas del panorama actual de seguridad empresarial. Lo que comenzó hace décadas como correos electrónicos obvios y mal escritos se ha transformado en campañas sofisticadas de ingeniería social que explotan la psicología humana y el contexto organizacional. En entornos corporativos modernos, los atacantes han perfeccionado técnicas de suplantación que imitan con precisión alarmante a compañeros de trabajo, directivos e incluso proveedores de confianza, utilizando dominios similares y contextos conversacionales robados de brechas previas. Un solo clic en un enlace malicioso puede desencadenar una cascada de compromisos: desde el robo de credenciales corporativas hasta la instalación de ransomware que paraliza operaciones críticas, pasando por el acceso lateral a sistemas financieros y bases de datos de clientes. Las consecuencias económicas y reputacionales son devastadoras, con costes promedio que superan el millón de euros en medianas empresas. Esta píldora de concienciación profundiza en las señales de alerta sutiles que distinguen un correo legítimo de una trampa diseñada por ciberdelincuentes, proporcionando marcos prácticos de verificación y protocolos de respuesta que todo empleado debe internalizar para proteger los activos digitales de la organización.",
    "tips": [
        {
            "headline": "Verifica siempre el remitente real, no solo el nombre visible",
            "body": "Los atacantes configuran nombres de display (el nombre visible del remitente) que imitan con precisión a directivos, IT support o proveedores habituales. Sin embargo, el nombre visible no tiene ninguna validación técnica: cualquiera puede poner 'Carlos García - IT' como nombre de remitente. Para ver la dirección real, haz clic en el nombre del remitente en tu cliente de correo. Desconfía especialmente de dominios similares pero no idénticos al de tu empresa, como 'empresa-soporte.com' en lugar de 'empresa.com', o de dominios legítimos pero inusuales para ese tipo de comunicación.",
            "links": [
                {"text": "Guía de Google sobre verificación de remitentes", "url": "https://support.google.com/mail/answer/185835"}
            ]
        }
    ],
    "closing": "La prevención del phishing es responsabilidad de todos. Cuando tengas dudas sobre un correo sospechoso, contacta directamente a la persona o equipo mediante un canal alternativo antes de interactuar con el mensaje.",
    "contactEmail": "seguridad@empresa.com"
}

NOTA: El subtitle "No muerdas el anzuelo..." es creativo y diferente del tema técnico "Phishing Empresarial".

REGLA CRÍTICA: 
- Tema de entrada: "Phishing Empresarial" (técnico, genérico)
- Subtítulo generado: Debe ser creativo, atractivo y DIFERENTE al tema de entrada.
- NUNCA repitas "Phishing Empresarial" como subtitle. Transforma el concepto.
"""


# ============================================================================
# DATACLASSES DE TRÁNSITO
# ============================================================================

@dataclass(frozen=True)
class AegisTipData:
    """
    Consejo individual inmutable y validado.

    Se crea a partir de la respuesta del modelo, se valida en __post_init__
    y se descarta tras la persistencia en BD. No es un modelo ORM.
    """

    headline: str
    body:     str
    links:    list[dict] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.headline or len(self.headline) > 150:
            raise AegisValidationError("headline debe tener entre 1 y 150 caracteres", field="headline")
        for link in self.links:
            if not isinstance(link, dict) or "text" not in link or "url" not in link:
                raise AegisValidationError("cada link debe ser un dict con 'text' y 'url'", field="links")


@dataclass(frozen=True)
class AegisQuizData:
    """
    Pregunta de quiz individual inmutable y validada.

    Se crea a partir de la respuesta del modelo, se valida en __post_init__
    y se descarta tras la persistencia en BD. No es un modelo ORM. Espejo de
    AegisTipData.
    """

    prompt:        str
    options:       list[str]
    correct_index: int

    def __post_init__(self) -> None:
        if not self.prompt or len(self.prompt) > 300:
            raise AegisValidationError("prompt debe tener entre 1 y 300 caracteres", field="prompt")
        if not (2 <= len(self.options) <= 4):
            raise AegisValidationError("options debe tener entre 2 y 4 elementos", field="options")
        if not all(isinstance(opt, str) and opt for opt in self.options):
            raise AegisValidationError("cada option debe ser un string no vacío", field="options")
        if not (0 <= self.correct_index < len(self.options)):
            raise AegisValidationError(
                "correct_index debe apuntar a una opción válida",
                field="correct_index",
                value=str(self.correct_index),
            )


@dataclass
class AegisContent:
    """
    Resultado estructurado de AegisAIWriter.generate_pill().

    Actúa como DTO de salida del writer. El manager lo consume para persistir
    en BD y para escribir el archivo JSON en disco (vía to_json_dict).
    No contiene lógica de exportación de cara al usuario: eso es
    responsabilidad de los exportadores en aegis_exporters.py.
    """

    topic_id:      int
    topic_title:   str
    language:      str
    company:       str
    generated_at:  str
    topic_note:    str           = ""
    subtitle:      str           = ""
    intro:         str           = ""
    tips:          list[AegisTipData] = field(default_factory=list)
    closing:       str           = ""
    contact_email: str           = ""
    questions:     list[AegisQuizData] = field(default_factory=list)

    def to_json_dict(self, document_id: int, alerts: list[AegisAlert]) -> dict:
        """
        Serialización para el archivo .json que se guarda en disco.

        Este método existe exclusivamente para la escritura del fichero de
        archivo. No se usa para respuestas de API ni para los exportadores
        de usuario (que leen de BD a través de get_document).
        """
        return {
            "version": "2.0",
            "metadata": {
                "documentId":  document_id,
                "topicId":     self.topic_id,
                "topicTitle":  self.topic_title,
                "language":    self.language,
                "company":     self.company,
                "generatedAt": self.generated_at,
                "checksum":    self._checksum(),
            },
            "pill": {
                "subtitle":     self.subtitle,
                "intro":        self.intro,
                "tips": [
                    {
                        "position": i + 1,
                        "headline": t.headline,
                        "body":     t.body,
                        "links":    t.links,
                    }
                    for i, t in enumerate(self.tips)
                ],
                "closing":      self.closing,
                "contactEmail": self.contact_email,
                "questions": [
                    {
                        "position":     i + 1,
                        "prompt":       q.prompt,
                        "options":      q.options,
                        "correctIndex": q.correct_index,
                    }
                    for i, q in enumerate(self.questions)
                ],
            },
            "alerts": [
                {
                    "title":       a.title,
                    "description": a.description,
                    "url":         a.url,
                    "source":      a.source.value,
                    "published":   a.published,
                    "severity":    a.severity.value if isinstance(a.severity, Enum) else a.severity,
                    "brands":      a.brands,
                }
                for a in alerts
            ],
        }

    def _checksum(self) -> str:
        raw = f"{self.topic_id}{self.subtitle}{self.generated_at}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass(frozen=True)
class AegisAlert:
    """
    Alerta de vulnerabilidad validada e inmutable.

    Se crea en AegisAlertFetcher, se valida en __post_init__ y se persiste
    en AegisDocumentAlert. La inmutabilidad (frozen=True) garantiza que
    el estado no cambia durante el pipeline de persistencia.
    """

    title:       str
    description: str
    url:         str
    source:      AlertSource
    published:   str
    severity:    SeverityLevel | str = ""
    brands:      list[str]          = field(default_factory=list)

    def __post_init__(self) -> None:
        # Normalizar severidad al enum correspondiente
        if isinstance(self.severity, str) and self.severity:
            mapping = {
                "critical": SeverityLevel.CRITICA, "crítica": SeverityLevel.CRITICA,
                "high":     SeverityLevel.ALTA,    "alta":    SeverityLevel.ALTA,
                "medium":   SeverityLevel.MEDIA,   "media":   SeverityLevel.MEDIA,
                "low":      SeverityLevel.BAJA,    "baja":    SeverityLevel.BAJA,
            }
            # frozen=True impide asignación directa; usamos object.__setattr__
            object.__setattr__(self, "severity", mapping.get(self.severity.lower(), SeverityLevel.INFO))

        if not self.url.startswith(("http://", "https://")):
            raise AegisValidationError(f"URL inválida: {self.url}", field="url", value=self.url)


def retry_on_failure(max_retries: int = MAX_RETRIES, exceptions: tuple = (Exception,)):
    """Reintentos con backoff exponencial y jitter."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except exceptions:
                    if attempt == max_retries - 1:
                        raise
                    delay = RETRY_DELAY_BASE ** attempt + random.uniform(0, 0.5)
                    time.sleep(delay)
        return wrapper
    return decorator


def validate_url(url: str) -> bool:
    """Valida que una URL sea real y no un placeholder."""
    if not url or not isinstance(url, str):
        return False

    invalid_patterns = [
        "example.com", "placeholder", "link.com", "url.com",
        "sitio-web.com", "tu-sitio.com", "domain.com",
        "localhost", "herramienta-ejemplo", "recurso-ejemplo",
        "clickhere.com", "test.com", "sample.org",
    ]
    if any(p in url.lower() for p in invalid_patterns):
        return False

    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        domain = parsed.netloc.replace("www.", "")
        if "." not in domain:
            return False
        tld = domain.split(".")[-1]
        return len(tld) >= 2 and tld.isalpha()
    except Exception:
        return False


# ============================================================================
# FETCHER DE ALERTAS
# ============================================================================

class AegisAlertFetcher:
    """
    Fetch concurrente de alertas de vulnerabilidad desde INCIBE y CIRCL.

    Mantiene una caché en memoria por instancia de clase (compartida entre
    instancias del mismo proceso) con TTL de 15 minutos. Las llamadas
    externas se protegen con @retry_on_failure.
    """

    INCIBE_FEED = "https://www.incibe.es/incibe-cert/alerta-temprana/avisos/feed"

    _cache:     dict[str, tuple[list[AegisAlert], datetime]] = {}
    _cache_ttl  = timedelta(minutes=15)
    _lock       = threading.Lock()

    def __init__(self, fallback_brands: list[str] | None = None) -> None:
        self._max_alert_age_years = CR.get_aegis_vulnerabilities_antiquity()

        brand_catalogue           = CR.get_aegis_brands()
        self._brand_slugs: dict[str, tuple[str, str]] = {
            b["label"]: (b["circl_vendor"], b["circl_product"])
            for b in brand_catalogue
        }
        self._brand_aliases: dict[str, list[str]] = {
            b["label"]: [a.lower() for a in b.get("aliases", [])]
            for b in brand_catalogue
            if b.get("aliases")
        }
        catalogue_labels          = [b["label"] for b in brand_catalogue]
        self._fallback_brands     = fallback_brands or catalogue_labels or FALLBACK_BRANDS[:]

    # ── Caché ─────────────────────────────────────────────────────────────────

    def _get_cached(self, key: str) -> list[AegisAlert] | None:
        with self._lock:
            entry = self._cache.get(key)
            if entry:
                alerts, timestamp = entry
                if datetime.now() - timestamp < self._cache_ttl:
                    return alerts
                del self._cache[key]
        return None

    def _set_cached(self, key: str, alerts: list[AegisAlert]) -> None:
        with self._lock:
            self._cache[key] = (alerts, datetime.now())

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _resolve_brands(self, brands: list[str]) -> list[str]:
        """Completa la lista de marcas hasta MAX_BRANDS con fallbacks."""
        unique    = list(dict.fromkeys(b.strip() for b in brands if b.strip()))
        if len(unique) >= MAX_BRANDS:
            return unique[:MAX_BRANDS]
        available = [b for b in self._fallback_brands if b not in unique]
        padding   = random.sample(available, min(MAX_BRANDS - len(unique), len(available)))
        return unique + padding

    def _is_recent(self, date_str: str) -> bool:
        if not date_str:
            return True
        try:
            pub_date = datetime.strptime(date_str[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
            cutoff   = datetime.now(timezone.utc) - timedelta(days=365 * self._max_alert_age_years)
            return pub_date >= cutoff
        except ValueError:
            logger.warning(f"Fecha no parseable '{date_str}', asumiendo reciente")
            return True

    # ── Fuentes externas ──────────────────────────────────────────────────────

    @retry_on_failure(max_retries=3)
    def _fetch_incibe(self, brands: list[str], max_per_brand: int) -> list[AegisAlert]:
        """Fetch de alertas desde INCIBE."""
        from email.utils import parsedate_to_datetime

        cache_key = f"incibe_{','.join(sorted(brands))}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        req = urllib.request.Request(
            self.INCIBE_FEED,
            headers={"User-Agent": "AegisAlertFetcher/2.0", "Accept": "application/rss+xml"},
        )
        
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()

        root = ET.fromstring(raw)
        channel = root.find("channel")
        if channel is None:
            return []

        alerts = []
        brand_counts = {b: 0 for b in brands}

        for item in channel.findall("item"):
            title = (item.findtext("title") or "").strip()
            desc_raw = html.unescape(item.findtext("description") or "").strip()
            url = (item.findtext("link") or "").strip()
            pub = (item.findtext("pubDate") or "").strip()

            # Parseo de fecha
            pub_iso = pub[:10]
            try:
                pub_iso = parsedate_to_datetime(pub).strftime("%Y-%m-%d")
            except Exception:
                pass

            # Limpieza de descripción
            desc_text = re.sub(r"<[^>]+>", "", desc_raw).strip()
            m = re.search(r"Descripción.*?<p>(.*?)</p>", desc_raw, re.DOTALL)
            summary = html.unescape(m.group(1)) if m else desc_text[:300]

            # Detección de severidad
            haystack = (title + " " + desc_text).lower()
            severity = ""
            for keyword, level in [
                ("crítica", "crítica"), ("critical", "crítica"),
                ("alta", "alta"), ("high", "alta"),
                ("media", "media"), ("medium", "media"),
                ("baja", "baja"), ("low", "baja"),
            ]:
                if keyword in haystack:
                    severity = level
                    break

            # Matching de marcas: nombre canónico + aliases de texto libre
            matched = []
            for brand in brands:
                if brand_counts[brand] >= max_per_brand:
                    continue
                search_terms = [brand.lower()] + self._brand_aliases.get(brand, [])
                if any(term in haystack for term in search_terms):
                    matched.append(brand)
                    brand_counts[brand] += 1

            if matched:
                try:
                    alerts.append(AegisAlert(
                        title=title[:200],
                        description=summary[:500],
                        url=url[:512],
                        source=AlertSource.INCIBE,
                        published=pub_iso,
                        severity=severity,
                        brands=matched[:MAX_BRANDS],
                    ))
                except ValueError as e:
                    logger.debug(f"Alerta INCIBE inválida descartada: {e}")

        self._set_cached(cache_key, alerts)
        return alerts

    @retry_on_failure(max_retries=3)
    def _fetch_circl(self, brands: list[str], max_per_brand: int) -> list[AegisAlert]:
        """Fetch de alertas desde CIRCL/NVD."""
        cache_key = f"circl_{','.join(sorted(brands))}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        alerts = []
        brand_counts = {b: 0 for b in brands}

        for brand in brands:
            if brand_counts[brand] >= max_per_brand:
                continue

            cve_list = self._circl_fetch_cve_list(brand)
            if cve_list is None:
                continue

            sorted_entries = sorted(cve_list, key=self._circl_extract_date, reverse=True)

            for entry in sorted_entries:
                if brand_counts[brand] >= max_per_brand:
                    break

                alert = self._circl_parse_entry(entry, brand)
                if alert is not None:
                    alerts.append(alert)
                    brand_counts[brand] += 1

            time.sleep(0.2)

        self._set_cached(cache_key, alerts)
        return alerts

    def _circl_fetch_cve_list(self, brand: str) -> list | None:
        """Consulta la API de CIRCL para ``brand``; devuelve la lista ``cvelistv5``
        o None si la petición falla o la respuesta no tiene el formato esperado."""
        vendor, product = self._brand_slugs.get(brand, (brand.lower().replace(" ", ""), ""))
        url = (
            f"https://cve.circl.lu/api/search/{vendor}/{product}"
            if product else
            f"https://cve.circl.lu/api/search/{vendor}"
        )

        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "AegisAlertFetcher/2.0", "Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
        except Exception as e:
            logger.warning(f"CIRCL error para '{brand}': {e}")
            return None

        results = data.get("results", {}) if isinstance(data, dict) else {}
        cve_list = results.get("cvelistv5", []) if isinstance(results, dict) else []

        if not isinstance(cve_list, list):
            return None
        return cve_list

    @staticmethod
    def _circl_extract_date(entry) -> str:
        """Fecha de publicación de una entrada cvelistv5, usada como clave de orden."""
        try:
            if isinstance(entry, (list, tuple)) and len(entry) > 1:
                return entry[1].get("cveMetadata", {}).get("datePublished", "")
            return ""
        except Exception:
            return ""

    def _circl_parse_entry(self, entry, brand: str) -> Optional[AegisAlert]:
        """Convierte una entrada cvelistv5 de CIRCL en un AegisAlert.

        Devuelve None si la entrada está malformada, no es reciente
        (``_is_recent``), o cualquier otro filtro descarta el CVE.
        """
        try:
            if not isinstance(entry, (list, tuple)) or len(entry) < 2:
                return None

            cve_id = entry[0].upper()
            meta = entry[1]

            if not isinstance(meta, dict):
                return None

            # Extraer metadata
            cve_metadata = meta.get("cveMetadata", {})
            pub_raw = cve_metadata.get("datePublished", "")[:10]

            if not self._is_recent(pub_raw):
                return None

            containers = meta.get("containers", {})
            cna = containers.get("cna", {})
            descriptions = cna.get("descriptions", [])

            desc = next(
                (d["value"] for d in descriptions if d.get("lang", "").startswith("es")),
                next((d["value"] for d in descriptions if d.get("lang", "").startswith("en")), "")
            ) if descriptions else ""

            severity = ""
            metrics = cna.get("metrics", [])
            for metric in metrics:
                for key in ("cvssV3_1", "cvssV3_0", "cvssV3"):
                    cvss = metric.get(key, {})
                    if cvss:
                        base = cvss.get("baseSeverity", "").upper()
                        severity = {
                            "CRITICAL": "crítica", "HIGH": "alta",
                            "MEDIUM": "media", "LOW": "baja"
                        }.get(base, "")
                        break
                if severity:
                    break

            affected = cna.get("affected", [])
            product_name = affected[0].get("product", "") if affected else ""
            title = f"{cve_id}" + (f" — {product_name}" if product_name else "")

            return AegisAlert(
                title=title[:200],
                description=(desc[:400] + "…" if len(desc) > 400 else desc) if desc else f"Vulnerabilidad en {brand}",
                url=f"https://cve.circl.lu/cve/{cve_id}",
                source=AlertSource.CIRCL,
                published=pub_raw,
                severity=severity,
                brands=[brand],
            )
        except Exception as e:
            logger.debug(f"Entrada CIRCL malformada: {e}")
            return None

    def fetch_alerts(
        self,
        brands:          list[str],
        max_per_brand:   int  = 3,
        use_concurrency: bool = True,
    ) -> list[AegisAlert]:
        """
        Fetch paralelo de INCIBE y CIRCL con fallback y deduplicación.
        Devuelve como máximo 20 alertas ordenadas por fecha descendente.
        """
        if not brands and not self._fallback_brands:
            return []

        resolved = self._resolve_brands(brands)
        results: list[AegisAlert] = []

        if use_concurrency:
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = {
                    executor.submit(self._fetch_incibe, resolved, max_per_brand): "INCIBE",
                    executor.submit(self._fetch_circl,  resolved, max_per_brand): "CIRCL",
                }
                for future in as_completed(futures):
                    source_name = futures[future]
                    try:
                        results.extend(future.result())
                    except Exception as exc:
                        logger.error(f"Error fetch {source_name}: {exc}")
        else:
            for fetch_fn, name in [(self._fetch_incibe, "INCIBE"), (self._fetch_circl, "CIRCL")]:
                try:
                    results.extend(fetch_fn(resolved, max_per_brand))
                except Exception as exc:
                    logger.error(f"Error fetch {name}: {exc}")

        # Deduplicación por (título, fecha)
        seen:          set[str]         = set()
        unique_alerts: list[AegisAlert] = []
        for alert in sorted(results, key=lambda a: a.published, reverse=True):
            key = f"{alert.title}_{alert.published}"
            if key not in seen:
                seen.add(key)
                unique_alerts.append(alert)

        return unique_alerts[:20]


class AegisAIWriter:
    """
    Genera el contenido de una píldora con few-shot prompting, tool calling para
    búsqueda web y validación estructural del JSON resultante.

    La llamada al modelo se delega en un ``AIGenerator`` inyectado (estrategia
    Ollama u OpenAI según ``SecOpsConfig.json``). Si no se pasa generador, se
    construye uno para el módulo 'aegis' mediante ``build_generator``.
    """

    def __init__(self, generator: Optional[AIGenerator] = None) -> None:
        self._generator = generator or build_generator("aegis")

    # ── Prompts ───────────────────────────────────────────────────────────────

    def _build_system_prompt(self) -> str:
        prompts = CR.get_aegis_prompts()
        return prompts.get("system", "")

    def _build_intro_context(self, tweaks: dict[str, Any]) -> str:
        """
        Construye el bloque de contexto adicional a partir de los tweaks de
        empresa (tamaño, jurisdicción, modelo de trabajo, incidente reciente).

        Rellena el placeholder ``{{intro_context}}`` de userTemplate. Cada
        campo tiene un fallback razonable cuando el tweak no se especifica.
        """
        employee_count = tweaks.get("employeeCount")
        company_size_bucket = tweaks.get("companySize", "")
        if employee_count:
            company_size = f"una empresa de aproximadamente {employee_count} empleados"
        elif company_size_bucket:
            company_size = f"una {COMPANY_SIZE_LABELS.get(company_size_bucket, company_size_bucket)}"
        else:
            company_size = "una empresa de tamaño no especificado"

        jurisdiction = tweaks.get("jurisdiction", "") or "el marco legal general aplicable (RGPD si procede)"
        work_model = {
            "remoto":      "trabajo remoto",
            "híbrido":     "trabajo híbrido (presencial y remoto)",
            "presencial":  "trabajo presencial",
        }.get(tweaks.get("workModel", ""), "un modelo de trabajo mixto")

        context = (
            f"Contexto adicional de la empresa destinataria: {company_size}, "
            f"con {work_model}, sujeta a {jurisdiction}."
        )

        recent_incident = tweaks.get("recentIncident", "")
        if recent_incident:
            context += (
                f" La empresa sufrió recientemente el siguiente incidente, "
                f"que puedes usar como contexto (sin inventar detalles adicionales): "
                f"{recent_incident}"
            )

        return context

    def _build_user_prompt(
        self,
        topic:              Topic | None,
        topic_id:           int,
        reference:          str,
        tweaks:             dict[str, Any],
        verified_resources: str,
    ) -> str:
        prompts = CR.get_aegis_prompts()
        user_template = prompts.get("userTemplate", "")
        
        company  = tweaks.get("company", "la empresa")
        sector   = tweaks.get("sector", "tecnología")
        audience = tweaks.get("audienceLevel", "mixed")
        brands   = ", ".join(tweaks.get("associatedBrands", []))
        contact  = tweaks.get("mentionContact", "el equipo de seguridad")
        language = tweaks.get("language", "es")
        tone     = tweaks.get("tone", "profesional")
        focus    = tweaks.get("topicFocus", "")

        audience_profile = {
            "technical":     "técnico (administradores de sistemas, desarrolladores)",
            "mixed":         "mixto (técnicos y no técnicos)",
            "non-technical": "no técnico (ventas, RRHH, dirección)",
        }.get(str(audience), "mixto")

        topic_title = topic.title if topic else "Ciberseguridad General"
        topic_description = getattr(topic, 'description', 'No disponible') if topic else f"Genérico para sector {sector}"

        intro_context = self._build_intro_context(tweaks)

        replacements = {
            "company": company,
            "sector": sector,
            "brands": brands or "No especificadas",
            "audience": audience_profile,
            "tone": tone,
            "language": language.upper(),
            "contact": contact,
            "topic_title": topic_title,
            "topic_description": topic_description,
            "topic_id": str(topic.id) if topic else str(topic_id),
            "focus": focus,
            "verified_resources": verified_resources[:2000],
            "tips_amount": str(CR.get_aegis_tips_amount()),
            "intro_context": intro_context,
        }
        
        result = user_template
        for key, value in replacements.items():
            result = result.replace("{{" + key + "}}", value)
        
        return result

    # ── Generación ────────────────────────────────────────────────────────────

    def generate(
        self,
        *,
        topic:             Topic | None,
        resolved_topic_id: int,
        topic_title:       str,
        topic_note:        str,
        reference:         str,
        tweaks:            dict[str, Any],
    ) -> AegisContent:
        """
        Genera el contenido de la píldora delegando en el ``AIGenerator``.

        El generador encapsula el tool calling, los reintentos y el circuit
        breaker; aquí solo construimos el ``AIInput`` y validamos la salida.
        Devuelve un AegisContent validado listo para persistir.
        """
        # Enriquecimiento de contexto con búsqueda web
        search_queries = [
            f"{topic_title} ciberseguridad guía oficial {tweaks.get('language', 'es')}",
            f"{topic_title} mejores prácticas empresa {tweaks.get('sector', '')}",
            f"CVE recientes {','.join(tweaks.get('associatedBrands', [])[:2])}",
        ]
        verified_resources = ""
        for query in search_queries:
            try:
                verified_resources += f"\n{web_search(query, max_results=3)}"
            except Exception as exc:
                logger.warning(f"Búsqueda fallida '{query}': {exc}")

        prompt = self._build_user_prompt(
            topic, resolved_topic_id, reference, tweaks, verified_resources
        )

        ai_input = AIInput(
            system_prompt = self._build_system_prompt(),
            user_prompt   = prompt,
            tools         = [WEB_SEARCH_TOOL],
            num_predict   = 8192,
            temperature   = 0.4,
        )

        result = self._generator.digest(ai_input)

        data = result.parse_json()
        tips_amount = CR.get_aegis_tips_amount()
        raw_subtitle = str(data.get("subtitle", "")).strip()
        
        if not raw_subtitle or raw_subtitle.lower() == topic_title.lower():
            logger.warning(
                f"IA generó subtitle idéntico al tema '{topic_title}' o vacío. "
                f"Forzando generación creativa..."
            )
            # Transformación automática para evitar duplicados
            prefixes = [
                "Protección empresarial contra",
                "Guía práctica de",
                "Cómo prevenir",
                "Seguridad avanzada en",
                "Manual de supervivencia ante"
            ]
            prefix = random.choice(prefixes)
            raw_subtitle = f"{prefix} {topic_title}"
        
        # También validar que no sea demasiado genérico
        if len(raw_subtitle) < 10:
            raw_subtitle = f"Píldora de concienciación: {topic_title}"

        # Construcción y validación de tips
        tips: list[AegisTipData] = []
        for i, tip_data in enumerate(data.get("tips", [])):
            if not isinstance(tip_data, dict):
                continue
            valid_links = [
                {"text": str(lk["text"])[:50], "url": str(lk["url"])[:512]}
                for lk in (tip_data.get("links") or [])
                if isinstance(lk, dict) and validate_url(lk.get("url")) and lk.get("text")
            ]
            try:
                tips.append(AegisTipData(
                    headline = str(tip_data.get("headline", f"Consejo {i + 1}"))[:150],
                    body     = str(tip_data.get("body", ""))[:1000],
                    links    = valid_links[:2],
                ))
            except AegisValidationError as exc:
                logger.warning(f"Tip {i + 1} descartado: {exc}")

        # Construcción y validación del quiz
        questions: list[AegisQuizData] = []
        for i, q_data in enumerate(data.get("questions", [])):
            if not isinstance(q_data, dict):
                continue
            try:
                options = [
                    str(opt)[:200] for opt in (q_data.get("options") or [])
                    if isinstance(opt, (str, int, float))
                ][:4]
                questions.append(AegisQuizData(
                    prompt        = str(q_data.get("prompt", f"Pregunta {i + 1}"))[:300],
                    options       = options,
                    correct_index = int(q_data.get("correctIndex", 0)),
                ))
            except (AegisValidationError, ValueError, TypeError) as exc:
                logger.warning(f"Pregunta {i + 1} descartada: {exc}")

        return AegisContent(
            topic_id      = resolved_topic_id,
            topic_title   = topic_title,
            language      = tweaks.get("language", "es"),
            company       = tweaks.get("company", "la empresa"),
            generated_at  = datetime.now(timezone.utc).isoformat(),
            topic_note    = topic_note,
            subtitle      = raw_subtitle[:100],  # Título creativo garantizado
            intro         = str(data.get("intro", ""))[:2500],
            tips          = tips,
            closing       = str(data.get("closing", ""))[:500],
            contact_email = str(data.get("contactEmail", ""))[:100],
            questions     = questions,
        )