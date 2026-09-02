"""
AI Writers for security scan analysis.

This module provides AI-powered analysis classes for different scan types:
- NmapAIWriter: Analyzes Nmap network scans
- NiktoAIWriter: Analyzes Nikto web vulnerability scans
- LybraAIWriter: Analyzes Lybra engine findings (already structured by the
  engine itself — cve_ids/cvss/epss/qod/confirmed — so unlike the other
  writers it does not need a text-heuristic "bucket into security controls"
  preprocessing step; also used for Nuclei scans, whose findings share the
  same shape)

Each writer delegates model calling to a scribe ``AIGenerator`` (Ollama or
OpenAI strategy, chosen per module in SecOpsConfig.json) to produce security
analysis, recommendations, and risk assessments based on scan data.
"""

import json
import re

from typing import Dict, Optional

import src.modules.system.config_reading as CR
from src.modules.tools.scribe import AIInput, AIGenerator, build_generator, WEB_SEARCH_TOOL

from ..lybra.grouping import build_service_rollup
from ..model import NmapScan, NiktoScan, LybraScan


# Escala de riesgo de menor a mayor, compartida por los tres writers para
# validar el nivel devuelto y aplicar techos (LAN en Nmap).
_RISK_ORDER = ["INFORMATIVO", "BAJO", "MEDIO", "ALTO", "CRÍTICO"]


class NmapAIWriter:
    """AI writer for Nmap scan security analysis.

    Generates security analysis and recommendations for Nmap network scans.
    Provides objective evaluation of attack surfaces, distinguishing between
    exposed services and confirmed vulnerabilities. Model calling is delegated
    to an injected ``AIGenerator`` (scribe).

    The system prompt enforces strict principles:
    - Open port ≠ Vulnerability
    - Prefer underestimation to overestimation
    - Never invent CVEs or assume missing authentication

    Attributes:
        _generator: scribe AIGenerator used for model calling.
    """

    # Tope de puertos detallados que viajan al prompt (#118): un host con
    # cientos de puertos abiertos (mala configuración, o un rango escaneado
    # como si fuera un solo host) podía generar un 'ports_json' sin límite.
    # '{{total_ports}}' sigue reportando el recuento real (no el recortado),
    # así que el modelo nunca lee "hay menos puertos de los que realmente hay".
    _MAX_PORTS = 60

    def __init__(self, generator: Optional[AIGenerator] = None) -> None:
        """Initialize Nmap AI writer.

        Args:
            generator: Optional scribe AIGenerator. If not provided, one is
                built for the 'themis' module via ``build_generator``.
        """
        self._generator = generator or build_generator("themis")

    def _classify_network_context(self, target: str) -> dict:
        """Classify target as private LAN or public network deterministically.

        Args:
            target: IP address or hostname string.

        Returns:
            Dictionary with keys:
                - is_private (bool): True if target is a private/LAN address.
                - network_type (str): Human-readable label ("LAN privada" | "Red pública").
                - max_risk_level (str): Hard ceiling for risk_level ("MEDIO" | "CRÍTICO").
                - context_note (str): One-line explanation to inject into the prompt.
        """
        import ipaddress
        try:
            addr = ipaddress.ip_address(target.strip())
            is_private = addr.is_private or addr.is_loopback or addr.is_link_local
        except ValueError:
            lower = target.lower()
            is_private = any(lower.endswith(suffix) for suffix in (
                ".local", ".lan", ".internal", ".intranet", ".corp", ".home"
            )) or lower in ("localhost",)

        if is_private:
            return {
                "is_private":    True,
                "network_type":  "LAN privada",
                "max_risk_level": "MEDIO",
                "context_note":  (
                    "CONTEXTO DE RED CONFIRMADO: El target es una IP privada (LAN). "
                    "El host NO está expuesto a internet. "
                    "risk_level máximo permitido = MEDIO. "
                    "SSH, HTTP y DNS en LAN son servicios estándar: riesgo BAJO salvo anomalía confirmada."
                ),
            }
        return {
            "is_private":    False,
            "network_type":  "Red pública",
            "max_risk_level": "CRÍTICO",
            "context_note":  "CONTEXTO DE RED CONFIRMADO: El target es una IP o dominio público.",
        }

    def _build_system_prompt(self) -> str:
        """Build the system prompt defining analyst persona and principles."""
        prompts_config = CR.get_prompts_config()
        return prompts_config.get("nmap", {}).get("system", "")

    def _build_user_prompt(self, scan_data: dict, open_ports: list, network_ctx: dict) -> str:
        """Build the user prompt with scan data, port analysis and network context."""
        target = scan_data.get("target", "desconocido")
        started = scan_data.get("started_at", "N/A")

        analysis_context = self._analyze_port_patterns(open_ports)

        ports_info = []
        for open_port in open_ports:
            port_num = open_port.get("port", {}).get("port", "N/A")
            protocol = open_port.get("port", {}).get("protocol", "tcp")
            service = open_port.get("given_use", "unknown")
            product = open_port.get("product", "")
            version = open_port.get("version", "")

            port_type = "sistema" if isinstance(port_num, int) and port_num < 1024 else "usuario"

            ports_info.append({
                "puerto": f"{port_num}/{protocol}",
                "servicio": service,
                "implementacion": f"{product} {version}".strip() if (product or version) else "No identificada",
                "tipo_puerto": port_type,
                "categoria_funcional": self._infer_functional_category(service, port_num)
            })

        total_ports = len(ports_info)
        ports_info = ports_info[:self._MAX_PORTS]

        prompts_config = CR.get_prompts_config()
        template = prompts_config.get("nmap", {}).get("userTemplate", "")

        context_header = (
            f"[DATO VERIFICADO — NO MODIFICAR]\n"
            f"{network_ctx['context_note']}\n"
            f"[FIN DATO VERIFICADO]\n\n"
        )

        rendered = template.replace("{{target}}", str(target)) \
                        .replace("{{started}}", str(started)) \
                        .replace("{{total_ports}}", str(total_ports)) \
                        .replace("{{distribution}}", str(analysis_context["distribution"])) \
                        .replace("{{profile_type}}", str(analysis_context["profile_type"])) \
                        .replace("{{ports_json}}", json.dumps(ports_info, indent=2, ensure_ascii=False))

        return context_header + rendered

    def _analyze_port_patterns(self, open_ports: list) -> dict:
        """Analyze port patterns to infer system context."""
        if not open_ports:
            return {"distribution": "ninguno", "profile_type": "Host sin servicios detectados"}

        ports = []
        for open_port in open_ports:
            port_number = open_port.get("port", {}).get("port", 0)
            if isinstance(port_number, int):
                ports.append(port_number)

        priviliged = sum(1 for port in ports if port < 1024)
        userland = sum(1 for port in ports if port >= 1024)
        web_like = any(port in [80, 443, 8080, 8443] for port in ports)
        admin_like = any(port in [22, 23, 3389, 5900] for port in ports)

        if priviliged >= 3 and userland <= 2:
            profile = "Servidor de infraestructura (mix privilegiado estándar)"
        elif web_like and admin_like:
            profile = "Servidor web con gestión remota"
        elif userland > priviliged:
            profile = "Aplicación/Servicio específico (puertos dinámicos predominantes)"
        elif priviliged == 1 and not userland:
            profile = "Servicio único dedicado"
        else:
            profile = "Configuración híbrida estándar"

        return {
            "distribution": f"{priviliged} sistema / {userland} aplicación",
            "profile_type": profile
        }

    def _infer_functional_category(self, service_name: str, port: int) -> str:
        """Infer functional category based on service behavior."""
        service = str(service_name).lower()

        if any(x in service for x in ['ssh', 'telnet', 'rdp', 'vnc', 'shell']):
            return "acceso_remoto"
        elif any(x in service for x in ['http', 'www', 'web', 'proxy']):
            return "web_api"
        elif any(x in service for x in ['dns', 'domain', 'dhcp', 'ntp', 'ldap']):
            return "servicio_red"
        elif any(x in service for x in ['sql', 'db', 'mongo', 'redis', 'postgres', 'mysql']):
            return "almacenamiento_datos"
        elif port in [111, 2049, 445, 139, 21]:
            return "comparticion_archivos"
        else:
            return "servicio_especifico"

    def generate(self, scan: NmapScan) -> dict:
        """Generate AI security analysis for an Nmap scan."""
        scan_data = {
            "target": scan.target,
            "started_at": scan.started_at.isoformat() if getattr(scan, 'started_at', None) else "N/A",
            "finished_at": scan.finished_at.isoformat() if getattr(scan, 'finished_at', None) else "N/A",
            "status": getattr(scan, 'status', 'unknown'),
        }

        network_ctx = self._classify_network_context(str(scan.target))

        open_ports = []
        for relation in (getattr(scan, 'open_ports_relation', None) or []):
            port_obj = getattr(relation, "port", None)
            open_ports.append({
                "port": {
                    "port": getattr(port_obj, "port", "N/A") if port_obj else "N/A",
                    "protocol": getattr(port_obj, "protocol", "") if port_obj else "",
                },
                "given_use": getattr(relation, "given_use", ""),
                "product": getattr(relation, "product", ""),
                "version": getattr(relation, "version", ""),
                "reason": getattr(relation, "reason", ""),
            })

        prompt = self._build_user_prompt(scan_data, open_ports, network_ctx)

        ai_input = AIInput(
            system_prompt = self._build_system_prompt(),
            user_prompt   = prompt,
            tools         = [WEB_SEARCH_TOOL],
            num_predict   = 4096,
            temperature   = 0.15,
            top_p         = 0.8,
            repeat_penalty = 1.2,
        )

        result = self._generator.digest(ai_input)
        return self._validate(result.parse_json(), network_ctx=network_ctx)

    def _validate(self, result: dict, network_ctx: Optional[dict] = None) -> dict:
        """Aplica al JSON ya parseado las reglas de dominio de Nmap.

        El parseo (incluida la detección de truncado por límite de tokens) lo
        hace ``AIResult.parse_json``. Aquí sólo queda lo que es propio de este
        writer: saneado de ``cve_refs``, nivel de riesgo válido y el techo de
        riesgo de LAN, que antes se saltaba en cuanto la respuesta llegaba
        envuelta en markdown y caía por la rama de recuperación.
        """
        if isinstance(result.get("recommendations"), list):
            for rec in result["recommendations"]:
                if not isinstance(rec.get("cve_refs"), list):
                    rec["cve_refs"] = []
                else:
                    rec["cve_refs"] = [
                        cve for cve in rec["cve_refs"]
                        if isinstance(cve, str) and re.match(r'^CVE-\d{4}-\d{4,}$', cve)
                    ]

        risk_level = result.get("risk_level")
        if risk_level is None or not isinstance(risk_level, str) or risk_level.upper() not in _RISK_ORDER:
            result["risk_level"] = "INFORMATIVO"

        if network_ctx:
            cap = network_ctx.get("max_risk_level", "CRÍTICO").upper()
            if _RISK_ORDER.index(result["risk_level"].upper()) > _RISK_ORDER.index(cap):
                result["risk_level"] = cap

        return result


class NiktoAIWriter:
    """AI writer for Nikto scan security analysis.

    Generates security analysis for Nikto web vulnerability scans. Analyzes
    aggregated findings grouped by security controls rather than individual
    incidents, providing calibrated risk assessments. Model calling is
    delegated to an injected ``AIGenerator`` (scribe).

    The system prompt enforces:
    - Controls over counts (one misconfigured control = one issue)
    - Never escalate risk based on number of findings
    - Distinguish between placeholder SSL certs and real invalid certs

    Attributes:
        _generator: scribe AIGenerator used for model calling.
    """

    def __init__(self, generator: Optional[AIGenerator] = None) -> None:
        """Initialize Nikto AI writer."""
        self._generator = generator or build_generator("themis")

    def _preprocess_incidents(self, incidents: list) -> dict:
        """Preprocess incidents by grouping them into security controls."""
        if not incidents:
            return {"error": "No incidents"}

        controls = {
            "transport_security": [],
            "session_management": [],
            "information_disclosure": [],
            "client_protection": [],
            "access_control": [],
            "configuration": [],
            "noise": []
        }

        for incident in incidents:
            desc = str(incident.get("description", "")).lower()
            url = str(incident.get("url", ""))
            method = str(incident.get("method", "GET"))
            severity = str(incident.get("severity", "INFO")).upper()

            if "hash(" in url or "0x" in url or len(url) > 200:
                controls["noise"].append(incident)
                continue

            if any(x in desc for x in ["cookie", "session", "httponly", "secure flag"]):
                controls["session_management"].append(incident)
            elif any(x in desc for x in ["certificate", "ssl", "tls", "https", "cn=", "hostname"]):
                controls["transport_security"].append(incident)
            elif any(x in desc for x in ["x-frame-options", "csp", "content-security", "clickjacking", "xss"]):
                controls["client_protection"].append(incident)
            elif any(x in desc for x in ["method", "put", "delete", "trace", "debug", "options"]):
                controls["access_control"].append(incident)
            elif any(x in desc for x in ["banner", "version", "x-powered-by", "server:", "etag", "inode"]):
                controls["information_disclosure"].append(incident)
            elif any(x in desc for x in ["robots.txt", "directory", "index of", "accessible"]):
                controls["configuration"].append(incident)
            else:
                controls["information_disclosure"].append(incident)

        total_valid = sum(len(v) for k, v in controls.items() if k != "noise")

        return {
            "controls": controls,
            "metrics": {
                "total_raw": len(incidents),
                "noise_filtered": len(controls["noise"]),
                "effective_findings": total_valid,
                "critical_controls_missing": sum(
                    1 for k, v in controls.items()
                    if k in ["transport_security", "session_management"] and len(v) > 0
                )
            }
        }

    def _build_system_prompt(self) -> str:
        prompts_config = CR.get_prompts_config()
        return prompts_config.get("nikto", {}).get("system", "")

    def _build_user_prompt(self, scan_data: dict, processed: dict) -> str:
        target = scan_data.get("target", "desconocido")
        started = scan_data.get("started_at", "N/A")
        metrics = processed.get("metrics", {})
        controls = processed.get("controls", {})

        controls_summary = {}
        for control_name, findings in controls.items():
            if control_name == "noise" or not findings:
                continue

            # Show the most severe findings first so a CRITICAL/HIGH incident
            # never gets silently dropped behind three LOW ones sharing a control.
            ranked = sorted(
                findings,
                key=lambda finding: self._severity_rank(finding.get("severity", "INFO")),
                reverse=True,
            )

            unique_issues = []
            seen = set()
            for finding in ranked[:3]:
                desc = finding.get("description", "")[:120]
                if desc in seen:
                    continue
                seen.add(desc)
                unique_issues.append(f"[{str(finding.get('severity', 'INFO')).upper()}] {desc}")

            controls_summary[control_name] = {
                "instancias_detectadas": len(findings),
                "severidad_original_nikto": sorted(
                    {str(finding.get("severity", "INFO")).upper() for finding in findings},
                    key=self._severity_rank, reverse=True
                ),
                "ejemplos_representativos": unique_issues,
                "techo_teorico": self._assess_control_severity(control_name, findings)
            }

        prompts_config = CR.get_prompts_config()
        template = prompts_config.get("nikto", {}).get("userTemplate", "")

        return template.replace("{{target}}", str(target)) \
                    .replace("{{started}}", str(started)) \
                    .replace("{{total_raw}}", str(metrics.get("total_raw", 0))) \
                    .replace("{{noise_filtered}}", str(metrics.get("noise_filtered", 0))) \
                    .replace("{{effective_findings}}", str(metrics.get("effective_findings", 0))) \
                    .replace("{{controls_json}}", json.dumps(controls_summary, indent=2, ensure_ascii=False))

    _NIKTO_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

    def _severity_rank(self, severity: str) -> int:
        """Rank Nikto's own severity label so real CRITICAL/HIGH findings surface first."""
        return self._NIKTO_SEVERITY_RANK.get(str(severity).upper(), 0)

    def _assess_control_severity(self, control_name: str, findings: list) -> str:
        """Assess the ceiling severity for a security control.

        Starts from the control's static base ceiling, then raises it to match
        the highest severity Nikto itself already assigned to a finding in that
        control (e.g. a CRITICAL '.htpasswd' disclosure must never be capped at
        BAJO just because it got bucketed under information_disclosure).
        """
        severity_map = {
            "transport_security": "ALTO",
            "session_management": "MEDIO",
            "access_control": "MEDIO",
            "client_protection": "BAJO",
            "information_disclosure": "BAJO",
            "configuration": "BAJO"
        }
        static_base = severity_map.get(control_name, "BAJO")

        nikto_to_local = {"CRITICAL": "CRÍTICO", "HIGH": "ALTO", "MEDIUM": "MEDIO", "LOW": "BAJO", "INFO": "INFORMATIVO"}
        risk_order = ["INFORMATIVO", "BAJO", "MEDIO", "ALTO", "CRÍTICO"]

        real_max = "INFORMATIVO"
        for finding in findings:
            translated = nikto_to_local.get(str(finding.get("severity", "INFO")).upper(), "INFORMATIVO")
            if risk_order.index(translated) > risk_order.index(real_max):
                real_max = translated

        return real_max if risk_order.index(real_max) > risk_order.index(static_base) else static_base

    def generate(self, scan: NiktoScan) -> dict:
        """Generate AI security analysis for a Nikto scan."""
        scan_data = {
            "target": scan.target,
            "started_at": scan.started_at.isoformat() if getattr(scan, 'started_at', None) else "N/A",
        }

        incidents = []
        for incident in (getattr(scan, 'incidents', None) or []):
            incidents.append({
                "osvdb_id": getattr(incident, "osvdb_id", None),
                "url": getattr(incident, "url", ""),
                "method": getattr(incident, "method", ""),
                "description": getattr(incident, "description", ""),
                "severity": getattr(incident, "severity", "INFO"),
            })

        processed = self._preprocess_incidents(incidents)

        if processed["metrics"]["effective_findings"] == 0:
            return {
                "executive_summary": "Escaneo con datos insuficientes o ruido técnico predominante. No se detectaron controles de seguridad evaluables.",
                "risk_level": "INFORMATIVO",
                "technical_analysis": "Los hallazgos del escaneo consisten principalmente en datos corruptos o falsos positivos técnicos (URLs malformadas, referencias de memoria). Se recomienda verificar la configuración del escáner.",
                "recommendations": [],
                "conclusions": "Requiere re-escaneo con configuración adecuada."
            }

        prompt = self._build_user_prompt(scan_data, processed)

        ai_input = AIInput(
            system_prompt = self._build_system_prompt(),
            user_prompt   = prompt,
            tools         = [WEB_SEARCH_TOOL],
            num_predict   = 4096,
            temperature   = 0.1,
            top_p         = 0.75,
            repeat_penalty = 1.3,
        )

        result = self._generator.digest(ai_input)
        return self._validate(result.parse_json())

    @staticmethod
    def _validate(result: dict) -> dict:
        """Aplica al JSON ya parseado las reglas de dominio de Nikto."""
        risk_level = result.get("risk_level")
        if risk_level is None or not isinstance(risk_level, str) or risk_level.upper() not in _RISK_ORDER:
            result["risk_level"] = "BAJO"

        result.setdefault("executive_summary", "Análisis completado.")
        result.setdefault("technical_analysis", "Análisis de controles de seguridad completado.")
        result.setdefault("recommendations", [])
        result.setdefault("conclusions", "Continuar monitoreo de seguridad.")

        return result


class LybraAIWriter:
    """AI writer for Lybra engine scan security analysis.

    Unlike the other writers, Lybra's own `Finding` rows already carry
    CVE ids, CVSS, EPSS, KEV membership, QoD and the confirmed/hypothesis
    distinction — the engine did that correlation, not free text needing a
    heuristic "bucket into security controls" pass. This writer's job is
    narrower: turn an already-structured, already-prioritized finding list
    into a readable executive narrative. Model calling is delegated to an
    injected ``AIGenerator`` (scribe).

    The system prompt enforces:
    - Never invent a CVE, CVSS or EPSS value beyond what is supplied
    - Weigh `confirmed=true` findings above `confirmed=false` hypotheses
    - Respect `in_kev` (actively exploited) as the strongest urgency signal

    Attributes:
        _generator: scribe AIGenerator used for model calling.
    """

    # Tope de hallazgos detallados que viajan al prompt. Se aplica al conjunto
    # completo (confirmados + KEV + cola), no solo a la cola: un scan con más
    # de _MAX_HIGHLIGHTED_FINDINGS hallazgos confirmados/KEV podía generar un
    # payload sin límite real pese a este tope, porque antes solo recortaba
    # "rest" (Issue #118). El rollup por servicio cubre igualmente los que no
    # entran, así que un host con cientos de CVEs sigue describiéndose entero.
    _MAX_HIGHLIGHTED_FINDINGS = 25
    _MAX_DESCRIPTION_CHARS = 300

    # Tope de grupos del rollup por servicio (#118): un objetivo con muchos
    # productos/puertos distintos (un rango de red, no un solo host) podía
    # generar un 'services_json' sin límite pese a que ya es una compresión
    # de los hallazgos. Ordenado por severidad (ver _build_service_rollup),
    # así que un recorte siempre descarta primero los grupos menos graves.
    _MAX_SERVICE_GROUPS = 40

    # Mismo orden que FindingsPrintingStrategy._PRIORITY_ORDER: el informe y el
    # análisis deben priorizar igual o se contradicen entre páginas.
    _PRIORITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    def __init__(self, generator: Optional[AIGenerator] = None, prompt_key: str = "lybra") -> None:
        """Initialize the writer.

        Args:
            generator:  Injected scribe generator (tests) — defaults to the
                configured one.
            prompt_key: Which entry of ``get_prompts_config()`` to read
                (``"lybra"``, ``"nuclei"``...). The writer's logic is generic
                over the source — it only reads already-structured ``Finding``
                rows (``cve_ids``, ``cvss``, ``epss``, ``confirmed``...) — so a
                second tool with the same shape (Nuclei, Fase U1) reuses this
                class instead of duplicating it, distinguished only by which
                prompt pair it reads.
        """
        self._generator = generator or build_generator("themis")
        self._prompt_key = prompt_key

    def _build_system_prompt(self) -> str:
        prompts_config = CR.get_prompts_config()
        return prompts_config.get(self._prompt_key, {}).get("system", "")

    def _build_service_rollup(self, findings: list) -> list:
        """Resume los hallazgos por servicio afectado, en la forma que el prompt
        documenta.

        La agrupación en sí vive en la capa pura (``lybra/grouping.py``), donde
        la comparte con la respuesta de la API: estaba aquí dentro, así que el
        modelo de lenguaje recibía los hallazgos bien organizados y el usuario
        los recibía en una lista plana. Lo que queda aquí es sólo la traducción
        a las claves en castellano que el texto de sistema del prompt describe
        una por una — cambiarlas rompería el contrato con el prompt, y por eso
        no viajan desde la capa pura.
        """
        return [{
            "producto": group.label,
            "puerto": group.port,
            "servicio": group.service,
            "total_hallazgos": group.total_findings,
            "cves_en_kev": group.kev_cve_ids,
            "max_cvss": group.max_cvss,
            "max_epss": group.max_epss,
            "corregido_en": group.fixed_version,
            "confirmados": group.confirmed_count,
            "por_prioridad": group.by_priority,
            "total_cves": group.total_cves,
        } for group in build_service_rollup(findings, max_groups=self._MAX_SERVICE_GROUPS)]

    def _sort_key(self, finding: dict) -> tuple:
        """Mismo criterio de orden que las fichas del PDF (findings.py)."""
        return (
            self._PRIORITY_ORDER.get(finding.get("priority", "INFO"), 5),
            not finding.get("confirmed"),
            -(finding.get("cvss_score") or 0),
            -(finding.get("epss_score") or 0),
        )

    def _build_user_prompt(self, scan_data: dict, findings: list) -> str:
        target = scan_data.get("target", "desconocido")
        started = scan_data.get("started_at", "N/A")
        exposure = scan_data.get("exposure", "unknown")

        # Confirmados y KEV se priorizan siempre por delante de la cola, y se
        # deduplican por identidad antes de ordenar: un hallazgo puede ser
        # confirmado Y estar en KEV a la vez, y una concatenación ingenua lo
        # metía dos veces. Se ordenan por prioridad real (no por orden de
        # repositorio) para que, al recortar, sobrevivan los más graves —
        # y se recortan igual que la cola: antes solo _rest_ tenía tope, así
        # que un scan con más de _MAX_HIGHLIGHTED_FINDINGS confirmados/KEV
        # generaba un payload sin límite real pese a la constante (#118).
        priority = list({id(finding): finding for finding in findings
                          if finding.get("confirmed") or finding.get("in_kev")}.values())
        priority.sort(key=self._sort_key)

        priority_ids = {id(finding) for finding in priority}
        rest = sorted(
            (finding for finding in findings if id(finding) not in priority_ids),
            key=self._sort_key,
        )
        highlighted = (priority + rest)[:self._MAX_HIGHLIGHTED_FINDINGS]

        findings_for_ai = [{
            "titulo": finding.get("title", "")[:160],
            "categoria": finding.get("category", ""),
            "puerto": finding.get("port"),
            "servicio": finding.get("service"),
            "prioridad": finding.get("priority"),
            "cve_ids": finding.get("cve_ids") or [],
            "cvss": finding.get("cvss_score"),
            "epss": finding.get("epss_score"),
            "en_kev": bool(finding.get("in_kev")),
            "confirmado": bool(finding.get("confirmed")),
            "qod": finding.get("qod"),
            "estado": finding.get("state", "open"),
            "corregido_en": finding.get("fixed_version"),
            "descripcion": (finding.get("description") or "")[:self._MAX_DESCRIPTION_CHARS],
            "requiere_so": finding.get("required_os"),
        } for finding in highlighted]

        prompts_config = CR.get_prompts_config()
        template = prompts_config.get(self._prompt_key, {}).get("userTemplate", "")

        return template.replace("{{target}}", str(target)) \
                    .replace("{{started}}", str(started)) \
                    .replace("{{exposure}}", str(exposure)) \
                    .replace("{{total_findings}}", str(len(findings))) \
                    .replace("{{confirmed_count}}", str(sum(1 for finding in findings if finding.get("confirmed")))) \
                    .replace("{{kev_count}}", str(sum(1 for finding in findings if finding.get("in_kev")))) \
                    .replace("{{services_json}}", json.dumps(self._build_service_rollup(findings), indent=2, ensure_ascii=False)) \
                    .replace("{{findings_json}}", json.dumps(findings_for_ai, indent=2, ensure_ascii=False))

    def generate(self, scan, findings: Optional[list] = None) -> dict:
        """Generate AI security analysis for a Lybra or Nuclei scan.

        Args:
            scan: The ``LybraScan`` or ``NucleiScan`` being reported on.
            findings: Los hallazgos ya enriquecidos y priorizados por
                ``FindingsPrintingStrategy.append_body`` — la misma lista que
                imprime las fichas del PDF, con ``priority``, ``description`` y
                ``fixed_version`` ya resueltos. Pasarla evita repetir la consulta
                y, sobre todo, es lo que permite que el análisis cite la versión
                destino concreta en vez de "actualizar a la última versión".
                Si no se pasa, se consultan los hallazgos aquí (sin el contexto
                de CVE del informe, que es cosa de la capa de impresión).

        ``LybraEngineManager.exposure_for`` is reused as-is: it reads only
        ``scan.target`` and an optional ``asset_id`` (absent on ``NucleiScan``,
        so it degrades to the plain ``classify_exposure`` path), so it works for
        either scan type without a Nuclei-specific branch.
        """
        from src.modules.infrastructure.session import build_repository
        from ..repositories import ScanRepository
        from src.modules.features.themis.lybra import score_finding
        # Diferido como el resto de imports de esta función: `managers` importa
        # `services`, así que a nivel de módulo sería un ciclo.
        from ..managers.lybra import LybraEngineManager

        exposure = LybraEngineManager.exposure_for(scan)
        scan_data = {
            "target": scan.target,
            "started_at": scan.started_at.isoformat() if getattr(scan, 'started_at', None) else "N/A",
            "exposure": exposure,
        }

        if findings is None:
            # Neither `LybraScan` nor `NucleiScan` carries an ORM relationship to
            # `Finding` (see `repositories.py`), so this mirrors how the manager/
            # report code already fetches them rather than adding one just for
            # this writer.
            rows = build_repository(ScanRepository).get_findings_by_scan(scan.id)
            findings = [{
                "title": row.title, "category": row.category, "port": row.port,
                "service": row.service, "cpe": row.cpe, "cve_ids": row.cve_ids,
                "cvss_score": row.cvss_score, "epss_score": row.epss_score, "in_kev": row.in_kev,
                "confirmed": row.confirmed, "qod": row.qod, "state": row.state,
                "required_os": row.required_os,
            } for row in rows]

        for finding in findings:
            finding.setdefault("priority", score_finding(finding, exposure))

        if not findings:
            return {
                "executive_summary": "El motor no ha producido hallazgos para este objetivo.",
                "risk_level": "INFORMATIVO",
                "technical_analysis": "Sin datos suficientes para un análisis.",
                "recommendations": [],
                "conclusions": "Continuar con monitoreo regular.",
            }

        prompt = self._build_user_prompt(scan_data, findings)

        ai_input = AIInput(
            system_prompt = self._build_system_prompt(),
            user_prompt   = prompt,
            tools         = [WEB_SEARCH_TOOL],
            num_predict   = 4096,
            temperature   = 0.1,
            top_p         = 0.75,
            repeat_penalty = 1.3,
        )

        result = self._generator.digest(ai_input)
        return self._validate(result.parse_json())

    @staticmethod
    def _validate(result: dict) -> dict:
        """Aplica al JSON ya parseado las reglas de dominio de Lybra/Nuclei."""
        risk_level = result.get("risk_level")
        if risk_level is None or not isinstance(risk_level, str) or risk_level.upper() not in _RISK_ORDER:
            result["risk_level"] = "BAJO"

        result.setdefault("executive_summary", "Análisis completado.")
        result.setdefault("technical_analysis", "Análisis de vulnerabilidades completado.")
        result.setdefault("recommendations", [])
        result.setdefault("conclusions", "Continuar con el plan de remediación.")

        return result