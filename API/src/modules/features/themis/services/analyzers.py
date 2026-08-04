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

from typing import Optional

import src.modules.system.config_reading as CR
from src.modules.tools.scribe import AIInput, AIGenerator, build_generator, WEB_SEARCH_TOOL
from src.modules.tools.scribe.exceptions import AIResponseError

from ..model import NmapScan, NiktoScan, LybraScan


def _extract_json_with_regex(raw: str) -> Optional[dict]:
    """Best-effort JSON recovery from a model response that failed ``json.loads``.

    Tries a couple of regex patterns (a top-level ``{...}`` object and a fenced
    ```` ```json ```` block) and returns the first one that parses, or ``None``
    if none do. Shared by the AI writers' ``_parse_response`` fallback branches.
    """
    for pattern in [r'\{[\s\S]*?\}(?=\s*$)', r'```(?:json)?\s*([\s\S]*?)\s*```']:
        match = re.search(pattern, raw, re.MULTILINE)
        if match:
            try:
                json_str = match.group(1) if match.groups() else match.group()
                return json.loads(json_str)
            except json.JSONDecodeError:
                continue
    return None


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
            is_private = any(lower.endswith(s) for s in (
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
        for op in open_ports:
            port_num = op.get("port", {}).get("port", "N/A")
            protocol = op.get("port", {}).get("protocol", "tcp")
            service = op.get("given_use", "unknown")
            product = op.get("product", "")
            version = op.get("version", "")

            port_type = "sistema" if isinstance(port_num, int) and port_num < 1024 else "usuario"

            ports_info.append({
                "puerto": f"{port_num}/{protocol}",
                "servicio": service,
                "implementacion": f"{product} {version}".strip() if (product or version) else "No identificada",
                "tipo_puerto": port_type,
                "categoria_funcional": self._infer_functional_category(service, port_num)
            })

        prompts_config = CR.get_prompts_config()
        template = prompts_config.get("nmap", {}).get("userTemplate", "")

        context_header = (
            f"[DATO VERIFICADO — NO MODIFICAR]\n"
            f"{network_ctx['context_note']}\n"
            f"[FIN DATO VERIFICADO]\n\n"
        )

        rendered = template.replace("{{target}}", str(target)) \
                        .replace("{{started}}", str(started)) \
                        .replace("{{total_ports}}", str(len(ports_info))) \
                        .replace("{{distribution}}", str(analysis_context["distribution"])) \
                        .replace("{{profile_type}}", str(analysis_context["profile_type"])) \
                        .replace("{{ports_json}}", json.dumps(ports_info, indent=2, ensure_ascii=False))

        return context_header + rendered

    def _analyze_port_patterns(self, open_ports: list) -> dict:
        """Analyze port patterns to infer system context."""
        if not open_ports:
            return {"distribution": "ninguno", "profile_type": "Host sin servicios detectados"}

        ports = []
        for op in open_ports:
            p = op.get("port", {}).get("port", 0)
            if isinstance(p, int):
                ports.append(p)

        priviliged = sum(1 for p in ports if p < 1024)
        userland = sum(1 for p in ports if p >= 1024)
        web_like = any(p in [80, 443, 8080, 8443] for p in ports)
        admin_like = any(p in [22, 23, 3389, 5900] for p in ports)

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
            num_predict   = 2048,
            temperature   = 0.15,
            top_p         = 0.8,
            repeat_penalty = 1.2,
        )

        result = self._generator.digest(ai_input)
        return self._parse_response(result.text, network_ctx=network_ctx)

    def _parse_response(self, raw: str, attempt: int = 0, network_ctx: Optional[dict] = None) -> dict:
        """Parseo robusto de la respuesta JSON con validación de integridad."""
        if not raw:
            raise AIResponseError("Respuesta vacía del modelo", attempt=attempt)

        _RISK_ORDER = ["INFORMATIVO", "BAJO", "MEDIO", "ALTO", "CRÍTICO"]

        try:
            result = json.loads(raw)

            if isinstance(result.get("recommendations"), list):
                for rec in result["recommendations"]:
                    if not isinstance(rec.get("cve_refs"), list):
                        rec["cve_refs"] = []
                    else:
                        rec["cve_refs"] = [
                            cve for cve in rec["cve_refs"]
                            if isinstance(cve, str) and re.match(r'^CVE-\d{4}-\d{4,}$', cve)
                        ]

            valid_levels = ["CRÍTICO", "ALTO", "MEDIO", "BAJO", "INFORMATIVO"]
            risk_level = result.get("risk_level")
            if risk_level is None or not isinstance(risk_level, str) or risk_level.upper() not in valid_levels:
                result["risk_level"] = "INFORMATIVO"

            if network_ctx:
                cap = network_ctx.get("max_risk_level", "CRÍTICO").upper()
                current = result["risk_level"].upper()
                if _RISK_ORDER.index(current) > _RISK_ORDER.index(cap):
                    result["risk_level"] = cap

            return result

        except json.JSONDecodeError:
            pass

        recovered = _extract_json_with_regex(raw)
        if recovered is not None:
            return recovered

        cleaned = re.sub(r'^[^{]*', '', raw)
        cleaned = re.sub(r'[^}]*$', '', cleaned)
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            raise ValueError(f"No se pudo parsear la respuesta: {raw[:200]}")


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

        for inc in incidents:
            desc = str(inc.get("description", "")).lower()
            url = str(inc.get("url", ""))
            method = str(inc.get("method", "GET"))
            severity = str(inc.get("severity", "INFO")).upper()

            if "hash(" in url or "0x" in url or len(url) > 200:
                controls["noise"].append(inc)
                continue

            if any(x in desc for x in ["cookie", "session", "httponly", "secure flag"]):
                controls["session_management"].append(inc)
            elif any(x in desc for x in ["certificate", "ssl", "tls", "https", "cn=", "hostname"]):
                controls["transport_security"].append(inc)
            elif any(x in desc for x in ["x-frame-options", "csp", "content-security", "clickjacking", "xss"]):
                controls["client_protection"].append(inc)
            elif any(x in desc for x in ["method", "put", "delete", "trace", "debug", "options"]):
                controls["access_control"].append(inc)
            elif any(x in desc for x in ["banner", "version", "x-powered-by", "server:", "etag", "inode"]):
                controls["information_disclosure"].append(inc)
            elif any(x in desc for x in ["robots.txt", "directory", "index of", "accessible"]):
                controls["configuration"].append(inc)
            else:
                controls["information_disclosure"].append(inc)

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
            ranked = sorted(findings, key=lambda f: self._severity_rank(f.get("severity", "INFO")), reverse=True)

            unique_issues = []
            seen = set()
            for f in ranked[:3]:
                desc = f.get("description", "")[:120]
                if desc in seen:
                    continue
                seen.add(desc)
                unique_issues.append(f"[{str(f.get('severity', 'INFO')).upper()}] {desc}")

            controls_summary[control_name] = {
                "instancias_detectadas": len(findings),
                "severidad_original_nikto": sorted(
                    {str(f.get("severity", "INFO")).upper() for f in findings},
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
        for f in findings:
            translated = nikto_to_local.get(str(f.get("severity", "INFO")).upper(), "INFORMATIVO")
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
            num_predict   = 2048,
            temperature   = 0.1,
            top_p         = 0.75,
            repeat_penalty = 1.3,
        )

        result = self._generator.digest(ai_input)
        return self._parse_response(result.text)

    def _parse_response(self, raw: str, attempt: int = 0) -> dict:
        """Parse the AI response JSON with validation."""
        if not raw:
            raise AIResponseError("Respuesta vacía", attempt=attempt)

        try:
            result = json.loads(raw)
            valid = ["CRÍTICO", "ALTO", "MEDIO", "BAJO", "INFORMATIVO"]
            risk_level = result.get("risk_level")
            if risk_level is None or not isinstance(risk_level, str) or risk_level.upper() not in valid:
                result["risk_level"] = "BAJO"

            result.setdefault("executive_summary", "Análisis completado.")
            result.setdefault("technical_analysis", "Análisis de controles de seguridad completado.")
            result.setdefault("recommendations", [])
            result.setdefault("conclusions", "Continuar monitoreo de seguridad.")

            return result
        except json.JSONDecodeError:
            recovered = _extract_json_with_regex(raw)
            if recovered is not None:
                return recovered
            raise AIResponseError(f"Respuesta inválida: {raw[:200]}", attempt=attempt)


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

    def _build_user_prompt(self, scan_data: dict, findings: list) -> str:
        target = scan_data.get("target", "desconocido")
        started = scan_data.get("started_at", "N/A")
        exposure = scan_data.get("exposure", "unknown")

        confirmed = [f for f in findings if f.get("confirmed")]
        kev = [f for f in findings if f.get("in_kev")]

        # Cap the payload to the highest-signal findings rather than dumping
        # everything: confirmed + KEV first (never dropped), then a sample of
        # the rest, so a host with hundreds of open-port entries doesn't drown
        # the handful of real vulnerabilities in the prompt.
        priority_ids = {id(f) for f in confirmed} | {id(f) for f in kev}
        sample = confirmed + kev + [f for f in findings if id(f) not in priority_ids][:15]

        findings_for_ai = [{
            "titulo": f.get("title", "")[:160],
            "categoria": f.get("category", ""),
            "cve_ids": f.get("cve_ids") or [],
            "cvss": f.get("cvss_score"),
            "epss": f.get("epss_score"),
            "en_kev": bool(f.get("in_kev")),
            "confirmado": bool(f.get("confirmed")),
            "qod": f.get("qod"),
            "estado": f.get("state", "open"),
        } for f in sample]

        prompts_config = CR.get_prompts_config()
        template = prompts_config.get(self._prompt_key, {}).get("userTemplate", "")

        return template.replace("{{target}}", str(target)) \
                    .replace("{{started}}", str(started)) \
                    .replace("{{exposure}}", str(exposure)) \
                    .replace("{{total_findings}}", str(len(findings))) \
                    .replace("{{confirmed_count}}", str(len(confirmed))) \
                    .replace("{{kev_count}}", str(len(kev))) \
                    .replace("{{findings_json}}", json.dumps(findings_for_ai, indent=2, ensure_ascii=False))

    def generate(self, scan) -> dict:
        """Generate AI security analysis for a Lybra or Nuclei scan.

        Reads the scan's own `Finding` rows directly via the repository —
        neither `LybraScan` nor `NucleiScan` carries an ORM relationship to
        `Finding` (see `repositories.py`), so this mirrors how the manager/
        report code already fetches them rather than adding one just for this
        writer. ``LybraEngineManager.exposure_for`` is reused as-is: it reads
        only ``scan.target`` and an optional ``asset_id`` (absent on
        ``NucleiScan``, so it degrades to the plain ``classify_exposure`` path),
        so it works for either scan type without a Nuclei-specific branch.
        """
        from src.modules.infrastructure.session import build_repository
        from ..repositories import ScanRepository
        # Diferido como el resto de imports de esta función: `managers` importa
        # `services`, así que a nivel de módulo sería un ciclo.
        from ..managers.lybra import LybraEngineManager

        scan_data = {
            "target": scan.target,
            "started_at": scan.started_at.isoformat() if getattr(scan, 'started_at', None) else "N/A",
            "exposure": LybraEngineManager.exposure_for(scan),
        }

        rows = build_repository(ScanRepository).get_findings_by_scan(scan.id)
        findings = [{
            "title": f.title, "category": f.category, "cve_ids": f.cve_ids,
            "cvss_score": f.cvss_score, "epss_score": f.epss_score, "in_kev": f.in_kev,
            "confirmed": f.confirmed, "qod": f.qod, "state": f.state,
        } for f in rows]

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
            num_predict   = 2048,
            temperature   = 0.1,
            top_p         = 0.75,
            repeat_penalty = 1.3,
        )

        result = self._generator.digest(ai_input)
        return self._parse_response(result.text)

    def _parse_response(self, raw: str, attempt: int = 0) -> dict:
        """Parse the AI response JSON with validation."""
        if not raw:
            raise AIResponseError("Respuesta vacía", attempt=attempt)

        try:
            result = json.loads(raw)
            valid = ["CRÍTICO", "ALTO", "MEDIO", "BAJO", "INFORMATIVO"]
            risk_level = result.get("risk_level")
            if risk_level is None or not isinstance(risk_level, str) or risk_level.upper() not in valid:
                result["risk_level"] = "BAJO"

            result.setdefault("executive_summary", "Análisis completado.")
            result.setdefault("technical_analysis", "Análisis de vulnerabilidades completado.")
            result.setdefault("recommendations", [])
            result.setdefault("conclusions", "Continuar con el plan de remediación.")

            return result
        except json.JSONDecodeError:
            recovered = _extract_json_with_regex(raw)
            if recovered is not None:
                return recovered
            raise AIResponseError(f"Respuesta inválida: {raw[:200]}", attempt=attempt)