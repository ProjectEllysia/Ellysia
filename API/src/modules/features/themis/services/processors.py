from abc import ABC, abstractmethod
from typing import List, Dict, Any, Tuple
import json
import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path


logger = logging.getLogger(__name__)


class ScanResultProcessor(ABC):
    """Procesador base para transformar datos crudos en estructuras de dominio.

    Responsabilidad única: conversión de formatos externos (XML/JSON) a
    diccionarios/objetos del modelo sin persistencia.
    """

    @abstractmethod
    def process(self, raw_data: Any, **context) -> Any:
        """Transforma datos crudos en estructuras de dominio listas para persistir.

        Args:
            raw_data: Datos en formato nativo (XML, JSON, dict)
            **context: Información adicional necesaria (target, etc.)

        Returns:
            Estructuras de datos listas para ser persistidas por los managers.
        """
        pass


class NmapResultProcessor(ScanResultProcessor):
    """Procesa resultados de escaneos Nmap."""

    def process(self, raw_data: dict | str, target: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """Extrae información de hosts y puertos de resultados Nmap.

        Args:
            raw_data: XML string o dict parseado del resultado Nmap.

        Returns:
            Tuple conteniendo:
            - Dict con datos del host (hostname, vendor, ip_address, mac_address)
            - List de dicts con datos de puertos (protocol, state, reason, product, version, given_use)
        """
        if isinstance(raw_data, str):
            raw_data = self._parse_nmap_xml(raw_data)

        parsed = self._parse_nmap_structure(raw_data, target)

        host_data = {
            'hostname': parsed['host']['name'] or parsed['host']['addresses']['ipv4'] or target,
            'vendor': parsed['host']['vendor'],
            'ip_address': parsed['host']['addresses']['ipv4'],
            'mac_address': parsed['host']['addresses']['mac']
        }

        # parsed['ports'] are already dicts (see _parse_nmap_structure); the cpe
        # rides along so it reaches persistence instead of being dropped here.
        ports_data = [dict(port) for port in parsed['ports']]

        return host_data, ports_data

    def _parse_nmap_structure(self, json_data: dict, target: str) -> dict:
        """Parsea la estructura JSON de Nmap."""
        if isinstance(json_data, str):
            try:
                result = json.loads(json_data)
            except json.JSONDecodeError as e:
                raise ValueError(f"JSON inválido: {e}")
        elif isinstance(json_data, dict):
            result = json_data
        else:
            raise TypeError(f"Datos deben ser str o dict, recibido: {type(json_data)}")

        if "nmap" not in result or "scan" not in result:
            raise ValueError("Estructura JSON de Nmap inválida")

        scan_targets = list(result["scan"].keys())
        if target not in result["scan"] and scan_targets:
            target = scan_targets[0]
        elif not scan_targets:
            return {
                'host': {
                    'vendor': "",
                    'name': "",
                    'type': "",
                    'addresses': {"ipv4": "", "mac": ""}
                },
                'ports': []
            }

        scan_data = result["scan"][target]

        hostnames = scan_data.get("hostnames", [])
        hostname = hostnames[0].get("name", "") if hostnames else ""
        hostname_type = hostnames[0].get("type", "") if hostnames else ""

        addresses = scan_data.get("addresses", {})
        ipv4 = addresses.get("ipv4", "")
        mac = addresses.get("mac", "")

        vendor_dict = scan_data.get("vendor", {})
        vendor = vendor_dict.get(mac, "") if mac and vendor_dict else ""

        tcp_ports = scan_data.get("tcp", {})
        ports = []
        for port_number, port_info in tcp_ports.items():
            ports.append({
                "protocol":  f"{port_number}/tcp",
                "state":     port_info.get("state", "unknown"),
                "reason":    port_info.get("reason", ""),
                "product":   port_info.get("product", ""),
                "version":   port_info.get("version", ""),
                "given_use": port_info.get("name", ""),
                "cpe":       port_info.get("cpe", ""),
            })

        return {
            'command': result.get("nmap", {}).get("command_line", ""),
            'host': {
                'vendor': vendor,
                'name': hostname,
                'type': hostname_type,
                'addresses': {
                    'ipv4': ipv4,
                    'mac': mac
                }
            },
            'ports': ports
        }

    def _parse_nmap_xml(self, xml_data: str) -> dict:
        import xml.etree.ElementTree as ET

        root = ET.fromstring(xml_data)

        nmap_meta = {
            "command_line": root.get("args", ""),
            "version": root.get("version", ""),
            "scanflags": "",
            "scaninfo": {}
        }
        scaninfo_el = root.find("scaninfo")
        if scaninfo_el is not None:
            nmap_meta["scaninfo"] = {
                "type": scaninfo_el.get("type", ""),
                "protocol": scaninfo_el.get("protocol", ""),
                "numservices": scaninfo_el.get("numservices", ""),
                "services": scaninfo_el.get("services", ""),
            }

        stats = {}
        runstats = root.find("runstats")
        if runstats is not None:
            finished = runstats.find("finished")
            hosts_el = runstats.find("hosts")
            stats = {
                "timestr": finished.get("timestr", "") if finished is not None else "",
                "elapsed": finished.get("elapsed", "") if finished is not None else "",
                "uphosts": hosts_el.get("up", "0") if hosts_el is not None else "0",
                "downhosts": hosts_el.get("down", "0") if hosts_el is not None else "0",
                "totalhosts": hosts_el.get("total", "0") if hosts_el is not None else "0",
            }

        scan = {}
        for host in root.findall("host"):
            addr_el = host.find("address[@addrtype='ipv4']")
            if addr_el is None:
                addr_el = host.find("address")
            if addr_el is None:
                continue
            ip = addr_el.get("addr", "unknown")

            addresses = {}
            vendor = {}
            for a in host.findall("address"):
                atype = a.get("addrtype", "")
                addr_val = a.get("addr", "")
                addresses[atype] = addr_val
                if atype == "mac" and a.get("vendor"):
                    vendor[addr_val] = a.get("vendor", "")

            status_el = host.find("status")
            status = {
                "state": status_el.get("state", "unknown") if status_el is not None else "unknown",
                "reason": status_el.get("reason", "") if status_el is not None else "",
            }

            hostnames = []
            hostnames_el = host.find("hostnames")
            if hostnames_el is not None:
                for hn in hostnames_el.findall("hostname"):
                    hostnames.append({"name": hn.get("name", ""), "type": hn.get("type", "")})
            if not hostnames:
                hostnames.append({"name": ip, "type": "PTR"})

            tcp_ports = {}
            udp_ports = {}
            ports_el = host.find("ports")
            if ports_el is not None:
                for port_el in ports_el.findall("port"):
                    proto = port_el.get("protocol", "tcp")
                    portid = int(port_el.get("portid", 0))
                    state_el = port_el.find("state")
                    service_el = port_el.find("service")

                    port_data = {
                        "state": state_el.get("state", "") if state_el is not None else "",
                        "reason": state_el.get("reason", "") if state_el is not None else "",
                        "name": service_el.get("name", "") if service_el is not None else "",
                        "product": service_el.get("product", "") if service_el is not None else "",
                        "version": service_el.get("version", "") if service_el is not None else "",
                        "extrainfo": service_el.get("extrainfo", "") if service_el is not None else "",
                        "conf": service_el.get("conf", "") if service_el is not None else "",
                        "cpe": "",
                    }
                    cpe_el = service_el.find("cpe") if service_el is not None else None
                    if cpe_el is not None and cpe_el.text:
                        port_data["cpe"] = cpe_el.text

                    if proto == "tcp":
                        tcp_ports[portid] = port_data
                    else:
                        udp_ports[portid] = port_data

            scan[ip] = {
                "hostnames": hostnames,
                "addresses": addresses,
                "vendor": vendor,
                "status": status,
                "tcp": tcp_ports,
                "udp": udp_ports,
            }

        return {"nmap": nmap_meta, "scan": scan, "stats": stats}


class NiktoResultProcessor(ScanResultProcessor):
    """Procesa resultados de escaneos Nikto."""

    def process(self, raw_data: List[dict] | str) -> List[Dict[str, Any]]:
        """Extrae incidentes de seguridad de resultados Nikto.

        Args:
            raw_data: Path al archivo XML o lista de dicts parseados.

        Returns:
            Lista de diccionarios con datos para crear NiktoIncident
            (description, osvdb_id, method, url, severity)
        """
        if isinstance(raw_data, str):
            raw_data = self._parse_nikto_xml(raw_data)

        incidents = []

        for block in (raw_data or []):
            block_incidents = self._extract_nikto_items(block)
            for item in block_incidents:
                severity = self._classify_threat_level(item)
                incidents.append({
                    'description': item.get('description', ''),
                    'osvdb_id': item.get('osvdbid', ''),
                    'method': item.get('method', ''),
                    'url': item.get('uri', ''),
                    'severity': severity
                })

        return incidents

    def _extract_nikto_items(self, json_data: dict) -> List[dict]:
        """Extrae items individuales del XML parseado de Nikto."""
        try:
            scan_elem = json_data.get('niktoscan') or json_data
            if 'scandetails' in scan_elem:
                scan_elem = scan_elem['scandetails']
            items = scan_elem.get('item', [])
            if isinstance(items, dict):
                return [{k.lstrip('@'): v for k, v in items.items()}]
            return [{k.lstrip('@'): v for k, v in item.items()} for item in items]
        except (KeyError, TypeError):
            return []

    def _classify_threat_level(self, item: dict) -> str:
        """Clasifica la severidad de un incidente Nikto basado en patrones."""
        desc = item.get('description', '').lower()
        url = item.get('uri', '').lower()
        method = item.get('method', '').upper()

        # Patrones críticos
        critical_patterns = [
            ".env", "env.production", "env.local", ".git/", ".git/config",
            "git/head", "phpinfo", "config.php", "database.yml", "wp-config.php",
            "web.config", ".sql", "backup.sql", "dump.sql", "passwd", "shadow",
            "credentials", "private_key", "id_rsa", "config.bak", "database.bak",
            "shell", "webshell", "backdoor", "remote code execution",
            "arbitrary code", "command injection", "sql injection",
            "unrestricted file upload",
        ]
        for pattern in critical_patterns:
            if pattern in desc or pattern in url:
                return "CRITICAL"

        # Patrones altos
        high_patterns = [
            "outdated", "vulnerable version", "known vulnerability", "cve-",
            "xss", "cross site scripting", "cross-site scripting", "csrf",
            "authentication bypass", "authorization bypass", "privilege escalation",
            "directory traversal", "path traversal", "../", "local file inclusion",
            "remote file inclusion", "lfi", "rfi", "weak ssl", "weak tls",
            "ssl v2", "ssl v3", "sslv2", "sslv3", "poodle", "heartbleed",
            "shellshock", "default password", "default credential", "admin/admin",
            "weak cipher", "insecure cipher", "null cipher", "export cipher",
        ]
        dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT"]

        for pattern in high_patterns:
            if pattern in desc or pattern in url:
                return "HIGH"
        if method in dangerous_methods and "allowed" in desc:
            return "HIGH"

        # Patrones medios
        medium_patterns = [
            "directory indexing", "directory listing", "indexes",
            "missing security header", "x-frame-options", "x-content-type-options",
            "content-security-policy", "strict-transport-security", "x-xss-protection",
            "clickjacking", "information disclosure", "information leakage",
            "stack trace", "error message", "debug mode", "verbose error",
            "source code disclosure", "path disclosure", "version disclosure",
            "session fixation", "weak session", "cookie without", "cookie httponly",
            "cookie secure", "unencrypted", "http basic auth", "weak authentication",
            "robots.txt", "sitemap.xml", "cors misconfiguration", "open redirect",
            "server-status", "server-info", "admin panel", "login panel",
            "phpmyadmin", "adminer",
        ]
        for pattern in medium_patterns:
            if pattern in desc or pattern in url:
                return "MEDIUM"

        # Patrones bajos
        low_patterns = [
            "server banner", "server header", "x-powered-by", "server version",
            "apache/", "nginx/", "microsoft-iis", "options method", "head method",
            "allowed http methods", "default page", "default installation",
            "test page", "welcome page", "it works", "uncommon header",
            "unusual header", "missing header", "cache control", "pragma",
            "expires", "retrieved x-powered-by", "retrieved server", "ip address",
            "internal ip", "retrieved via",
        ]
        for pattern in low_patterns:
            if pattern in desc or pattern in url:
                return "LOW"

        # Patrones informativos
        info_patterns = [
            "the site uses", "appears to be", "may be", "possibly",
            "cookie created", "retrieved", "hostname resolves", "scan completed",
            "target ip", "end time", "start time",
        ]
        for pattern in info_patterns:
            if pattern in desc:
                return "INFO"

        return "LOW"

    def _parse_nikto_xml(self, xml_path: str) -> List[Dict]:
        xml_file = Path(xml_path)
        if not xml_file.is_file():
            return []

        try:
            content = xml_file.read_text(encoding='utf-8')
            content = re.sub(r'<!DOCTYPE[^>]*>', '', content)

            root = ET.fromstring(content)
            results = []

            niktoscans = root.findall('.//niktoscan') or ([root] if root.tag == 'niktoscan' else [])

            for niktoscan in niktoscans:
                scandetails = niktoscan.find('scandetails')
                container = scandetails if scandetails is not None else niktoscan
                items = []
                for item_el in container.findall('item'):
                    item = {
                        'osvdbid': item_el.get('id', ''),
                        'method':  item_el.get('method', ''),
                    }
                    for child in item_el:
                        item[child.tag] = (child.text or '').strip()
                    items.append(item)
                if items:
                    results.append({'niktoscan': {'scandetails': {'item': items}}})

            return results

        except ET.ParseError as e:
            logger.error(f"Error parseando XML Nikto: {e}")
            return []


class NucleiResultProcessor(ScanResultProcessor):
    """Procesa resultados de escaneos Nuclei (JSONL, una línea por hallazgo)."""

    def process(self, raw_data: List[dict] | str) -> List[Dict[str, Any]]:
        """Extrae los hallazgos de un fichero JSONL de Nuclei.

        Args:
            raw_data: Ruta al fichero ``.jsonl``, o una lista ya vacía (el caso
                "escaneo limpio, Nuclei no escribió fichero" que
                ``NucleiScanTask._process_results`` produce directamente).

        Returns:
            Lista de diccionarios, uno por línea JSONL decodificada. Más
            simple que Nikto: sin XML, sin ``DOCTYPE`` que limpiar. Una línea
            corrupta se salta con log en vez de tumbar el escaneo entero.
        """
        if isinstance(raw_data, str):
            return self._parse_nuclei_jsonl(raw_data)
        return list(raw_data or [])

    def _parse_nuclei_jsonl(self, jsonl_path: str) -> List[Dict[str, Any]]:
        path = Path(jsonl_path)
        if not path.is_file():
            return []

        results: List[Dict[str, Any]] = []
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, IOError) as e:
            logger.error(f"Error leyendo JSONL de Nuclei: {e}", exc_info=True)
            return []

        for line_number, raw_line in enumerate(content.splitlines(), start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError as e:
                logger.warning(f"Línea {line_number} del JSONL de Nuclei corrupta, se salta: {e}")
                continue

        return results

