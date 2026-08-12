"""Estrategia de impresión de los informes de Nmap (D5)."""

from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
import src.modules.system.config_reading as CR

from ...model import Host, NmapScan, ScanType
from ..analyzers import NmapAIWriter
from src.modules.shared.report_theme import ColorType, ReportTheme
from .base import PrintingStrategy


@PrintingStrategy.register(ScanType.NMAP)
class NmapPrintingStrategy(PrintingStrategy):
    """Printing strategy for Nmap scan reports.

    Generates PDF reports for Nmap network scans including host information,
    open ports table, and optional AI-powered security analysis.

    Color palette: Blue theme for network security reports.

    Attributes:
        writer: NmapAIWriter instance for AI analysis.
        color_palette: Blue color palette for the report.
    """

    def __init__(self, scan: NmapScan) -> None:
        """Initialize Nmap printing strategy.

        Args:
            scan: NmapScan instance to generate report from.
        """
        super().__init__(scan)
        self.writer = NmapAIWriter()

        palette_config = CR.get_tool_color_palette(ScanType.NMAP)

        self.color_palette = {
            ColorType.BLACK: palette_config.get("black", "#121212"),
            ColorType.DARK: palette_config.get("dark", "#01375A"),
            ColorType.MAIN: palette_config.get("main", "#014F86"),
            ColorType.SECONDARY: palette_config.get("secondary", "#555B6E"),
            ColorType.LIGHT: palette_config.get("light", "#4A90E2"),
            ColorType.WHITE: palette_config.get("white", "#E1E8F0"),
        }

    def append_body(self, theme: ReportTheme, elements: list, ai_report: bool = False) -> None:
        """Generate the report body for Nmap scans.

        Args:
            theme: Report theme for styling.
            elements: List of flowable elements to append to.
            ai_report: Whether to include AI-generated analysis.
        """
        scan = self.scan
        palette = self.color_palette
        main = colors.HexColor(palette[ColorType.MAIN])
        dark = colors.HexColor(palette[ColorType.DARK])
        white = colors.HexColor(palette[ColorType.WHITE])
        light = colors.HexColor(palette[ColorType.LIGHT])

        elements.append(Paragraph("Informe de Escaneo Nmap", theme.title))
        elements.append(Spacer(1, 0.1 * inch))

        if getattr(scan, "host", None):
            host: Host = scan.host
            host_info = [
                ["Host analizado:", str(getattr(host, "ip_address", ""))],
                ["Nombre de host:", str(getattr(host, "hostname", ""))],
                ["MAC address:", str(getattr(host, "mac_address", ""))],
            ]
            host_table = theme.kv_table(host_info, col_widths=[2 * inch, 4 * inch])
            elements.append(host_table)
            elements.append(Spacer(1, 0.1 * inch))

        started = getattr(scan, "started_at", None)
        started_str = started.strftime("%d/%m/%Y %H:%M:%S") if started else "N/A"
        total_ports = len(getattr(scan, "open_ports_relation", []))

        scan_info = [
            ["ID del escaneo:", str(getattr(scan, "id", ""))],
            ["Fecha de inicio:", started_str],
            ["Total de puertos abiertos:", str(total_ports)],
        ]
        scan_table = theme.kv_table(scan_info, col_widths=[2 * inch, 4 * inch])
        elements.append(scan_table)
        elements.append(Spacer(1, 0.3 * inch))

        elements.append(Paragraph("Puertos abiertos detectados", theme.subtitle))
        elements.append(Spacer(1, 0.1 * inch))

        open_ports = getattr(scan, "open_ports_relation", [])
        if not open_ports:
            elements.append(Paragraph("No se detectaron puertos abiertos.", theme.info))
            return

        port_data = [["#", "Puerto", "Servicio", "Versión del software"]]
        for idx, relation in enumerate(open_ports, start=1):
            port = getattr(relation, "port", None)
            port_id = getattr(port, "port", "") if port else ""
            protocol = getattr(port, "protocol", "") if port else ""
            given_use = str(getattr(relation, "given_use", "") or "").upper()
            product_name = str(getattr(relation, "product", "") or "") or "NO ENCONTRADO"
            product_version = str(getattr(relation, "version", "") or "") or "N/A"

            port_str = f"{port_id}"
            proto_str = protocol.split("/")[0] if protocol else ""

            port_data.append([
                str(idx),
                proto_str,
                given_use,
                f"{product_name} {product_version}".strip(),
            ])

        port_table = Table(
            port_data,
            colWidths=[0.5 * inch, 0.8 * inch, 2.0 * inch, 4.0 * inch],
            repeatRows=1,
        )
        port_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), main),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, 0), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 10),
            ("TOPPADDING", (0, 0), (-1, 0), 8),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
            ("BACKGROUND", (0, 1), (-1, -1), white),
            ("TEXTCOLOR", (0, 1), (-1, -1), dark),
            ("ALIGN", (0, 1), (0, -1), "CENTER"),
            ("ALIGN", (1, 1), (-1, -1), "LEFT"),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 1), (-1, -1), 9),
            ("TOPPADDING", (0, 1), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, white]),
            ("GRID", (0, 0), (-1, -1), 0.4, light),
            ("LINEBELOW", (0, 0), (-1, 0), 1.2, main),
        ]))
        elements.append(port_table)

        if ai_report:
            self._append_ai_analysis(elements, theme)

        self._append_history_stats(elements, theme)

    def get_filename_suffix(self) -> str:
        """Get the PDF filename suffix.

        Returns:
            Filename suffix: "_Nmap.pdf"
        """
        return "_Nmap.pdf"

    def get_picture_name(self, dark: bool = False) -> str:
        """Get the logo image name for Nmap reports.

        Args:
            dark: Whether to use dark variant.

        Returns:
            Logo filename.
        """
        picture_name = "Themis-Blue-Bg"
        return picture_name + "Dark.png" if dark else picture_name + "Light.png"

    def get_report_title(self) -> str:
        """Get the report title for the cover page.

        Returns:
            Report title: "Análisis de Seguridad de Red"
        """
        return "Análisis de Seguridad de Red"

