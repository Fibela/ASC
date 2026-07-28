"""
Report Generation Service — PDF & HTML reports with PremosCorp branding.
"""

import io
from datetime import UTC, datetime

from asc_api.core.config import get_settings
from asc_api.core.logging import get_logger

settings = get_settings()
log = get_logger(__name__)

# Color palette PremosCorp
COLOR_PRIMARY = (0.11, 0.11, 0.11)  # Charcoal (PremosCorp void)
COLOR_ACCENT = (0.909, 0.365, 0.016)  # Ember (PremosCorp #E85D04)
COLOR_CRITICAL = (0.85, 0.10, 0.10)  # Red
COLOR_HIGH = (0.90, 0.45, 0.05)  # Orange
COLOR_MEDIUM = (0.95, 0.75, 0.05)  # Yellow
COLOR_LOW = (0.20, 0.70, 0.30)  # Green
COLOR_WHITE = (1.0, 1.0, 1.0)
COLOR_LIGHT_BG = (0.95, 0.97, 1.0)


def _severity_color(severity: str) -> tuple:
    return {
        "critical": COLOR_CRITICAL,
        "high": COLOR_HIGH,
        "medium": COLOR_MEDIUM,
        "low": COLOR_LOW,
    }.get(severity.lower(), (0.5, 0.5, 0.5))


def generate_pdf_report(report_data: dict) -> bytes:
    """Generate a professional PDF report. Returns bytes."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer, pagesize=A4, topMargin=2 * cm, bottomMargin=2 * cm, leftMargin=2 * cm, rightMargin=2 * cm
        )

        styles = getSampleStyleSheet()
        charcoal = colors.Color(*COLOR_PRIMARY)
        ember = colors.Color(*COLOR_ACCENT)

        title_style = ParagraphStyle("Title", parent=styles["Title"], textColor=charcoal, fontSize=22, spaceAfter=6)
        h2_style = ParagraphStyle(
            "H2", parent=styles["Heading2"], textColor=charcoal, fontSize=14, spaceBefore=14, spaceAfter=6
        )
        body_style = ParagraphStyle("Body", parent=styles["Normal"], fontSize=10, spaceAfter=4)

        story = []

        # Header
        story.append(Paragraph(f"<b>{settings.REPORT_COMPANY_NAME}</b>", title_style))
        story.append(
            Paragraph(
                "Advanced Security Center — Reporte de Análisis de Seguridad",
                ParagraphStyle("Sub", parent=styles["Normal"], textColor=ember, fontSize=12),
            )
        )
        story.append(HRFlowable(width="100%", thickness=2, color=ember, spaceAfter=10))

        # Metadata table
        meta = [
            [
                "ID de Reporte",
                report_data.get("report_id", "N/A"),
                "Generado",
                datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
            ],
            ["Analista", report_data.get("analyst", "System"), "Período", report_data.get("period", "N/A")],
            ["Cliente", report_data.get("client", settings.REPORT_COMPANY_NAME), "Clasificación", "CONFIDENCIAL"],
        ]
        meta_table = Table(meta, colWidths=[3.5 * cm, 5.5 * cm, 3.5 * cm, 5.5 * cm])
        meta_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.Color(*COLOR_LIGHT_BG)),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
                    ("PADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        story.append(meta_table)
        story.append(Spacer(1, 0.5 * cm))

        # Executive Summary
        story.append(Paragraph("Resumen Ejecutivo", h2_style))
        summary = report_data.get("summary", {})
        story.append(
            Paragraph(
                f"During the analysis period, the ASC detected <b>{summary.get('total_alerts', 0)}</b> alerts "
                f"from <b>{summary.get('total_events', 0)}</b> ingested events. "
                f"Risk posture: <b>{summary.get('risk_posture', 'N/A')}</b>. "
                f"Critical findings: <b>{summary.get('critical_count', 0)}</b>.",
                body_style,
            )
        )

        # SOC Metrics
        story.append(Paragraph("Métricas SOC", h2_style))
        metrics = report_data.get("metrics", {})
        mttd = f"{metrics.get('mttd_minutes', 'N/A')} min" if metrics.get("mttd_minutes") else "N/A"
        mttr = f"{metrics.get('mttr_minutes', 'N/A')} min" if metrics.get("mttr_minutes") else "N/A"
        metrics_data = [
            ["Metric", "Value", "Metric", "Value"],
            ["MTTD", mttd, "MTTR", mttr],
            ["Total Events", str(metrics.get("total_events", 0)), "Total Alerts", str(metrics.get("total_alerts", 0))],
            [
                "True Positives",
                str(metrics.get("true_positives", 0)),
                "False Positive Rate",
                f"{metrics.get('fp_rate', 0) * 100:.1f}%",
            ],
            [
                "IoC Coverage",
                f"{metrics.get('ioc_coverage', 0) * 100:.1f}%",
                "Endpoint Coverage",
                f"{metrics.get('endpoint_coverage', 0) * 100:.1f}%",
            ],
        ]
        m_table = Table(metrics_data, colWidths=[4 * cm, 3.5 * cm, 4 * cm, 3.5 * cm])
        m_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), charcoal),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.Color(*COLOR_LIGHT_BG), colors.white]),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
                    ("PADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        story.append(m_table)
        story.append(Spacer(1, 0.4 * cm))

        # Alerts table
        alerts = report_data.get("alerts", [])
        if alerts:
            story.append(Paragraph(f"Alertas ({len(alerts)})", h2_style))
            alert_data = [["#", "Title", "Severity", "Risk Score", "Status", "Detected"]]
            for i, a in enumerate(alerts[:20], 1):
                alert_data.append(
                    [
                        str(i),
                        a.get("title", "")[:50],
                        a.get("severity", "").upper(),
                        f"{a.get('risk_score', 0):.2f}",
                        a.get("status", ""),
                        a.get("detected_at", "")[:10],
                    ]
                )
            a_table = Table(alert_data, colWidths=[0.8 * cm, 7 * cm, 2.2 * cm, 2 * cm, 2.5 * cm, 2.5 * cm])
            row_styles = [
                ("BACKGROUND", (0, 0), (-1, 0), charcoal),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
                ("PADDING", (0, 0), (-1, -1), 5),
            ]
            for i, a in enumerate(alerts[:20], 1):
                sev = a.get("severity", "low")
                sev_color = colors.Color(*_severity_color(sev))
                row_styles.append(("BACKGROUND", (2, i), (2, i), sev_color))
                row_styles.append(("TEXTCOLOR", (2, i), (2, i), colors.white))
            a_table.setStyle(TableStyle(row_styles))
            story.append(a_table)

        # Footer
        story.append(Spacer(1, 1 * cm))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey))
        story.append(
            Paragraph(
                f"<i>Generado y sellado por {settings.REPORT_COMPANY_NAME} ASC · v{settings.APP_VERSION} · CONFIDENCIAL — distribución no autorizada prohibida</i>",
                ParagraphStyle(
                    "Footer", parent=styles["Normal"], fontSize=8, textColor=colors.grey, alignment=TA_CENTER
                ),
            )
        )

        doc.build(story)
        return buffer.getvalue()

    except ImportError:
        log.warning("reportlab_not_installed", msg="PDF generation requires reportlab")
        return b""


def generate_html_report(report_data: dict) -> str:
    """Generate HTML report with PremosCorp branding."""
    alerts_html = ""
    for a in report_data.get("alerts", []):
        sev = a.get("severity", "low")
        sev_class = {"critical": "danger", "high": "warning", "medium": "info", "low": "success"}.get(sev, "secondary")
        alerts_html += f"""
        <tr>
            <td>{a.get("title", "")}</td>
            <td><span class="badge bg-{sev_class}">{sev.upper()}</span></td>
            <td>{a.get("risk_score", 0):.2f}</td>
            <td>{a.get("status", "")}</td>
            <td>{str(a.get("detected_at", ""))[:19]}</td>
        </tr>"""

    metrics = report_data.get("metrics", {})
    summary = report_data.get("summary", {})

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ASC Report — {settings.REPORT_COMPANY_NAME}</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
<style>
  body {{ background: #0A0A0A; color: #EAEAEA; font-family: 'Segoe UI', system-ui, sans-serif; }}
  .brand-header {{ background: linear-gradient(135deg, #0A0A0A 0%, #1a1a1a 100%); border-bottom: 2px solid #E85D04; }}
  .brand-header h1 {{ color: #E85D04; }}
  .metric-card {{ background: #141414; border: 1px solid rgba(232,93,4,0.35); border-radius: 10px; }}
  .metric-value {{ font-size: 2rem; font-weight: bold; color: #E85D04; }}
  table {{ --bs-table-bg: #141414; --bs-table-striped-bg: #1a1a1a; color: #EAEAEA; }}
  th {{ background: #0A0A0A !important; color: #E85D04 !important; }}
  .section-title {{ color: #E85D04; border-bottom: 1px solid rgba(232,93,4,0.4); padding-bottom: 6px; }}
</style>
</head>
<body>
<div class="brand-header py-4 px-5 mb-4">
  <h1 class="mb-0"><b>{settings.REPORT_COMPANY_NAME}</b> — Advanced Security Center</h1>
  <p class="text-light mb-0">Reporte de Análisis de Seguridad &nbsp;|&nbsp; Generado: {datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")}</p>
</div>
<div class="container-fluid px-5">
  <div class="row g-3 mb-4">
    <div class="col-md-3"><div class="metric-card p-3 text-center">
      <div class="metric-value">{summary.get("total_alerts", 0)}</div><div>Alertas Totales</div></div></div>
    <div class="col-md-3"><div class="metric-card p-3 text-center">
      <div class="metric-value">{summary.get("critical_count", 0)}</div><div>Críticas</div></div></div>
    <div class="col-md-3"><div class="metric-card p-3 text-center">
      <div class="metric-value">{metrics.get("mttd_minutes", "N/A")}</div><div>MTTD (min)</div></div></div>
    <div class="col-md-3"><div class="metric-card p-3 text-center">
      <div class="metric-value">{metrics.get("mttr_minutes", "N/A")}</div><div>MTTR (min)</div></div></div>
  </div>

  <h4 class="section-title">Alertas</h4>
  <div class="table-responsive">
  <table class="table table-striped table-hover">
    <thead><tr><th>Título</th><th>Severidad</th><th>Riesgo</th><th>Estado</th><th>Detectado</th></tr></thead>
    <tbody>{alerts_html}</tbody>
  </table>
  </div>

  <p class="text-muted mt-5 text-center small">
    Generado y sellado por {settings.REPORT_COMPANY_NAME} ASC · v{settings.APP_VERSION} · CONFIDENCIAL — distribución no autorizada prohibida
  </p>
</div>
</body>
</html>"""
