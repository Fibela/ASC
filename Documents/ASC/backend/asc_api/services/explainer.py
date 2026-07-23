"""
Explainer — traducción adaptativa de alertas (S102/S110).

Contrato innegociable (meta del proyecto):
  El módulo EXPLICA y RECOMIENDA. NUNCA decide ni ejecuta. La acción la toma
  el motor determinista o el usuario. Este servicio no llama a specter_bridge,
  ni a neutralizer, ni a ningún adaptador — solo produce texto.

Diseño (S110 — motor 100% PropremosCorp, sin LLM externo):
  - La explicación la genera `local_explainer` de forma DETERMINISTA a partir de
    los datos reales de la alerta. Tu telemetría de seguridad NUNCA sale a un
    tercero (ventaja de privacidad) y no hay riesgo de alucinación.
  - El perfil del tenant (hogar/pyme/enterprise) selecciona el registro y el
    nivel técnico. Si un campo falta, se omite — aquí no se inventa nada.
  - `build_alert_context` / `_PROFILE_SYSTEM` se conservan como utilidades de
    contexto y registro (reutilizables por una capa premium futura).
"""

from __future__ import annotations

import json

from asc_api.core.logging import get_logger

log = get_logger("asc.explainer")


# ── Guardrail común a todos los perfiles ──────────────────────────────────────
_GUARDRAIL = (
    "Reglas absolutas:\n"
    "- Solo EXPLICAS y RECOMIENDAS. No decides ni ejecutas acciones.\n"
    "- Nunca afirmes haber bloqueado, aislado, o neutralizado nada: eso lo hace "
    "el motor determinista o el analista, no tú.\n"
    "- Usa únicamente los datos de la alerta que se te entregan. Si un dato no "
    "está, no lo inventes ni lo supongas.\n"
    "- No inventes IPs, hosts, hashes, nombres de malware ni integraciones.\n"
    "- Responde en español, directo, sin adulación."
)

_PROFILE_SYSTEM = {
    "hogar": (
        "Eres el asistente de ciberseguridad de ASC (PremosCorp) explicando una "
        "alerta a una persona SIN conocimientos técnicos, en su hogar.\n"
        "Traduce todo a lenguaje cotidiano, con una analogía simple. Evita jerga "
        "(nada de 'TTP', 'C2', 'exfiltración' sin explicarlos). Prioriza calma y "
        "un paso concreto que la persona pueda dar.\n" + _GUARDRAIL
    ),
    "pyme": (
        "Eres el asistente de ciberseguridad de ASC (PremosCorp) explicando una "
        "alerta al responsable de IT de una pequeña o mediana empresa, con "
        "conocimiento técnico medio y sin equipo de seguridad dedicado.\n"
        "Sé claro y accionable: qué pasó, por qué importa para el negocio, y qué "
        "conviene revisar o pedir. Explica la jerga la primera vez que aparezca.\n" + _GUARDRAIL
    ),
    "enterprise": (
        "Eres el asistente de ciberseguridad de ASC (PremosCorp) explicando una "
        "alerta a un analista SOC de nivel enterprise.\n"
        "Puedes usar terminología técnica (MITRE ATT&CK, IOC, cadena de eventos) "
        "sin diluirla. Sé conciso y denso en señal: hipótesis de la técnica, "
        "pivotes de investigación sugeridos, y qué evidencia correlacionar.\n" + _GUARDRAIL
    ),
}

_VALID_PROFILES = frozenset(_PROFILE_SYSTEM)


def _normalize_profile(profile: str | None) -> str:
    p = (profile or "pyme").lower().strip()
    return p if p in _VALID_PROFILES else "pyme"


def build_alert_context(alert: dict) -> str:
    """Serializa SOLO los campos presentes de la alerta — sin relleno."""
    fields = [
        ("Título", alert.get("title")),
        ("Descripción", alert.get("description")),
        ("Severidad", alert.get("severity")),
        ("Risk score", alert.get("risk_score")),
        ("Estado", alert.get("status")),
        ("Hosts afectados", alert.get("affected_hosts")),
        ("TTPs (MITRE)", alert.get("ttps")),
        ("IOCs correlacionados", alert.get("matched_iocs")),
        ("Acciones recomendadas por el motor", alert.get("recommended_actions")),
    ]
    lines = []
    for label, value in fields:
        if value in (None, "", [], {}):
            continue
        if isinstance(value, (list, dict)):
            value = json.dumps(value, ensure_ascii=False)
        lines.append(f"{label}: {value}")
    return "\n".join(lines) if lines else "(alerta sin campos legibles)"


async def stream_local(alert: dict, profile: str | None):
    """
    Genera la explicación con el MOTOR PROPIO de PremosCorp (S110) — determinista,
    sin LLM externo. La telemetría nunca sale a un tercero; cero alucinación.
    Async generator de fragmentos de texto (str). EXPLICA y RECOMIENDA; nunca decide
    ni ejecuta, nunca inventa datos ausentes.
    """
    from asc_api.services.local_explainer import stream_local_explanation

    log.info("explainer_start", profile=_normalize_profile(profile), alert_id=alert.get("id"), engine="local")
    async for piece in stream_local_explanation(alert, profile):
        yield piece
    log.info("explainer_done", profile=_normalize_profile(profile), alert_id=alert.get("id"), engine="local")


# Alias de compatibilidad: el endpoint importa stream_explanation.
stream_explanation = stream_local
