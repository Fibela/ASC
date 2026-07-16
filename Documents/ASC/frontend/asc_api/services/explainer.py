"""
Explainer — traducción adaptativa de alertas con claude-fable-5 (S102).

Contrato innegociable (meta del proyecto):
  El módulo EXPLICA y RECOMIENDA. NUNCA decide ni ejecuta. La acción la toma
  el motor determinista o el usuario. Este servicio no llama a specter_bridge,
  ni a neutralizer, ni a ningún adaptador — solo produce texto.

Diseño:
  - Server-side: la ANTHROPIC_API_KEY vive solo en el env de Vercel, nunca
    viaja al frontend ni aparece en el repo.
  - Streaming SSE token a token vía httpx (sin añadir el SDK de Anthropic:
    httpx ya es dependencia y mantiene el Lambda liviano).
  - El perfil del tenant (hogar/pyme/enterprise) selecciona el registro y el
    nivel técnico de la explicación. Los datos de la alerta son reales
    (Supabase); aquí no se inventa nada — si un campo falta, se omite.
"""
from __future__ import annotations

import json

import httpx

from asc_api.core.config import get_settings
from asc_api.core.logging import get_logger

log = get_logger("asc.explainer")

_ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
_ANTHROPIC_VERSION = "2023-06-01"


class ExplainerDisabled(RuntimeError):
    """ANTHROPIC_API_KEY no configurada — el endpoint responde 503."""


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
        "conviene revisar o pedir. Explica la jerga la primera vez que aparezca.\n"
        + _GUARDRAIL
    ),
    "enterprise": (
        "Eres el asistente de ciberseguridad de ASC (PremosCorp) explicando una "
        "alerta a un analista SOC de nivel enterprise.\n"
        "Puedes usar terminología técnica (MITRE ATT&CK, IOC, cadena de eventos) "
        "sin diluirla. Sé conciso y denso en señal: hipótesis de la técnica, "
        "pivotes de investigación sugeridos, y qué evidencia correlacionar.\n"
        + _GUARDRAIL
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


def _payload(profile: str, alert_context: str) -> dict:
    settings = get_settings()
    return {
        "model": settings.ANTHROPIC_MODEL,
        "max_tokens": settings.EXPLAINER_MAX_TOKENS,
        "system": _PROFILE_SYSTEM[profile],
        "stream": True,
        "messages": [
            {
                "role": "user",
                "content": (
                    "Explica esta alerta de seguridad para el perfil indicado. "
                    "Estructura: (1) Qué ocurrió, (2) Por qué importa, "
                    "(3) Qué se recomienda considerar. No ejecutes nada.\n\n"
                    f"--- ALERTA ---\n{alert_context}"
                ),
            }
        ],
    }


async def stream_explanation(alert: dict, profile: str | None):
    """
    Async generator de fragmentos de texto (str) de la explicación.

    Lanza ExplainerDisabled si no hay API key. Propaga httpx errors para que
    el endpoint los mapee (502/504). No captura excepciones en silencio:
    un fallo real debe verse, no simularse.
    """
    settings = get_settings()
    if not settings.ANTHROPIC_API_KEY:
        raise ExplainerDisabled("ANTHROPIC_API_KEY no configurada")

    prof = _normalize_profile(profile)
    ctx = build_alert_context(alert)
    headers = {
        "x-api-key": settings.ANTHROPIC_API_KEY,
        "anthropic-version": _ANTHROPIC_VERSION,
        "content-type": "application/json",
    }

    log.info("explainer_start", profile=prof, alert_id=alert.get("id"))
    timeout = httpx.Timeout(settings.EXPLAINER_TIMEOUT_SECONDS, connect=5.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        async with client.stream(
            "POST", _ANTHROPIC_URL, headers=headers, json=_payload(prof, ctx)
        ) as resp:
            if resp.status_code != 200:
                body = (await resp.aread()).decode("utf-8", "replace")[:400]
                log.error("explainer_api_error", status=resp.status_code, body=body)
                raise httpx.HTTPStatusError(
                    f"Anthropic {resp.status_code}", request=resp.request, response=resp
                )
            async for line in resp.aiter_lines():
                if not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if not data or data == "[DONE]":
                    continue
                try:
                    evt = json.loads(data)
                except json.JSONDecodeError:
                    continue
                if evt.get("type") == "content_block_delta":
                    piece = evt.get("delta", {}).get("text", "")
                    if piece:
                        yield piece
    log.info("explainer_done", profile=prof, alert_id=alert.get("id"))
