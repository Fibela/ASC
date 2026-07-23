"""
Explicación adaptativa PROPIA de PremosCorp (S110) — determinista, sin LLM externo.

Ventaja competitiva y de privacidad: tu telemetría de seguridad NUNCA sale a un tercero.
Cero alucinación (es determinista). Guardrail: EXPLICA y RECOMIENDA; nunca decide ni
ejecuta, nunca inventa datos que la alerta no trae.

Genera 3 secciones (qué ocurrió · por qué importa · qué se recomienda considerar) a partir
de los campos REALES de la alerta, en el registro del perfil (hogar/pyme/enterprise), y las
emite en trozos para conservar el efecto de streaming en vivo del panel.
"""

from __future__ import annotations

import asyncio
from typing import Any

_VALID_PROFILES = ("hogar", "pyme", "enterprise")


def _reg(profile: str | None) -> str:
    p = (profile or "pyme").lower().strip()
    return p if p in _VALID_PROFILES else "pyme"


# ── Base de conocimiento MITRE ATT&CK (activo propio; crece con el tiempo) ─────
_TTP_KB: dict[str, dict[str, str]] = {
    "T1110": {
        "hogar": "alguien intentó entrar probando muchas contraseñas, como quien prueba llave tras llave",
        "pyme": "se detectaron múltiples intentos fallidos de acceso — patrón típico de fuerza bruta contra una cuenta",
        "enterprise": "T1110 (Brute Force): intentos repetidos de autenticación para adivinar credenciales",
    },
    "T1071": {
        "hogar": "un programa estuvo 'llamando a casa' a un servidor desconocido de forma repetida",
        "pyme": "tráfico saliente periódico hacia un destino no reconocido — posible canal de control remoto (C2)",
        "enterprise": "T1071 (Application Layer Protocol): comunicación C2 sobre protocolo de aplicación",
    },
    "T1547": {
        "hogar": "se cambió algo para que un programa arranque solo cada vez que enciendes el equipo",
        "pyme": "se creó un mecanismo de persistencia (arranque automático) — el atacante busca mantenerse",
        "enterprise": "T1547 (Boot/Logon Autostart): persistencia vía autostart",
    },
    "T1021": {
        "hogar": "hubo intentos de saltar de un equipo a otro dentro de la red",
        "pyme": "movimiento lateral entre equipos de la red — el atacante intenta expandirse",
        "enterprise": "T1021 (Remote Services): movimiento lateral vía servicios remotos (SMB)",
    },
    "T1048": {
        "hogar": "salió información del equipo hacia afuera de forma inusual",
        "pyme": "posible extracción de datos (exfiltración) hacia un destino externo",
        "enterprise": "T1048 (Exfiltration Over Alternative Protocol): exfiltración de datos",
    },
    "T1003": {
        "hogar": "hubo un intento de robar contraseñas guardadas en el equipo",
        "pyme": "intento de volcado de credenciales (credential dumping)",
        "enterprise": "T1003 (OS Credential Dumping): extracción de credenciales del SO",
    },
}
_GENERIC_TTP = {
    "hogar": "una técnica de ataque conocida",
    "pyme": "una técnica de ataque catalogada en MITRE ATT&CK",
    "enterprise": "técnica MITRE ATT&CK",
}

_SEV_PHRASE: dict[str, dict[str, str]] = {
    "critical": {
        "hogar": "muy grave y urgente",
        "pyme": "crítica — requiere atención inmediata",
        "enterprise": "crítica",
    },
    "high": {"hogar": "grave", "pyme": "alta", "enterprise": "alta"},
    "medium": {"hogar": "moderada", "pyme": "media", "enterprise": "media"},
    "low": {"hogar": "baja", "pyme": "baja", "enterprise": "baja"},
    "info": {"hogar": "informativa", "pyme": "informativa", "enterprise": "informativa"},
}

# Acciones recomendadas (códigos del motor) → frase por registro. Siempre en tono de
# RECOMENDACIÓN, jamás como algo ya ejecutado.
_ACTION_KB: dict[str, dict[str, str]] = {
    "block_ip": {
        "hogar": "bloquear la conexión sospechosa",
        "pyme": "bloquear la IP en el firewall",
        "enterprise": "block_ip en el firewall",
    },
    "block_domain": {
        "hogar": "bloquear el sitio sospechoso",
        "pyme": "bloquear el dominio (sinkhole DNS)",
        "enterprise": "block_domain / DNS sinkhole",
    },
    "isolate_endpoint": {
        "hogar": "desconectar el equipo de internet",
        "pyme": "aislar el equipo de la red",
        "enterprise": "isolate_endpoint (contención de host)",
    },
    "kill_process": {
        "hogar": "cerrar el programa sospechoso",
        "pyme": "terminar el proceso malicioso",
        "enterprise": "kill_process del proceso implicado",
    },
    "disable_account": {
        "hogar": "bloquear temporalmente la cuenta",
        "pyme": "deshabilitar la cuenta comprometida",
        "enterprise": "disable_account en el directorio",
    },
    "quarantine_file": {
        "hogar": "poner en cuarentena el archivo peligroso",
        "pyme": "poner el archivo en cuarentena",
        "enterprise": "quarantine_file",
    },
}


def _join(items: list[str]) -> str:
    items = [i for i in items if i]
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + " y " + items[-1]


def _describe_ttps(ttps: list, reg: str) -> list[str]:
    out: list[str] = []
    for t in ttps or []:
        kb = _TTP_KB.get(str(t))
        out.append(kb[reg] if kb else f"{_GENERIC_TTP[reg]} ({t})")
    return out


def _humanize_action(code: str, reg: str) -> str:
    kb = _ACTION_KB.get(str(code))
    return kb[reg] if kb else str(code).replace("_", " ")


def build_explanation(alert: dict[str, Any], profile: str | None) -> str:
    """Construye la explicación completa (determinista). Solo usa campos presentes."""
    reg = _reg(profile)
    title = alert.get("title") or "una alerta de seguridad"
    sev = str(alert.get("severity") or "").lower()
    risk = alert.get("risk_score")
    hosts = alert.get("affected_hosts") or []
    ttps = alert.get("ttps") or []
    iocs = alert.get("matched_iocs") or []
    actions = alert.get("recommended_actions") or []

    # ── Sección 1: qué ocurrió ──
    s1 = f"**Qué ocurrió:** {title}."
    ttp_desc = _describe_ttps(ttps, reg)
    if ttp_desc:
        connector = {"hogar": "En palabras simples, ", "pyme": "Técnicamente, ", "enterprise": ""}[reg]
        s1 += " " + connector + _join(ttp_desc) + "."
    if hosts:
        label = "Equipo(s) involucrado(s)" if reg == "hogar" else "Equipo(s) afectado(s)"
        s1 += f" {label}: {_join([str(h) for h in hosts])}."
    if iocs:
        s1 += f" Se correlacionaron {len(iocs)} indicador(es) de compromiso conocido(s)."

    # ── Sección 2: por qué importa ──
    s2 = "**Por qué importa:** "
    sevp = _SEV_PHRASE.get(sev, {}).get(reg)
    if sevp:
        s2 += f"La severidad es {sevp}. "
    if isinstance(risk, (int, float)):
        s2 += f"Puntaje de riesgo: {risk}. "
    s2 += {
        "hogar": "Conviene atenderlo para proteger tu información.",
        "pyme": "Ignorarlo podría derivar en acceso no autorizado o interrupción del negocio.",
        "enterprise": "Priorizar según el contexto de la cadena de eventos y los activos afectados.",
    }[reg]

    # ── Sección 3: qué se recomienda considerar ──
    s3 = "**Qué se recomienda considerar:** "
    if actions:
        opener = {"hogar": "Podrías ", "pyme": "Conviene ", "enterprise": "Acciones sugeridas: "}[reg]
        s3 += opener + _join([_humanize_action(a, reg) for a in actions]) + "."
    else:
        s3 += {
            "hogar": "Revisa el equipo y cambia contraseñas si notas algo raro.",
            "pyme": "Revisar los accesos recientes y validar si la actividad es legítima.",
            "enterprise": "Correlacionar con eventos adyacentes y validar con telemetría adicional.",
        }[reg]
    s3 += (
        " "
        + {
            "hogar": "(Esto es una recomendación; la decisión y la acción las tomas tú.)",
            "pyme": "(ASC explica y recomienda; la acción la ejecuta el analista o el motor determinista.)",
            "enterprise": "(Recomendación; ejecución a cargo del analista o del motor determinista.)",
        }[reg]
    )

    return " ".join([s1, s2, s3])


async def stream_local_explanation(alert: dict[str, Any], profile: str | None):
    """Async generator: emite la explicación en trozos (palabra a palabra) para el
    efecto de streaming en vivo. No hay red ni LLM externo: es instantáneo y privado."""
    text = build_explanation(alert, profile)
    words = text.split(" ")
    for i, w in enumerate(words):
        yield (w if i == 0 else " " + w)
        await asyncio.sleep(0)  # cede control al loop; no bloquea
