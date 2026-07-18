"""
S103.8 — Guardia anti-IDOR (analizador AST como test de CI).

Previene la reaparición de la familia IDOR por-id (S103.2/103.6/103.7). Escanea
services/ y api/v1/endpoints/: si una función consulta un modelo tenant-scoped por
`Model.id ==` SIN ninguna señal de tenant (tenant_id / get_tenant_id /
apply_tenant_filter / current_user.tenant_id) en la misma función, es un IDOR
candidato. El test FALLA ante cualquier violación nueva (fuera del allowlist).

Cada entrada del allowlist es un caso VERIFICADO seguro, con su razón. Añadir algo
aquí exige justificar por qué no es explotable — no es un silenciador cómodo.
"""
from __future__ import annotations

import ast
from pathlib import Path

ASC = Path(__file__).resolve().parents[1] / "asc_api"

# Modelos con columna tenant_id (recursos scopeables). Verificado en models/.
TENANT_MODELS = {
    "Agent", "AgentEvent", "Alert", "APIKey", "Artifact", "CorrelationRule",
    "Hunt", "HuntQuery", "IdentityAction", "Incident", "IoC",
    "NeutralizationAction", "PlaybookTrigger", "ScheduledReport",
    "TenantAdapterConfig", "ThreatIndicator", "Webhook", "Event",
}
TENANT_SIGNALS = (
    "tenant_id", "get_tenant_id", "apply_tenant_filter",
    "current_user.tenant_id", "admin.tenant_id", "user.tenant_id",
)

# ── Allowlist: (archivo, función) -> razón VERIFICADA de por qué NO es IDOR ──
ALLOWLIST = {
    ("agents.py", "_get_agent_by_header"):
        "auth del AGENTE por header X-Specter-ID; el agente es el principal, no una ruta de usuario",
    ("agent_commander.py", "record_command_result"):
        "resultado reportado por el agente autenticado (no ruta de usuario cross-tenant)",
    ("approval.py", "_get_or_raise"):
        "interno; los endpoints de neutralize scopean NeutralizationAction.tenant_id directamente",
    ("correlation_service.py", "_get_rule_unchecked"):
        "interno; el endpoint público get_rule pasa tenant_id=current_user.tenant_id al servicio",
    ("soar_incident_bridge.py", "write_soar_event_to_timeline"):
        "interno; corre durante el procesamiento de un incidente ya cargado de forma scopeada",
    ("query_executor.py", "execute_hunt_query"):
        "alcanzado solo tras get_hunt scopeado (S103.7) + verificación de que el query pertenece al hunt",
}


def _find_violations() -> dict[tuple[str, str], list[str]]:
    violations: dict[tuple[str, str], list[str]] = {}
    files = list((ASC / "services").glob("*.py")) + list((ASC / "api" / "v1" / "endpoints").glob("*.py"))
    for f in files:
        src = f.read_text(encoding="utf-8")
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        lines = src.splitlines()
        for node in ast.walk(tree):
            if not isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
                continue
            seg = "\n".join(lines[node.lineno - 1: node.end_lineno])
            hit = {m for m in _models_compared_by_id(seg) if m in TENANT_MODELS}
            if not hit:
                continue
            if any(sig in seg for sig in TENANT_SIGNALS):
                continue
            violations[(f.name, node.name)] = sorted(hit)
    return violations


def _models_compared_by_id(seg: str) -> set[str]:
    import re
    return set(re.findall(r"(\w+)\.id\s*==", seg))


def test_no_unscoped_tenant_queries_outside_allowlist():
    violations = _find_violations()
    new = {k: v for k, v in violations.items() if k not in ALLOWLIST}
    assert not new, (
        "IDOR candidato NUEVO (query Model.id== de modelo tenant sin scope de tenant):\n"
        + "\n".join(f"  {f}::{fn}() -> {models}" for (f, fn), models in sorted(new.items()))
        + "\n\nScopea por get_tenant_id() / current_user.tenant_id, o si es seguro, "
          "añádelo al ALLOWLIST con su razón verificada."
    )


def test_allowlist_has_no_stale_entries():
    # Si arreglas un allowlisted (deja de ser violación), quítalo del allowlist.
    violations = _find_violations()
    stale = [k for k in ALLOWLIST if k not in violations]
    assert not stale, f"Entradas de ALLOWLIST ya no son violaciones (quítalas): {stale}"
