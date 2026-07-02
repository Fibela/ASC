"""
Playbooks Engine — automated incident response orchestration.

4 built-in playbooks:
  PB-001  Verde      risk < 0.40          Log + monitoreo (auto)
  PB-002  Amarillo   0.40 ≤ risk < 0.85   Alerta + [HitL] + bloqueo IP
  PB-003  Rojo       risk ≥ 0.85          Alerta + [HitL] + aislamiento + C2 + persistencia
  PB-004  Targeted   fingerprint ≥ 0.30   Escalación + [HitL] + aislamiento condicional

HitL (Human-in-the-Loop) pauses execution at AWAIT_APPROVAL.
Resume via approve_playbook_run() with the stored approval_token.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.core.logging import get_logger
from asc_api.models.alert import Alert
from asc_api.models.playbook_run import PlaybookRun
from asc_api.services import neutralizer

log = get_logger(__name__)


# ─── Context ──────────────────────────────────────────────────────────────────

@dataclass
class PlaybookContext:
    """Normalized trigger context passed to every playbook."""
    semaphore: str                                # green | yellow | red
    risk_score: float
    trigger_source: str                           # manual | auto_detection | auto_fingerprint
    trigger_data: dict = field(default_factory=dict)

    # Event fields (optional — derived from trigger_data when available)
    host: str | None = None
    dst_ip: str | None = None
    dst_domain: str | None = None
    process_name: str | None = None
    ttps: list[str] = field(default_factory=list)

    # Fingerprint-specific
    fingerprint_confidence: float | None = None
    fingerprint_triggers: list[str] = field(default_factory=list)

    # Identity context — P26 PIDS
    affected_user: str | None = None       # sAMAccountName of the target identity
    affected_domain: str = "corp.local"   # AD domain for the target identity

    @classmethod
    def from_detection(cls, event: dict, risk_score: float, semaphore: str) -> "PlaybookContext":
        host = (
            event.get("host", {}).get("hostname")
            or event.get("host")
            if not isinstance(event.get("host"), str)
            else event.get("host")
        )
        return cls(
            semaphore=semaphore,
            risk_score=risk_score,
            trigger_source="auto_detection",
            trigger_data=event,
            host=str(host) if host else None,
            dst_ip=event.get("destination", {}).get("ip") if isinstance(event.get("destination"), dict) else None,
            dst_domain=event.get("destination", {}).get("domain") if isinstance(event.get("destination"), dict) else None,
            process_name=event.get("process", {}).get("name") if isinstance(event.get("process"), dict) else None,
            ttps=event.get("ttps", []),
        )

    @classmethod
    def from_fingerprint(cls, result: dict) -> "PlaybookContext":
        confidence = result.get("confidence", 0.0)
        risk = result.get("risk_score", 0.85)
        return cls(
            semaphore="red" if confidence >= 0.50 else "yellow",
            risk_score=float(risk),
            trigger_source="auto_fingerprint",
            trigger_data=result,
            fingerprint_confidence=float(confidence),
            fingerprint_triggers=result.get("triggers", []),
        )


# ─── Playbook Definitions ─────────────────────────────────────────────────────

@dataclass
class StepDef:
    action: str      # LOG | CREATE_ALERT | TAG_ALERT | NOTIFY | AWAIT_APPROVAL | ISOLATE_ENDPOINT | BLOCK_IP | BLOCK_DOMAIN | REMOVE_PERSISTENCE
    name: str
    params: dict = field(default_factory=dict)


@dataclass
class PlaybookDefinition:
    id: str
    name: str
    description: str
    semaphore: str
    requires_approval: bool
    steps: list[StepDef]
    min_risk: float = 0.0
    max_risk: float = 1.0


PLAYBOOKS: dict[str, PlaybookDefinition] = {
    "PB-001": PlaybookDefinition(
        id="PB-001",
        name="Monitoreo Verde — Evento Nominal",
        description="Actividad dentro de umbrales normales. Registro en SIEM y clasificación para monitoreo continuo.",
        semaphore="green",
        requires_approval=False,
        min_risk=0.0,
        max_risk=0.39,
        steps=[
            StepDef("LOG",        "Registrar evento nominal en SIEM"),
            StepDef("TAG_ALERT",  "Clasificar alerta como monitoreo continuo"),
            StepDef("NOTIFY",     "Notificación informativa a analista de turno"),
        ],
    ),
    "PB-002": PlaybookDefinition(
        id="PB-002",
        name="Respuesta Amarilla — Actividad Sospechosa",
        description="Indicadores de compromiso detectados. Se crea alerta HIGH y se espera aprobación analista para bloquear IP.",
        semaphore="yellow",
        requires_approval=True,
        min_risk=0.40,
        max_risk=0.84,
        steps=[
            StepDef("LOG",            "Registrar actividad sospechosa — prioridad alta"),
            StepDef("CREATE_ALERT",   "Crear alerta HIGH en base de datos"),
            StepDef("NOTIFY",         "Notificar analista SOC"),
            StepDef("AWAIT_APPROVAL", "Esperar aprobación analista (Human-in-the-Loop)"),
            StepDef("BLOCK_IP",       "Bloquear IP C2 si disponible en contexto"),
            StepDef("BLOCK_DOMAIN",   "Bloquear dominio C2 si disponible en contexto"),
        ],
    ),
    "PB-003": PlaybookDefinition(
        id="PB-003",
        name="Respuesta Roja Crítica — Compromiso Activo",
        description="Compromiso activo confirmado. Aislamiento de endpoint, bloqueo C2 y eliminación de persistencia tras aprobación.",
        semaphore="red",
        requires_approval=True,
        min_risk=0.85,
        max_risk=1.0,
        steps=[
            StepDef("LOG",              "Registrar compromiso activo — CRÍTICO"),
            StepDef("CREATE_ALERT",     "Crear alerta CRITICAL en base de datos"),
            StepDef("NOTIFY",           "Notificación de emergencia a SOC senior"),
            StepDef("AWAIT_APPROVAL",   "Autorización analista senior (Human-in-the-Loop)"),
            StepDef("ISOLATE_ENDPOINT", "Aislar endpoint comprometido de la red"),
            StepDef("BLOCK_IP",         "Bloquear tráfico C2 entrante y saliente"),
            StepDef("BLOCK_DOMAIN",     "Bloquear dominio C2 en DNS sinkhole"),
            StepDef("REMOVE_PERSISTENCE", "Eliminar mecanismos de persistencia en registro"),
            StepDef("NOTIFY",           "Notificar cierre de acciones al equipo"),
        ],
    ),
    "PB-004": PlaybookDefinition(
        id="PB-004",
        name="Ataque Dirigido — Environmental Keying Detectado",
        description="Malware con environmental keying específico para PremosCorp. Escalación inmediata y aislamiento condicional.",
        semaphore="red",
        requires_approval=True,
        min_risk=0.0,
        max_risk=1.0,
        steps=[
            StepDef("LOG",            "Registrar malware dirigido — environmental keying detectado"),
            StepDef("CREATE_ALERT",   "Crear alerta CRITICAL — TARGETED ATTACK en BD"),
            StepDef("NOTIFY",         "Escalación inmediata a SOC senior y CISO"),
            StepDef("AWAIT_APPROVAL", "Aprobación para aislamiento (Human-in-the-Loop)"),
            StepDef("ISOLATE_ENDPOINT", "Aislar endpoint (condicional: confidence ≥ 0.80)"),
            StepDef("BLOCK_DOMAIN",   "Bloquear dominios de C2 detectados"),
        ],
    ),
    "PB-005": PlaybookDefinition(
        id="PB-005",
        name="Respuesta de Identidad — PIDS Enforcement",
        description=(
            "Acciones de identidad vinculadas a un incidente confirmado. "
            "Deshabilita la cuenta comprometida en AD, fuerza reset de credenciales "
            "y mueve al usuario a OU de cuarentena tras aprobación del analista."
        ),
        semaphore="red",
        requires_approval=True,
        min_risk=0.0,
        max_risk=1.0,
        steps=[
            StepDef("LOG",                 "Registrar acción PIDS — identidad comprometida detectada"),
            StepDef("CREATE_ALERT",        "Crear alerta CRITICAL — Identity Compromise en BD"),
            StepDef("NOTIFY",              "Notificar al equipo SOC — acción sobre identidad pendiente"),
            StepDef("AWAIT_APPROVAL",      "Aprobación analista para acciones sobre identidad (Human-in-the-Loop)"),
            StepDef("DISABLE_ACCOUNT",     "Deshabilitar cuenta de usuario en Active Directory"),
            StepDef("FORCE_PASSWORD_RESET","Forzar cambio de contraseña en próximo inicio de sesión"),
            StepDef("QUARANTINE_ACCOUNT",  "Mover usuario a OU de cuarentena en Active Directory"),
            StepDef("NOTIFY",              "Notificar cierre de acciones PIDS al equipo"),
        ],
    ),
}


# ─── Playbook Selection ───────────────────────────────────────────────────────

def select_playbook_id(ctx: PlaybookContext) -> str:
    """Auto-select the most appropriate playbook for the given context."""
    # Fingerprint with environmental keying → always PB-004
    if ctx.trigger_source == "auto_fingerprint" and ctx.fingerprint_confidence is not None:
        if ctx.fingerprint_confidence >= 0.30:
            return "PB-004"

    # Risk-score based selection
    if ctx.risk_score >= 0.85:
        return "PB-003"
    if ctx.risk_score >= 0.40:
        return "PB-002"
    return "PB-001"


# ─── Step Executor ────────────────────────────────────────────────────────────

async def _execute_step(
    step: StepDef,
    ctx: PlaybookContext,
    run: PlaybookRun,
    db: AsyncSession,
) -> dict[str, Any]:
    """Execute a single playbook step. Returns a step_log entry dict."""
    ts = datetime.now(timezone.utc).isoformat()
    result: dict[str, Any] = {"action": step.action, "name": step.name, "status": "ok", "ts": ts}

    try:
        if step.action == "LOG":
            log.info(
                "playbook_step_log",
                playbook=run.playbook_id,
                run_id=run.id,
                semaphore=ctx.semaphore,
                risk_score=ctx.risk_score,
                host=ctx.host,
                step=step.name,
            )

        elif step.action == "CREATE_ALERT":
            sev_map = {"red": "critical", "yellow": "high", "green": "low"}
            severity = sev_map.get(ctx.semaphore, "medium")

            title = run.playbook_name
            if ctx.trigger_source == "auto_fingerprint":
                title = f"[TARGETED] {title}"

            alert = Alert(
                id=str(uuid.uuid4()),
                title=title,
                description=(
                    f"Playbook {run.playbook_id} activado. "
                    f"Semáforo: {ctx.semaphore.upper()}. "
                    f"Riesgo: {ctx.risk_score:.2f}. "
                    f"Host: {ctx.host or 'desconocido'}."
                ),
                severity=severity,
                status="open",
                risk_score=ctx.risk_score,
                affected_hosts=[ctx.host] if ctx.host else [],
                ttps=ctx.ttps,
                recommended_actions=_recommended_actions(ctx),
            )
            db.add(alert)
            await db.flush()
            run.alert_id = alert.id
            result["alert_id"] = alert.id
            log.info("playbook_alert_created", run_id=run.id, alert_id=alert.id, severity=severity)

        elif step.action == "TAG_ALERT":
            # For PB-001: if a pre-existing alert exists, mark it as monitoring
            result["detail"] = "Alert tagged as monitoring (no automated action required)"

        elif step.action == "NOTIFY":
            # Future: Slack / email / PagerDuty integration
            log.info(
                "playbook_notify",
                run_id=run.id,
                playbook=run.playbook_id,
                semaphore=ctx.semaphore,
                message=step.name,
            )
            result["detail"] = f"SOC notification queued: {step.name}"

        elif step.action == "AWAIT_APPROVAL":
            # HitL checkpoint — caller must detect status=awaiting_approval and stop
            result["status"] = "awaiting_approval"
            result["detail"] = "Execution paused — analyst approval required"
            return result

        elif step.action == "ISOLATE_ENDPOINT":
            if ctx.trigger_source == "auto_fingerprint":
                # Conditional on confidence
                conf = ctx.fingerprint_confidence or 0.0
                if conf < 0.80:
                    result["detail"] = f"Isolation skipped — confidence {conf:.2f} < 0.80"
                    return result

            host = ctx.host or "unknown"
            nr = await neutralizer.isolate_endpoint(host, reason=f"Playbook {run.playbook_id}")
            result["success"] = nr.success
            result["detail"] = nr.message
            result["neutralizer_details"] = nr.details
            if not nr.success:
                result["status"] = "warning"

        elif step.action == "BLOCK_IP":
            if not ctx.dst_ip:
                result["detail"] = "No destination IP in context — step skipped"
                return result
            nr = await neutralizer.block_ip(ctx.dst_ip, reason=f"Playbook {run.playbook_id}")
            result["success"] = nr.success
            result["detail"] = nr.message
            result["neutralizer_details"] = nr.details

        elif step.action == "BLOCK_DOMAIN":
            if not ctx.dst_domain:
                result["detail"] = "No destination domain in context — step skipped"
                return result
            nr = await neutralizer.block_domain(ctx.dst_domain, reason=f"Playbook {run.playbook_id}")
            result["success"] = nr.success
            result["detail"] = nr.message
            result["neutralizer_details"] = nr.details

        elif step.action == "REMOVE_PERSISTENCE":
            host = ctx.host or "unknown"
            nr = await neutralizer.remove_persistence(
                host,
                persistence_type="registry_run_key",
                target="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            )
            result["success"] = nr.success
            result["detail"] = nr.message
            result["neutralizer_details"] = nr.details

        elif step.action in ("DISABLE_ACCOUNT", "FORCE_PASSWORD_RESET", "QUARANTINE_ACCOUNT"):
            await _execute_identity_step(step.action, ctx, run, db, result)

        else:
            result["status"] = "warning"
            result["detail"] = f"Unknown action type: {step.action}"

    except Exception as exc:  # noqa: BLE001
        log.error("playbook_step_error", run_id=run.id, step=step.action, error=str(exc))
        result["status"] = "error"
        result["detail"] = str(exc)

    return result


async def _execute_identity_step(
    action: str,
    ctx: PlaybookContext,
    run: PlaybookRun,
    db: AsyncSession,
    result: dict,
) -> None:
    """
    Execute an identity enforcement step (DISABLE_ACCOUNT / FORCE_PASSWORD_RESET /
    QUARANTINE_ACCOUNT) via the ActiveDirectoryAdapter and create a signed
    IdentityAction forensic record via pids_service.

    Identity context is read from ctx.affected_user + ctx.affected_domain.
    If no affected_user is set in context, the step is skipped.
    """
    from asc_api.adapters.identity.active_directory import ActiveDirectoryAdapter
    from asc_api.services import pids_service

    username = ctx.affected_user
    if not username:
        result["detail"] = f"{action} skipped — no affected_user in playbook context"
        return

    domain = ctx.affected_domain or "corp.local"
    reason = f"Playbook {run.playbook_id} run {run.id}"
    ad = ActiveDirectoryAdapter()

    ad_result: dict = {}
    pids_action_type: str

    if action == "DISABLE_ACCOUNT":
        pids_action_type = "disable_account"
        ad_result = await ad.disable_account(username, domain, reason=reason)

    elif action == "FORCE_PASSWORD_RESET":
        pids_action_type = "force_password_reset"
        ad_result = await ad.force_password_reset(username, domain)

    else:  # QUARANTINE_ACCOUNT
        pids_action_type = "quarantine_account"
        ad_result = await ad.move_to_quarantine_ou(username, domain)

    success = ad_result.get("status") == "ok"
    detail = str(ad_result)

    # Create forensic record regardless of AD outcome
    identity_action = await pids_service.create_identity_action(
        db,
        action_type=pids_action_type,
        username=username,
        domain=domain,
        reason=reason,
        playbook_run_id=run.id,
        success=success,
        result_detail=detail,
        initiated_by=run.initiated_by or "soar_auto",
    )

    result["success"] = success
    result["detail"] = detail
    result["identity_action_id"] = identity_action.id
    result["forensic_hash"] = identity_action.hash_sha3_512
    if not success:
        result["status"] = "warning"

    log.info(
        "playbook_identity_step",
        run_id=run.id,
        action=action,
        username=username,
        success=success,
        identity_action_id=identity_action.id,
    )


def _recommended_actions(ctx: PlaybookContext) -> list[str]:
    if ctx.risk_score >= 0.85 or ctx.trigger_source == "auto_fingerprint":
        return neutralizer.RECOMMENDED_ACTIONS["critical"]
    if ctx.risk_score >= 0.70:
        return neutralizer.RECOMMENDED_ACTIONS["high"]
    if ctx.risk_score >= 0.40:
        return neutralizer.RECOMMENDED_ACTIONS["medium"]
    return neutralizer.RECOMMENDED_ACTIONS["low"]


# ─── Engine ───────────────────────────────────────────────────────────────────

async def _run_steps(
    run: PlaybookRun,
    pb: PlaybookDefinition,
    ctx: PlaybookContext,
    db: AsyncSession,
    start_index: int = 0,
) -> None:
    """Execute steps from start_index. Stops and saves state on AWAIT_APPROVAL."""
    steps_log: list[dict] = list(run.steps_log)

    for i, step in enumerate(pb.steps[start_index:], start=start_index):
        step_entry = await _execute_step(step, ctx, run, db)
        step_entry["step_index"] = i
        steps_log.append(step_entry)
        run.steps_log = steps_log

        if step_entry.get("status") == "awaiting_approval":
            token = str(uuid.uuid4())
            run.approval_token = token
            run.next_step_index = i + 1
            run.status = "awaiting_approval"
            await db.flush()
            log.info("playbook_awaiting_approval", run_id=run.id, token=token, next_step=i + 1)
            return

        if step_entry.get("status") == "error":
            run.status = "failed"
            run.error = step_entry.get("detail", "Unknown error")
            run.completed_at = datetime.now(timezone.utc)
            await db.flush()
            log.error("playbook_failed", run_id=run.id, step=step.action, error=run.error)
            return

    # All steps done
    run.status = "completed"
    run.completed_at = datetime.now(timezone.utc)
    run.steps_log = steps_log
    await db.flush()
    log.info("playbook_completed", run_id=run.id, playbook=run.playbook_id, steps=len(steps_log))


async def trigger_playbook(
    playbook_id: str,
    ctx: PlaybookContext,
    db: AsyncSession,
    initiated_by: str,
) -> PlaybookRun:
    """Trigger a specific playbook by ID. Creates a PlaybookRun and executes steps."""
    pb = PLAYBOOKS.get(playbook_id)
    if pb is None:
        raise ValueError(f"Unknown playbook: {playbook_id}")

    run = PlaybookRun(
        id=str(uuid.uuid4()),
        playbook_id=pb.id,
        playbook_name=pb.name,
        trigger_source=ctx.trigger_source,
        trigger_data=ctx.trigger_data,
        semaphore=ctx.semaphore,
        risk_score=ctx.risk_score,
        status="running",
        steps_log=[],
        next_step_index=0,
        initiated_by=initiated_by,
        started_at=datetime.now(timezone.utc),
    )
    db.add(run)
    await db.flush()

    log.info(
        "playbook_triggered",
        run_id=run.id,
        playbook=playbook_id,
        semaphore=ctx.semaphore,
        risk_score=ctx.risk_score,
        initiated_by=initiated_by,
    )

    await _run_steps(run, pb, ctx, db, start_index=0)
    return run


async def auto_trigger(
    ctx: PlaybookContext,
    db: AsyncSession,
    initiated_by: str = "system",
) -> PlaybookRun:
    """Auto-select playbook from context and trigger it."""
    pb_id = select_playbook_id(ctx)
    return await trigger_playbook(pb_id, ctx, db, initiated_by)


async def approve_playbook_run(
    run: PlaybookRun,
    approved_by: str,
    db: AsyncSession,
) -> PlaybookRun:
    """Resume a paused (awaiting_approval) playbook run after analyst approval."""
    if run.status != "awaiting_approval":
        raise ValueError(f"Run {run.id} is not awaiting approval (status={run.status})")

    pb = PLAYBOOKS.get(run.playbook_id)
    if pb is None:
        raise ValueError(f"Unknown playbook: {run.playbook_id}")

    # Reconstruct context from stored trigger_data
    ctx = _context_from_run(run)

    run.approved_by = approved_by
    run.approved_at = datetime.now(timezone.utc)
    run.approval_token = None
    run.status = "running"
    await db.flush()

    log.info(
        "playbook_approved",
        run_id=run.id,
        playbook=run.playbook_id,
        approved_by=approved_by,
        resume_step=run.next_step_index,
    )

    await _run_steps(run, pb, ctx, db, start_index=run.next_step_index)
    return run


async def abort_playbook_run(run: PlaybookRun, aborted_by: str, db: AsyncSession) -> PlaybookRun:
    """Abort a pending or awaiting-approval run."""
    if run.status not in ("pending", "running", "awaiting_approval"):
        raise ValueError(f"Cannot abort run with status={run.status}")

    run.status = "aborted"
    run.completed_at = datetime.now(timezone.utc)
    run.error = f"Aborted by {aborted_by}"
    await db.flush()
    log.info("playbook_aborted", run_id=run.id, aborted_by=aborted_by)
    return run


def _context_from_run(run: PlaybookRun) -> PlaybookContext:
    """Reconstruct PlaybookContext from stored trigger_data."""
    data = run.trigger_data or {}
    if run.trigger_source == "auto_fingerprint":
        return PlaybookContext.from_fingerprint(data)
    # For manual or auto_detection, rebuild minimal context
    return PlaybookContext(
        semaphore=run.semaphore,
        risk_score=run.risk_score,
        trigger_source=run.trigger_source,
        trigger_data=data,
        host=data.get("host"),
        dst_ip=data.get("dst_ip"),
        dst_domain=data.get("dst_domain"),
        process_name=data.get("process_name"),
        ttps=data.get("ttps", []),
    )


# ─── Catalog Helper ───────────────────────────────────────────────────────────

def get_playbook_catalog() -> list[dict]:
    """Return the list of available playbooks (for API /playbooks/ endpoint)."""
    return [
        {
            "id": pb.id,
            "name": pb.name,
            "description": pb.description,
            "semaphore": pb.semaphore,
            "requires_approval": pb.requires_approval,
            "min_risk": pb.min_risk,
            "max_risk": pb.max_risk,
            "step_count": len(pb.steps),
            "steps": [{"action": s.action, "name": s.name} for s in pb.steps],
        }
        for pb in PLAYBOOKS.values()
    ]
