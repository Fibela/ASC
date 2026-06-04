from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timezone
import uuid

from app.db.session import get_db
from app.models.neutralization import NeutralizationAction
from app.services.neutralizer import execute_action, RECOMMENDED_ACTIONS
from pydantic import BaseModel

router = APIRouter(prefix="/neutralize", tags=["Neutralization"])


class NeutralizeRequest(BaseModel):
    action_type: str
    target: str
    target_type: str
    params: dict = {}
    alert_id: str | None = None
    initiated_by: str | None = None
    automated: bool = False


@router.post("/", summary="Execute a neutralization action")
async def neutralize(payload: NeutralizeRequest, db: AsyncSession = Depends(get_db)):
    action = NeutralizationAction(
        id=str(uuid.uuid4()),
        alert_id=payload.alert_id,
        action_type=payload.action_type,
        target=payload.target,
        target_type=payload.target_type,
        status="executing",
        automated=payload.automated,
        initiated_by=payload.initiated_by or "system",
    )
    db.add(action)
    await db.commit()

    result = await execute_action(payload.action_type, payload.params)

    action.status = "success" if result.success else "failed"
    action.result = result.details
    action.error_message = None if result.success else result.message
    action.executed_at = datetime.now(timezone.utc)
    await db.commit()

    return {
        "action_id": action.id,
        "success":   result.success,
        "message":   result.message,
        "details":   result.details,
        "status":    action.status,
    }


@router.get("/recommended/{severity}", summary="Get recommended actions for a threat severity")
async def recommended_actions(severity: str):
    actions = RECOMMENDED_ACTIONS.get(severity.lower())
    if not actions:
        raise HTTPException(status_code=400, detail=f"Unknown severity: {severity}. Use: critical, high, medium, low")
    return {"severity": severity, "recommended_actions": actions}


@router.get("/history", summary="List past neutralization actions")
async def action_history(limit: int = 50, db: AsyncSession = Depends(get_db)):
    from sqlalchemy import select, desc
    result = await db.execute(
        select(NeutralizationAction).order_by(desc(NeutralizationAction.created_at)).limit(limit)
    )
    actions = result.scalars().all()
    return [
        {
            "id":          a.id,
            "action_type": a.action_type,
            "target":      a.target,
            "status":      a.status,
            "automated":   a.automated,
            "alert_id":    a.alert_id,
            "created_at":  a.created_at.isoformat(),
            "executed_at": a.executed_at.isoformat() if a.executed_at else None,
        }
        for a in actions
    ]
