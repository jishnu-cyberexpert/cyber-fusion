"""
CyberFusion XDR Enterprise - Incident Response & Case Management APIs
Full enterprise incident lifecycle: Triage -> Investigation -> Containment -> Eradication -> Closure.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import Dict, Any, List, Optional
import time
import json
import uuid
from app.core.database import get_db
from app.models.models import Incident, IncidentNote, IncidentEvidence, Alert
from app.schemas.schemas import IncidentCreateRequest, IncidentNoteRequest
from app.core.audit import AuditService

router = APIRouter()

@router.get("")
async def list_incidents(
    tenant_id: str = "tenant-enterprise-secops",
    mode: str = "LIVE",
    status_filter: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """List correlated enterprise security incidents."""
    stmt = select(Incident).where(
        Incident.tenant_id == tenant_id,
        Incident.mode == mode
    ).order_by(desc(Incident.created_at))
    
    if status_filter:
        stmt = stmt.where(Incident.status == status_filter)

    res = await db.execute(stmt)
    incidents = res.scalars().all()

    output = []
    for inc in incidents:
        output.append({
            "incident_id": inc.incident_id,
            "title": inc.title,
            "description": inc.description,
            "severity": inc.severity,
            "status": inc.status,
            "assignee": inc.assignee,
            "mitre_tactics": json.loads(inc.mitre_tactics or "[]"),
            "entities": json.loads(inc.entities or "{}"),
            "evidence_count": inc.evidence_count,
            "sla_deadline": inc.sla_deadline,
            "created_at": inc.created_at,
            "updated_at": inc.updated_at
        })
    return output

@router.get("/{incident_id}")
async def get_incident_detail(incident_id: str, db: AsyncSession = Depends(get_db)):
    """Retrieve complete incident case file with related alerts, evidence, and notes."""
    stmt = select(Incident).where(Incident.incident_id == incident_id)
    res = await db.execute(stmt)
    inc = res.scalar_one_or_none()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident case not found")

    # Fetch notes
    notes_stmt = select(IncidentNote).where(IncidentNote.incident_id == incident_id).order_by(desc(IncidentNote.timestamp))
    notes_res = await db.execute(notes_stmt)
    notes = [{"id": n.id, "author": n.author, "note": n.note, "timestamp": n.timestamp} for n in notes_res.scalars().all()]

    # Fetch evidence
    ev_stmt = select(IncidentEvidence).where(IncidentEvidence.incident_id == incident_id).order_by(desc(IncidentEvidence.collected_at))
    ev_res = await db.execute(ev_stmt)
    evidence = [{
        "evidence_id": e.evidence_id,
        "name": e.name,
        "type": e.evidence_type,
        "sha256": e.sha256_hash,
        "source_host": e.source_host,
        "collected_by": e.collected_by,
        "collected_at": e.collected_at,
        "file_size_bytes": e.file_size_bytes
    } for e in ev_res.scalars().all()]

    # Fetch alerts associated with this incident
    alerts_stmt = select(Alert).where(Alert.incident_id == incident_id)
    alerts_res = await db.execute(alerts_stmt)
    alerts = [{
        "alert_id": a.alert_id,
        "title": a.title,
        "severity": a.severity,
        "confidence": a.confidence,
        "rule_id": a.rule_id,
        "mitre_technique": a.mitre_technique,
        "mitre_tactic": a.mitre_tactic,
        "affected_host": a.affected_host,
        "affected_user": a.affected_user,
        "created_at": a.created_at
    } for a in alerts_res.scalars().all()]

    return {
        "incident_id": inc.incident_id,
        "tenant_id": inc.tenant_id,
        "mode": inc.mode,
        "title": inc.title,
        "description": inc.description,
        "severity": inc.severity,
        "status": inc.status,
        "assignee": inc.assignee,
        "mitre_tactics": json.loads(inc.mitre_tactics or "[]"),
        "entities": json.loads(inc.entities or "{}"),
        "created_at": inc.created_at,
        "sla_deadline": inc.sla_deadline,
        "notes": notes,
        "evidence": evidence,
        "alerts": alerts
    }

@router.patch("/{incident_id}/status")
async def update_incident_status(
    incident_id: str,
    payload: Dict[str, Any],
    db: AsyncSession = Depends(get_db)
):
    """Transition incident status: TRIAGE -> INVESTIGATING -> CONTAINED -> ERADICATED -> CLOSED."""
    stmt = select(Incident).where(Incident.incident_id == incident_id)
    res = await db.execute(stmt)
    inc = res.scalar_one_or_none()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    old_status = inc.status
    new_status = payload.get("status")
    assignee = payload.get("assignee")
    
    if new_status:
        inc.status = new_status
    if assignee:
        inc.assignee = assignee
    inc.updated_at = time.time()
    
    if new_status == "CLOSED":
        inc.closed_at = time.time()

    await db.commit()

    await AuditService.log_action(
        db=db,
        actor=payload.get("actor", "SecOps Lead"),
        action="INCIDENT_STATUS_CHANGE",
        target=incident_id,
        result=f"{old_status} -> {new_status}",
        previous_value={"status": old_status},
        new_value={"status": new_status, "assignee": assignee}
    )

    return {"status": "UPDATED", "incident_id": incident_id, "current_status": inc.status}

@router.post("/{incident_id}/notes")
async def add_incident_note(incident_id: str, req: IncidentNoteRequest, db: AsyncSession = Depends(get_db)):
    """Add analyst collaboration and forensic case notes."""
    note = IncidentNote(
        incident_id=incident_id,
        author="SecOps Analyst",
        note=req.note,
        timestamp=time.time()
    )
    db.add(note)
    await db.commit()
    return {"status": "NOTE_ADDED", "note_id": note.id}
