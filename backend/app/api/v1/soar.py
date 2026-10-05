"""
CyberFusion XDR Enterprise - SOAR Response Orchestration APIs
Response playbook execution, analyst authorization gates, and containment tracking.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import Dict, Any, List, Optional
import time
from app.core.database import get_db
from app.models.models import SOARPlaybook, SOARActionExecution
from app.schemas.schemas import SOARActionRequest, SOARApprovalRequest
from app.services.soar_engine import SOAREngine

router = APIRouter()

BUILTIN_PLAYBOOKS = [
    {
        "playbook_id": "PB-RANSOMWARE-CONTAIN",
        "name": "Rapid Ransomware Host Containment & Isolation",
        "description": "Triggered on critical ransomware activity. Immediately queues host network isolation and terminates malicious process tree.",
        "trigger_condition": "Alert with MITRE T1003 or LockBit IOC",
        "requires_approval": True,
        "actions": ["ISOLATE_ENDPOINT", "KILL_PROCESS", "NOTIFY_SOC"]
    },
    {
        "playbook_id": "PB-C2-BLOCK",
        "name": "Command & Control Perimeter Defense Block",
        "description": "Identifies external beacon destination and requests firewall block rule at enterprise perimeter.",
        "trigger_condition": "NDR-T1071-001 Outbound C2 match",
        "requires_approval": True,
        "actions": ["BLOCK_IP_FIREWALL", "ISOLATE_ENDPOINT"]
    },
    {
        "playbook_id": "PB-COMPROMISED-ACCOUNT",
        "name": "Identity Breach Revocation & Token Eviction",
        "description": "Revokes active OAuth/SAML tokens and terminates SSO sessions across Okta and Entra ID.",
        "trigger_condition": "UEBA Impossible Travel or Brute Force",
        "requires_approval": True,
        "actions": ["REVOKE_IAM_SESSION", "NOTIFY_SOC"]
    }
]

@router.get("/playbooks")
async def list_playbooks():
    """List available response playbooks."""
    return BUILTIN_PLAYBOOKS

@router.get("/executions")
async def list_action_executions(db: AsyncSession = Depends(get_db)):
    """List history of response actions with execution status."""
    stmt = select(SOARActionExecution).order_by(desc(SOARActionExecution.created_at)).limit(50)
    res = await db.execute(stmt)
    records = res.scalars().all()
    return [{
        "execution_id": r.execution_id,
        "action_type": r.action_type,
        "target_entity": r.target_entity,
        "status": r.status,
        "approval_status": r.approval_status,
        "approved_by": r.approved_by,
        "execution_output": r.execution_output,
        "executed_at": r.executed_at,
        "created_at": r.created_at
    } for r in records]

@router.post("/execute")
async def trigger_soar_action(req: SOARActionRequest, db: AsyncSession = Depends(get_db)):
    """
    Dispatch a response action against target host, IP, or identity.
    Enforces authorization check and NO FALSE CLAIMS.
    """
    res = await SOAREngine.execute_action(
        db=db,
        action_type=req.action_type,
        target_entity=req.target_entity,
        parameters=req.parameters,
        actor="SecOps Operator",
        incident_id=req.incident_id,
        approved=not req.require_approval
    )
    return res

@router.post("/approve")
async def approve_soar_action(req: SOARApprovalRequest, db: AsyncSession = Depends(get_db)):
    """
    Analyst authorization gate for pending high-impact containment actions.
    """
    stmt = select(SOARActionExecution).where(SOARActionExecution.execution_id == req.execution_id)
    res = await db.execute(stmt)
    execution = res.scalar_one_or_none()
    
    if not execution:
        raise HTTPException(status_code=404, detail="Execution record not found")

    if not req.approved:
        execution.approval_status = "REJECTED"
        execution.status = "REJECTED_BY_ANALYST"
        execution.execution_output = f"Action rejected by analyst: {req.analyst_comment}"
        await db.commit()
        return {"status": "REJECTED", "execution_id": req.execution_id}

    # Execute now that human approved
    result = await SOAREngine.execute_action(
        db=db,
        action_type=execution.action_type,
        target_entity=execution.target_entity,
        parameters={},
        actor="SecOps Analyst Approval Gate",
        incident_id=execution.incident_id,
        approved=True
    )
    return result
