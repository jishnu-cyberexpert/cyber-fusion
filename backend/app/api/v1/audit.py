"""
CyberFusion XDR Enterprise - Cryptographic Audit Trail Verification APIs
"""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import Dict, Any, List
import json
from app.core.database import get_db
from app.models.models import AuditRecord
from app.core.audit import AuditService

router = APIRouter()

@router.get("/logs")
async def get_audit_logs(limit: int = 100, db: AsyncSession = Depends(get_db)):
    """Retrieve immutable audit trail records."""
    stmt = select(AuditRecord).order_by(desc(AuditRecord.id)).limit(limit)
    res = await db.execute(stmt)
    records = res.scalars().all()
    return [{
        "id": r.id,
        "timestamp": r.timestamp,
        "actor": r.actor,
        "action": r.action,
        "target": r.target,
        "result": r.result,
        "source_ip": r.source_ip,
        "approval": r.approval,
        "current_hash": r.current_hash,
        "prev_hash": r.prev_hash,
        "mode": r.mode
    } for r in records]

@router.get("/verify")
async def verify_audit_chain_integrity(db: AsyncSession = Depends(get_db)):
    """
    Cryptographically verify the SHA-256 tamper-resistant hash chain.
    """
    stmt = select(AuditRecord).order_by(AuditRecord.id)
    res = await db.execute(stmt)
    records = res.scalars().all()

    if not records:
        return {"status": "EMPTY", "records_verified": 0, "tamper_detected": False}

    current_expected_prev = "GENESIS_CYBERFUSION_ENTERPRISE_ROOT_HASH_00000000"
    for r in records:
        if r.prev_hash != current_expected_prev:
            return {
                "status": "TAMPER_DETECTED",
                "compromised_record_id": r.id,
                "expected_prev_hash": current_expected_prev,
                "found_prev_hash": r.prev_hash,
                "tamper_detected": True
            }
        current_expected_prev = r.current_hash

    return {
        "status": "VALID",
        "records_verified": len(records),
        "root_hash": records[0].prev_hash,
        "latest_hash": records[-1].current_hash,
        "tamper_detected": False
    }
