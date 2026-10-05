"""
CyberFusion XDR Enterprise - Tamper-Resistant Cryptographic Audit Trail
Provides immutable chained SHA-256 audit records for all security-sensitive actions.
"""
import hashlib
import json
import time
from typing import Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
import logging

logger = logging.getLogger("cyberfusion.audit")

class AuditService:
    @staticmethod
    def calculate_record_hash(prev_hash: str, payload: Dict[str, Any]) -> str:
        serialized = json.dumps(payload, sort_keys=True, default=str)
        to_hash = f"{prev_hash}::{serialized}"
        return hashlib.sha256(to_hash.encode("utf-8")).hexdigest()

    @staticmethod
    async def log_action(
        db: AsyncSession,
        actor: str,
        action: str,
        target: str,
        result: str,
        source_ip: str = "127.0.0.1",
        tenant_id: str = "tenant-enterprise-secops",
        approval: Optional[str] = None,
        previous_value: Optional[Dict[str, Any]] = None,
        new_value: Optional[Dict[str, Any]] = None,
        mode: str = "LIVE"
    ):
        from app.models.models import AuditRecord
        
        # Get latest record hash for cryptographic chaining
        stmt = select(AuditRecord).order_by(desc(AuditRecord.id)).limit(1)
        res = await db.execute(stmt)
        last_rec = res.scalar_one_or_none()
        prev_hash = last_rec.current_hash if last_rec else "GENESIS_CYBERFUSION_ENTERPRISE_ROOT_HASH_00000000"

        payload = {
            "actor": actor,
            "action": action,
            "target": target,
            "result": result,
            "source_ip": source_ip,
            "tenant_id": tenant_id,
            "approval": approval,
            "previous_value": previous_value,
            "new_value": new_value,
            "timestamp": time.time(),
            "mode": mode
        }
        
        current_hash = AuditService.calculate_record_hash(prev_hash, payload)

        record = AuditRecord(
            actor=actor,
            action=action,
            target=target,
            result=result,
            source_ip=source_ip,
            tenant_id=tenant_id,
            approval=approval,
            previous_value=json.dumps(previous_value) if previous_value else None,
            new_value=json.dumps(new_value) if new_value else None,
            prev_hash=prev_hash,
            current_hash=current_hash,
            mode=mode,
            timestamp=payload["timestamp"]
        )
        db.add(record)
        await db.commit()
        logger.info(f"Audit log created: {actor} performed {action} on {target} -> {result} [Hash: {current_hash[:12]}...]")
        return record
