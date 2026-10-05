"""
CyberFusion XDR Enterprise - SIEM Telemetry & MongoDB Log API
Provides endpoints to query real-time security telemetry logs from MongoDB Atlas (with SQLite fallback)
and to monitor MongoDB injection status.
"""
from fastapi import APIRouter, Depends, Query, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, or_
from typing import Dict, Any, List, Optional
import time
from app.core.database import get_db
from app.models.models import SecurityEvent
from app.services.mongodb_service import mongodb_service

router = APIRouter()

@router.get("/events")
async def get_siem_events(
    mode: str = Query("LIVE", description="Environment mode: LIVE, LAB, DEMO"),
    limit: int = Query(100, ge=1, le=500),
    data_source: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db)
):
    """
    Retrieve real-time normalized SIEM telemetry logs.
    Queries MongoDB Atlas as the primary high-throughput document store.
    Gracefully falls back to SQLite if MongoDB Atlas is empty or unreachable.
    """
    # 1. Try querying MongoDB Atlas
    mongo_logs = []
    if mongodb_service.is_connected:
        try:
            mongo_logs = await mongodb_service.get_recent_logs(
                mode=mode,
                limit=limit,
                data_source=data_source,
                search=search
            )
        except Exception:
            mongo_logs = []

    if mongo_logs:
        return {
            "status": "SUCCESS",
            "storage_backend": "MONGODB_ATLAS",
            "count": len(mongo_logs),
            "events": mongo_logs
        }

    # 2. Fallback to SQLite relational data plane
    stmt = select(SecurityEvent).where(SecurityEvent.mode == mode)
    if data_source and data_source != "ALL":
        stmt = stmt.where(SecurityEvent.data_source == data_source)
    if search:
        s = f"%{search.strip().lower()}%"
        stmt = stmt.where(
            or_(
                SecurityEvent.process_name.ilike(s),
                SecurityEvent.command_line.ilike(s),
                SecurityEvent.user_identity.ilike(s),
                SecurityEvent.hostname.ilike(s),
                SecurityEvent.source_ip.ilike(s),
                SecurityEvent.dest_ip.ilike(s),
                SecurityEvent.category.ilike(s),
                SecurityEvent.action.ilike(s)
            )
        )
    stmt = stmt.order_by(desc(SecurityEvent.timestamp)).limit(limit)
    res = await db.execute(stmt)
    records = res.scalars().all()

    fallback_logs = []
    for r in records:
        fallback_logs.append({
            "event_uuid": r.event_uuid,
            "uuid": r.event_uuid,
            "timestamp": r.timestamp,
            "data_source": r.data_source,
            "category": r.category,
            "action": r.action or "activity",
            "severity": r.severity,
            "hostname": r.hostname or "Internal",
            "user": r.user_identity,
            "user_identity": r.user_identity,
            "process": r.process_name,
            "process_name": r.process_name,
            "pid": r.process_pid,
            "command_line": r.command_line or "",
            "source_ip": r.source_ip,
            "dest_ip": r.dest_ip,
            "dest_port": r.dest_port,
            "file_path": r.file_path,
            "domain": r.domain,
            "is_alert": r.is_alert,
            "storage_backend": "SQLITE_DATA_PLANE"
        })

    return {
        "status": "SUCCESS",
        "storage_backend": "SQLITE_FALLBACK",
        "count": len(fallback_logs),
        "events": fallback_logs
    }

@router.get("/status")
async def get_siem_status(db: AsyncSession = Depends(get_db)):
    """
    Returns real-time status of the SIEM pipeline, MongoDB Atlas injection,
    and storage document counts.
    """
    mongo_status = await mongodb_service.get_status()

    # Get SQLite event count
    from sqlalchemy import func
    res = await db.execute(select(func.count(SecurityEvent.id)))
    sqlite_count = res.scalar() or 0

    return {
        "siem_plane": "ACTIVE",
        "mongodb_atlas": mongo_status,
        "sqlite_events_stored": sqlite_count,
        "active_primary_storage": "MONGODB_ATLAS" if mongo_status["connected"] else "SQLITE"
    }

@router.post("/sync-mongodb")
async def sync_logs_to_mongodb(
    limit: int = Query(500, ge=10, le=5000),
    db: AsyncSession = Depends(get_db)
):
    """
    Backfills existing logs from SQLite into MongoDB Atlas.
    Useful for populating Atlas with existing enterprise security telemetry.
    """
    if not mongodb_service.is_connected:
        ok = await mongodb_service.connect()
        if not ok:
            return {
                "status": "ERROR",
                "message": "Cannot connect to MongoDB Atlas. Check credentials in .env"
            }

    stmt = select(SecurityEvent).order_by(desc(SecurityEvent.timestamp)).limit(limit)
    res = await db.execute(stmt)
    records = res.scalars().all()

    events_to_sync = []
    for r in records:
        events_to_sync.append({
            "event_uuid": r.event_uuid,
            "timestamp": r.timestamp,
            "tenant_id": r.tenant_id,
            "mode": r.mode,
            "data_source": r.data_source,
            "category": r.category,
            "action": r.action or "activity",
            "severity": r.severity,
            "hostname": r.hostname,
            "user_identity": r.user_identity,
            "process_name": r.process_name,
            "process_pid": r.process_pid,
            "parent_process": r.parent_process,
            "command_line": r.command_line,
            "source_ip": r.source_ip,
            "dest_ip": r.dest_ip,
            "source_port": r.source_port,
            "dest_port": r.dest_port,
            "protocol": r.protocol,
            "file_path": r.file_path,
            "file_hash": r.file_hash,
            "domain": r.domain,
            "url": r.url,
            "raw_payload": r.raw_payload,
            "is_alert": r.is_alert
        })

    injected = await mongodb_service.insert_logs_batch(events_to_sync)
    total_in_mongo = await mongodb_service.count_logs()

    return {
        "status": "SUCCESS",
        "synced_count": injected,
        "total_mongodb_logs": total_in_mongo,
        "message": f"Successfully injected {injected} logs into MongoDB Atlas!"
    }
