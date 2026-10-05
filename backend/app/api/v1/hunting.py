"""
CyberFusion XDR Enterprise - Live Threat Hunting Query API
Allows analysts to search and filter real stored telemetry using structured criteria.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, or_
from typing import Dict, Any, List, Optional
import time
import json
from app.core.database import get_db
from app.models.models import SecurityEvent
from app.schemas.schemas import ThreatHuntingQuery

router = APIRouter()

SAVED_HUNTS = [
    {
        "id": "HUNT-01",
        "name": "PowerShell Hidden Execution & Script Cradles",
        "description": "Finds instances of PowerShell invoked with bypass or encoded commands.",
        "query": "process_name = powershell.exe AND command_line LIKE %bypass%",
        "tactic": "Execution"
    },
    {
        "id": "HUNT-02",
        "name": "Outbound Connections to Non-Standard Ports",
        "description": "Searches for outbound TCP connections exceeding standard web ports.",
        "query": "dest_port NOT IN (80, 443, 53)",
        "tactic": "Command and Control"
    },
    {
        "id": "HUNT-03",
        "name": "Suspicious Reconnaissance Discovery Commands",
        "description": "Searches for whoami, net user, nltest, systeminfo, ipconfig.",
        "query": "process_name IN (whoami.exe, net.exe, nltest.exe)",
        "tactic": "Discovery"
    },
    {
        "id": "HUNT-04",
        "name": "Sensitive File Extension Access (DLP Hunt)",
        "description": "Searches for access to .kdbx, .pem, id_rsa, .docx, passwords.txt.",
        "query": "file_path LIKE %.pem OR file_path LIKE %id_rsa%",
        "tactic": "Credential Access"
    }
]

@router.get("/saved")
async def get_saved_hunts():
    """Retrieve curated enterprise hunting packages."""
    return SAVED_HUNTS

@router.post("/query")
async def execute_hunt(query: ThreatHuntingQuery, db: AsyncSession = Depends(get_db)):
    """
    Execute real-time query across telemetry database.
    """
    now = time.time()
    min_time = now - (query.time_window_minutes * 60)
    
    stmt = select(SecurityEvent).where(
        SecurityEvent.mode == query.mode,
        SecurityEvent.timestamp >= min_time
    ).order_by(desc(SecurityEvent.timestamp)).limit(query.limit)

    qs = query.query_string.strip().lower()
    
    # Simple search parser
    if qs and qs != "*":
        stmt = stmt.where(
            or_(
                SecurityEvent.process_name.ilike(f"%{qs}%"),
                SecurityEvent.command_line.ilike(f"%{qs}%"),
                SecurityEvent.user_identity.ilike(f"%{qs}%"),
                SecurityEvent.hostname.ilike(f"%{qs}%"),
                SecurityEvent.source_ip.ilike(f"%{qs}%"),
                SecurityEvent.dest_ip.ilike(f"%{qs}%"),
                SecurityEvent.domain.ilike(f"%{qs}%"),
                SecurityEvent.file_path.ilike(f"%{qs}%"),
                SecurityEvent.raw_payload.ilike(f"%{qs}%")
            )
        )

    res = await db.execute(stmt)
    records = res.scalars().all()

    results = []
    for r in records:
        results.append({
            "event_uuid": r.event_uuid,
            "timestamp": r.timestamp,
            "data_source": r.data_source,
            "category": r.category,
            "action": r.action,
            "hostname": r.hostname,
            "user": r.user_identity,
            "process": r.process_name,
            "pid": r.process_pid,
            "command_line": r.command_line,
            "source_ip": r.source_ip,
            "dest_ip": r.dest_ip,
            "dest_port": r.dest_port,
            "file_path": r.file_path,
            "domain": r.domain,
            "is_alert": r.is_alert
        })

    return {
        "matched_count": len(results),
        "query_string": query.query_string,
        "time_window_minutes": query.time_window_minutes,
        "mode": query.mode,
        "results": results
    }
