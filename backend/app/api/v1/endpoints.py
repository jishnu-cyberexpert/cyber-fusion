"""
CyberFusion XDR Enterprise - Endpoint Security & Agent Management APIs
Handles real endpoint agent registration, TLS token issuance, heartbeats, task dispatch, and isolation.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from typing import Dict, Any, List
import uuid
import time
import json
from app.core.database import get_db
from app.models.models import Endpoint
from app.schemas.schemas import AgentRegistrationRequest, AgentHeartbeatRequest, AgentCommandTask
from app.core.audit import AuditService

router = APIRouter()

@router.post("/register")
async def register_endpoint_agent(req: AgentRegistrationRequest, db: AsyncSession = Depends(get_db)):
    """
    Registers a live endpoint host into the EDR fleet management plane.
    """
    agent_id = f"CF-AGT-{uuid.uuid4().hex[:8].upper()}"
    
    # Check if host already registered
    stmt = select(Endpoint).where(Endpoint.hostname == req.hostname)
    res = await db.execute(stmt)
    existing = res.scalar_one_or_none()
    
    if existing:
        existing.agent_version = req.agent_version
        existing.ip_address = req.ip_address
        existing.last_seen = time.time()
        existing.status = "ONLINE"
        await db.commit()
        return {
            "status": "RE_REGISTERED",
            "agent_id": existing.agent_id,
            "policy": {
                "telemetry_interval_sec": 5,
                "process_monitoring": True,
                "network_monitoring": True,
                "file_integrity_monitoring": True
            }
        }

    endpoint = Endpoint(
        agent_id=agent_id,
        tenant_id=req.tenant_id,
        hostname=req.hostname,
        os_type=req.os_type,
        os_version=req.os_version or "Unknown",
        ip_address=req.ip_address or "127.0.0.1",
        mac_address=req.mac_address or "00:00:00:00:00:00",
        agent_version=req.agent_version,
        status="ONLINE",
        isolation_status=False,
        registered_at=time.time(),
        last_seen=time.time(),
        pending_tasks="[]"
    )
    db.add(endpoint)
    await db.commit()

    return {
        "status": "REGISTERED",
        "agent_id": agent_id,
        "policy": {
            "telemetry_interval_sec": 5,
            "process_monitoring": True,
            "network_monitoring": True,
            "file_integrity_monitoring": True
        }
    }

@router.post("/heartbeat")
async def agent_heartbeat(req: AgentHeartbeatRequest, db: AsyncSession = Depends(get_db)):
    """
    Receive heartbeat from live endpoint agent and return any pending tasks (containment, termination).
    """
    stmt = select(Endpoint).where(Endpoint.agent_id == req.agent_id)
    res = await db.execute(stmt)
    endpoint = res.scalar_one_or_none()

    if not endpoint:
        raise HTTPException(status_code=404, detail="Agent not registered")

    endpoint.last_seen = time.time()
    endpoint.cpu_percent = req.cpu_percent
    endpoint.memory_percent = req.memory_percent
    endpoint.status = "ISOLATED" if endpoint.isolation_status else "ONLINE"

    # Fetch and clear pending tasks
    pending = json.loads(endpoint.pending_tasks or "[]")
    endpoint.pending_tasks = "[]"
    await db.commit()

    return {
        "status": "ACK",
        "isolation_enforced": endpoint.isolation_status,
        "tasks": pending
    }

@router.get("")
async def list_endpoints(tenant_id: str = "tenant-enterprise-secops", db: AsyncSession = Depends(get_db)):
    """
    List all registered endpoints in fleet with real-time operational status.
    """
    stmt = select(Endpoint).where(Endpoint.tenant_id == tenant_id)
    res = await db.execute(stmt)
    endpoints = res.scalars().all()

    now = time.time()
    fleet = []
    for ep in endpoints:
        # If no heartbeat within 40 seconds, mark OFFLINE
        is_online = (now - ep.last_seen) < 40
        status_label = "ISOLATED" if ep.isolation_status else ("ONLINE" if is_online else "OFFLINE")
        fleet.append({
            "agent_id": ep.agent_id,
            "hostname": ep.hostname,
            "os_type": ep.os_type,
            "os_version": ep.os_version,
            "ip_address": ep.ip_address,
            "mac_address": ep.mac_address,
            "agent_version": ep.agent_version,
            "status": status_label,
            "isolation_status": ep.isolation_status,
            "cpu_percent": ep.cpu_percent,
            "memory_percent": ep.memory_percent,
            "last_seen": ep.last_seen,
            "last_seen_seconds_ago": round(now - ep.last_seen, 1)
        })

    return fleet

@router.post("/{agent_id}/task")
async def dispatch_agent_task(agent_id: str, task: AgentCommandTask, db: AsyncSession = Depends(get_db)):
    """
    Dispatch interactive forensic or containment command to a live endpoint.
    """
    stmt = select(Endpoint).where(Endpoint.agent_id == agent_id)
    res = await db.execute(stmt)
    endpoint = res.scalar_one_or_none()

    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint agent not found")

    tasks = json.loads(endpoint.pending_tasks or "[]")
    tasks.append({
        "task_id": task.task_id or f"TSK-{int(time.time())}",
        "action": task.action,
        "parameters": task.parameters,
        "created_at": time.time()
    })
    
    if task.action == "ISOLATE_ENDPOINT":
        endpoint.isolation_status = True
        endpoint.status = "ISOLATED"
    elif task.action == "DEISOLATE_ENDPOINT":
        endpoint.isolation_status = False
        endpoint.status = "ONLINE"

    endpoint.pending_tasks = json.dumps(tasks)
    await db.commit()

    await AuditService.log_action(
        db=db,
        actor="SecOps Analyst",
        action=f"DISPATCH_AGENT_TASK::{task.action}",
        target=endpoint.hostname,
        result="DISPATCHED_TO_QUEUE",
        new_value=task.parameters
    )

    return {"status": "TASK_DISPATCHED", "agent_id": agent_id, "action": task.action}
