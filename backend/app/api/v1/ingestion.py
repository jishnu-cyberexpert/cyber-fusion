"""
CyberFusion XDR Enterprise - Real-Time Telemetry Ingestion APIs
Accepts telemetry from agents, network collectors, firewalls, and HTTP Event Collectors (HEC).
"""
from fastapi import APIRouter, Depends, HTTPException, Header, Request
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Dict, Any, List, Optional
from app.schemas.schemas import RawTelemetryBatch
from app.services.pipeline import PipelineOrchestrator
from app.core.config import settings
import json
import logging

logger = logging.getLogger("cyberfusion.ingest")

router = APIRouter()

@router.post("/telemetry")
async def ingest_telemetry_batch(
    batch: RawTelemetryBatch,
    authorization: Optional[str] = Header(None),
    x_cyberfusion_api_key: Optional[str] = Header(None)
):
    """
    Primary real-time telemetry ingestion endpoint for EDR agents and collectors.
    """
    # Enforce agent authentication if configured
    if x_cyberfusion_api_key and x_cyberfusion_api_key != settings.AGENT_AUTH_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized agent ingestion key")

    results = []
    for event_data in batch.events:
        res = await PipelineOrchestrator.process_raw_event(
            raw_event=event_data,
            data_source=batch.data_source,
            mode=batch.mode,
            tenant_id=batch.tenant_id
        )
        results.append(res)

    return {
        "status": "ACCEPTED",
        "events_ingested": len(results),
        "mode": batch.mode,
        "tenant_id": batch.tenant_id
    }

@router.post("/syslog")
async def ingest_syslog_message(request: Request):
    """
    Ingest raw Syslog, CEF, or LEEF lines via HTTP POST.
    """
    body = await request.body()
    text = body.decode("utf-8", errors="ignore")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    
    processed = 0
    for line in lines:
        raw_event = {"raw": line, "action": "syslog_received", "category": "network"}
        if "CEF:" in line:
            raw_event["category"] = "security_appliance"
        await PipelineOrchestrator.process_raw_event(
            raw_event=raw_event,
            data_source="SYSLOG",
            mode="LIVE"
        )
        processed += 1

    return {"status": "INGESTED", "records": processed}

@router.post("/hec")
async def ingest_splunk_hec_compatible(request: Request):
    """
    Splunk HEC compatible endpoint for existing enterprise log shippers.
    """
    try:
        payload = await request.json()
    except Exception:
        raw = await request.body()
        payload = {"event": raw.decode("utf-8", errors="ignore")}

    raw_event = payload.get("event") if isinstance(payload, dict) and "event" in payload else payload
    if not isinstance(raw_event, dict):
        raw_event = {"raw": str(raw_event), "category": "log_shipper"}

    res = await PipelineOrchestrator.process_raw_event(
        raw_event=raw_event,
        data_source="HEC_COLLECTOR",
        mode="LIVE"
    )
    return {"text": "Success", "code": 0, "event_uuid": res.get("event_uuid")}
