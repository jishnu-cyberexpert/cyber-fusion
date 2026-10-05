"""
CyberFusion XDR Enterprise - Threat Intelligence Platform (TIP / CTI) APIs
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from app.core.database import get_db
from app.models.models import CorrelatedThreat
from typing import Dict, Any, List, Optional
from app.services.tip_service import ThreatIntelService, ACTIVE_IOCS
from app.services.virustotal_service import virustotal_service

router = APIRouter()

@router.get("/virustotal/status")
async def get_virustotal_status():
    """Retrieve real-time VirusTotal Free Tier quota allowances, rate limiting, and cache metrics."""
    return virustotal_service.get_quota_status()

@router.get("/iocs")
async def get_iocs(limit: int = 100):
    """List active verified indicators of compromise (IOCs)."""
    return ThreatIntelService.list_iocs(limit=limit)

@router.get("/lookup")
async def lookup_indicator(ioc_type: str, value: str):
    """Check a specific IP, domain, or SHA256 against enterprise CTI and live VirusTotal intelligence."""
    t = ioc_type.lower().strip()
    v = value.strip()
    
    table = ACTIVE_IOCS.get(t)
    if not table and t not in ["ip", "domain", "sha256", "hash", "url"]:
        raise HTTPException(status_code=400, detail=f"Unsupported IOC type: {ioc_type}")

    internal_match = table.get(v.lower()) if table else None

    # Query VirusTotal with rate limiting and 24h caching
    vt_result = None
    if virustotal_service.is_configured and t in ["ip", "domain", "sha256", "hash"]:
        try:
            vt_result = await virustotal_service.lookup_indicator(t, v, wait_if_needed=True)
            # If VirusTotal flagged it as confirmed malicious, dynamically seed it into active IOC cache
            if vt_result.get("is_malicious"):
                stats = vt_result.get("stats", {})
                ThreatIntelService.add_ioc(t, v, {
                    "threat_actor": vt_result.get("as_owner") or "Known Malicious Actor",
                    "campaign": f"VirusTotal Detection ({vt_result.get('detection_ratio', '')})",
                    "malware_family": ", ".join(vt_result.get("tags", [])[:3]) or "Malware/C2",
                    "severity": "CRITICAL" if stats.get("malicious", 0) >= 5 else "HIGH",
                    "confidence": min(1.0, 0.7 + (stats.get("malicious", 0) * 0.03)),
                    "source": f"VirusTotal v3 Intelligence ({vt_result.get('detection_ratio')})",
                    "tags": vt_result.get("tags", []) + ["virustotal", "auto-enriched"]
                })
        except Exception as vt_err:
            vt_result = {"error": str(vt_err)}

    is_found = bool(internal_match or (vt_result and vt_result.get("is_malicious")))

    return {
        "found": is_found,
        "query": {"type": ioc_type, "value": value},
        "indicator": internal_match,
        "virustotal": vt_result
    }

@router.post("/iocs")
async def add_custom_ioc(payload: Dict[str, Any]):
    """Add a verified threat indicator to the real-time enrichment index."""
    ioc_type = payload.get("ioc_type")
    value = payload.get("value")
    if not ioc_type or not value:
        raise HTTPException(status_code=400, detail="ioc_type and value are required")

    record = ThreatIntelService.add_ioc(ioc_type, value, payload)
    return {"status": "ADDED", "record": record}


@router.get("/correlated")
async def get_correlated_threats(db: AsyncSession = Depends(get_db)):
    """Fetch zero-false-positive correlated threats identified in the environment."""
    result = await db.execute(
        select(CorrelatedThreat)
        .order_by(desc(CorrelatedThreat.created_at))
        .limit(100)
    )
    return result.scalars().all()
