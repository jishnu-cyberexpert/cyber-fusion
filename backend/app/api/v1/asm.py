"""
CyberFusion XDR Enterprise - Attack Surface Management (ASM) APIs
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import Dict, Any, List
import json
import time
from app.core.database import get_db
from app.models.models import ASMAsset
from app.schemas.schemas import ASMScanRequest
from app.services.asm_scanner import ASMScanner

router = APIRouter()

@router.get("/assets")
async def list_asm_assets(db: AsyncSession = Depends(get_db)):
    """List discovered attack surface assets and open exposures."""
    stmt = select(ASMAsset).order_by(desc(ASMAsset.risk_score)).limit(50)
    res = await db.execute(stmt)
    assets = res.scalars().all()
    return [{
        "id": a.id,
        "target": a.asset_target,
        "type": a.asset_type,
        "resolved_ip": a.resolved_ip,
        "open_ports": json.loads(a.open_ports or "[]"),
        "ssl_cert_issuer": a.ssl_cert_issuer,
        "ssl_cert_expiry": a.ssl_cert_expiry,
        "risk_score": a.risk_score,
        "last_scanned": a.last_scanned
    } for a in assets]

@router.post("/scan")
async def trigger_authorized_scan(req: ASMScanRequest, db: AsyncSession = Depends(get_db)):
    """
    Execute scoped attack surface scan against specified domain or IP.
    Requires explicit scope confirmation.
    """
    if not req.scope_confirmed:
        raise HTTPException(status_code=400, detail="Explicit authorization scope confirmation is mandatory for ASM discovery.")

    result = ASMScanner.inspect_target(req.target, scope_confirmed=True)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])

    # Persist or update asset
    stmt = select(ASMAsset).where(ASMAsset.asset_target == result["target"])
    res = await db.execute(stmt)
    asset = res.scalar_one_or_none()

    if not asset:
        asset = ASMAsset(
            asset_target=result["target"],
            asset_type="DOMAIN" if not result["target"].replace(".", "").isdigit() else "IP_ENDPOINT",
            resolved_ip=result.get("resolved_ip"),
            open_ports=json.dumps(result.get("open_ports", [])),
            ssl_cert_issuer=result.get("ssl_info", {}).get("issuer"),
            ssl_cert_expiry=result.get("ssl_info", {}).get("notAfter"),
            risk_score=result.get("risk_score", 0.0),
            scope_authorized=True,
            last_scanned=time.time()
        )
        db.add(asset)
    else:
        asset.resolved_ip = result.get("resolved_ip")
        asset.open_ports = json.dumps(result.get("open_ports", []))
        asset.ssl_cert_issuer = result.get("ssl_info", {}).get("issuer")
        asset.ssl_cert_expiry = result.get("ssl_info", {}).get("notAfter")
        asset.risk_score = result.get("risk_score", 0.0)
        asset.last_scanned = time.time()

    await db.commit()

    return {"status": "SCANNED", "discovery": result}
