"""
CyberFusion XDR Enterprise - UEBA Behavioral Analytics APIs
"""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import Dict, Any, List
from app.core.database import get_db
from app.models.models import UEBAAnomaly
from app.services.ueba_engine import _ENTITY_BASELINES

router = APIRouter()

@router.get("/anomalies")
async def list_ueba_anomalies(mode: str = "LIVE", db: AsyncSession = Depends(get_db)):
    """List detected behavioral anomalies with explainable factor breakdown."""
    stmt = select(UEBAAnomaly).where(UEBAAnomaly.mode == mode).order_by(desc(UEBAAnomaly.timestamp)).limit(50)
    res = await db.execute(stmt)
    records = res.scalars().all()
    return [{
        "id": r.id,
        "entity_type": r.entity_type,
        "entity_id": r.entity_id,
        "metric_name": r.metric_name,
        "observed_value": r.observed_value,
        "baseline_mean": r.baseline_mean,
        "baseline_std": r.baseline_std,
        "z_score": r.z_score,
        "risk_score": r.risk_score,
        "explanation": r.explanation,
        "timestamp": r.timestamp
    } for r in records]

@router.get("/profiles")
async def get_learned_baselines():
    """Retrieve statistical baselines computed for enterprise entities."""
    output = []
    for entity, metrics in _ENTITY_BASELINES.items():
        for metric_name, stats in metrics.items():
            output.append({
                "entity_id": entity,
                "metric_name": metric_name,
                "mean": round(stats["mean"], 2),
                "observations": int(stats["count"])
            })
    return output
