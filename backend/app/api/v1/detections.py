"""
CyberFusion XDR Enterprise - Detection Rules & Alerts APIs
Manages production Sigma rules, triggered alerts, and real MITRE ATT&CK coverage matrix.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import Dict, Any, List, Optional
import time
import json
from app.core.database import get_db
from app.models.models import Alert, DetectionRule
from app.services.detection_engine import PRODUCTION_DETECTION_RULES

router = APIRouter()

@router.get("/rules")
async def list_detection_rules():
    """List all production-grade detection rules with MITRE mappings and confidence ratings."""
    rules_out = []
    for r in PRODUCTION_DETECTION_RULES:
        rules_out.append({
            "rule_id": r["rule_id"],
            "name": r["name"],
            "description": r["description"],
            "severity": r["severity"],
            "confidence": r["confidence"],
            "data_sources": r["data_sources"],
            "mitre_tactic": r["mitre_tactic"],
            "mitre_technique": r["mitre_technique"],
            "mitre_subtechnique": r["mitre_subtechnique"],
            "rule_type": r["rule_type"],
            "version": r["version"],
            "author": r["author"],
            "false_positive_guidance": r["false_positive_guidance"]
        })
    return rules_out

@router.get("/alerts")
async def list_alerts(
    tenant_id: str = "tenant-enterprise-secops",
    mode: str = "LIVE",
    severity: Optional[str] = None,
    limit: int = 100,
    db: AsyncSession = Depends(get_db)
):
    """List real triggered security alerts."""
    stmt = select(Alert).where(
        Alert.tenant_id == tenant_id,
        Alert.mode == mode
    ).order_by(desc(Alert.created_at)).limit(limit)
    
    if severity:
        stmt = stmt.where(Alert.severity == severity)

    res = await db.execute(stmt)
    alerts = res.scalars().all()

    return [{
        "alert_id": a.alert_id,
        "title": a.title,
        "description": a.description,
        "severity": a.severity,
        "confidence": a.confidence,
        "rule_id": a.rule_id,
        "rule_name": a.rule_name,
        "mitre_tactic": a.mitre_tactic,
        "mitre_technique": a.mitre_technique,
        "mitre_subtechnique": a.mitre_subtechnique,
        "source_ip": a.source_ip,
        "dest_ip": a.dest_ip,
        "affected_host": a.affected_host,
        "affected_user": a.affected_user,
        "status": a.status,
        "incident_id": a.incident_id,
        "created_at": a.created_at
    } for a in alerts]

@router.get("/mitre/coverage")
async def get_mitre_coverage_matrix(mode: str = "LIVE", db: AsyncSession = Depends(get_db)):
    """
    Computes verifiable MITRE ATT&CK coverage and detected hits.
    Strictly verifies against actual detection rules and ingested detections.
    """
    coverage = {}
    for r in PRODUCTION_DETECTION_RULES:
        tactic = r["mitre_tactic"]
        tech = r["mitre_technique"]
        if tactic not in coverage:
            coverage[tactic] = []
        coverage[tactic].append({
            "technique_id": tech,
            "name": r["mitre_subtechnique"],
            "rule_id": r["rule_id"],
            "confidence": r["confidence"],
            "detections_count": 0
        })

    # Count real alert occurrences for each technique
    stmt = select(Alert.mitre_technique, Alert.severity).where(Alert.mode == mode)
    res = await db.execute(stmt)
    hits = res.all()
    
    tech_hit_counts = {}
    for tech, sev in hits:
        if tech:
            tech_hit_counts[tech] = tech_hit_counts.get(tech, 0) + 1

    for tactic, techs in coverage.items():
        for t in techs:
            t["detections_count"] = tech_hit_counts.get(t["technique_id"], 0)

    return {
        "tactics_count": len(coverage),
        "total_rules": len(PRODUCTION_DETECTION_RULES),
        "active_mode": mode,
        "matrix": coverage
    }
