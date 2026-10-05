"""
CyberFusion XDR Enterprise - Local Machine Learning Analytics Router
Endpoints for ML model inspection, real-time command inference, and anomaly metrics.
"""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
from app.services.ml_engine import LocalMLEndpointEngine, SKLEARN_AVAILABLE, _BASELINE_TRAINING_CORPUS

router = APIRouter()

class TelemetryInferenceRequest(BaseModel):
    process_name: str
    command_line: str
    parent_process: Optional[str] = "explorer.exe"
    hostname: Optional[str] = "TEST-ENDPOINT"
    user_identity: Optional[str] = "secops_user"

@router.get("/status")
async def get_ml_status():
    """Returns local ML engine operational health, algorithm, and baseline status."""
    return {
        "status": "ONLINE",
        "engine": "CyberFusion Local ML Threat Engine",
        "algorithm": "Isolation Forest (Unsupervised) + Shannon Entropy Heuristics",
        "scikit_learn_loaded": SKLEARN_AVAILABLE,
        "baseline_training_samples": len(_BASELINE_TRAINING_CORPUS),
        "target_features": [
            "cmd_length",
            "cmd_entropy",
            "special_char_ratio",
            "digit_ratio",
            "is_lolbin",
            "is_suspicious_parent"
        ],
        "latency_target_ms": "< 2.0 ms"
    }

@router.post("/analyze")
async def analyze_process_telemetry(req: TelemetryInferenceRequest):
    """
    On-demand local ML evaluation of an arbitrary process or command-line.
    Returns risk score (0-100), explainable factors, and MITRE mapping.
    """
    event = {
        "category": "process",
        "action": "process_create",
        "process_name": req.process_name,
        "command_line": req.command_line,
        "parent_process": req.parent_process,
        "hostname": req.hostname,
        "user_identity": req.user_identity,
        "source_ip": "127.0.0.1",
        "mode": "TEST"
    }

    res = LocalMLEndpointEngine.analyze_detailed(event, force_enforce=True)
    return {
        "verdict": res["verdict"],
        "risk_score": res["risk_score"],
        "severity": res["severity"],
        "is_alert": res["is_alert"],
        "mitre_tactic": res["mitre_tactic"],
        "mitre_technique": res["mitre_technique"],
        "factors": res["factors"],
        "extracted_features": res["features"]
    }

@router.get("/learning/profiles")
async def get_learning_profiles():
    """Retrieve learning mode state, event progress, and learned lineage metrics for all endpoints."""
    return LocalMLEndpointEngine.list_all_profiles()

@router.post("/learning/reset/{host_id}")
async def reset_host_learning_mode(host_id: str, target_events: int = 50):
    """Reset an endpoint to LEARNING mode to observe and rebuild its behavioral baseline."""
    return LocalMLEndpointEngine.reset_host_learning(host_id, target_events=target_events)

@router.post("/learning/force-enforce/{host_id}")
async def force_enforce_host(host_id: str):
    """Manually conclude learning mode and immediately transition to ENFORCING mode."""
    return LocalMLEndpointEngine.force_enforce_host(host_id)
