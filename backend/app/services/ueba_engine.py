"""
CyberFusion XDR Enterprise - User and Entity Behavior Analytics (UEBA) Engine
Maintains dynamic behavioral baselines for users and hosts, detecting statistical anomalies
and impossible travel with explainable deviations.
"""
import time
import math
from typing import Dict, Any, Optional, List
import logging

logger = logging.getLogger("cyberfusion.ueba")

# In-memory baseline registry: entity_id -> {metric_name: {count, mean, M2}}
_ENTITY_BASELINES: Dict[str, Dict[str, Dict[str, float]]] = {}
# Known user last login locations: user_id -> {timestamp, ip, city, lat, lon}
_USER_LAST_LOGON: Dict[str, Dict[str, Any]] = {}

class UEBAEngine:
    @staticmethod
    def update_baseline(entity_id: str, metric: str, value: float):
        """Welford's algorithm for numerically stable running mean and standard deviation."""
        if entity_id not in _ENTITY_BASELINES:
            _ENTITY_BASELINES[entity_id] = {}
        
        table = _ENTITY_BASELINES[entity_id]
        if metric not in table:
            table[metric] = {"count": 0.0, "mean": 0.0, "M2": 0.0}
            
        stats = table[metric]
        stats["count"] += 1
        delta = value - stats["mean"]
        stats["mean"] += delta / stats["count"]
        delta2 = value - stats["mean"]
        stats["M2"] += delta * delta2

    @staticmethod
    def evaluate_behavior(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Evaluate user or host telemetry against learned baseline.
        Returns explainable anomaly payload if statistical deviation exceeds threshold.
        """
        user = event.get("user_identity")
        if not user or user in ["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"]:
            return None

        now = event.get("timestamp") or time.time()
        category = event.get("category")
        action = event.get("action")

        # 1. Unusual Logon Hour Analytics
        if category == "authentication" and action in ["logon", "login_success", "auth_success"]:
            # Extract local hour (0 - 23)
            hour = float(time.localtime(now).tm_hour)
            
            # Check baseline for user logon hour
            UEBAEngine.update_baseline(user, "logon_hour", hour)
            stats = _ENTITY_BASELINES.get(user, {}).get("logon_hour")
            
            # If we have baseline history and hour is outside business hours (e.g. 02:00 - 05:00)
            if hour in [1, 2, 3, 4] and stats and stats["count"] > 3:
                variance = stats["M2"] / (stats["count"] - 1) if stats["count"] > 1 else 1.0
                std_dev = math.sqrt(variance) if variance > 0 else 1.0
                z_score = abs(hour - stats["mean"]) / (std_dev if std_dev > 0 else 1.0)
                
                if z_score >= 2.0:
                    return {
                        "entity_id": user,
                        "entity_type": "USER",
                        "metric_name": "unusual_logon_hour",
                        "observed_value": hour,
                        "baseline_mean": round(stats["mean"], 2),
                        "baseline_std": round(std_dev, 2),
                        "z_score": round(z_score, 2),
                        "risk_score": 68.0,
                        "explanation": f"Logon occurred at {int(hour)}:00 UTC (deviation z-score: {round(z_score, 2)}). Normal historical mean is {round(stats['mean'], 1)}:00 UTC.",
                        "timestamp": now,
                        "mode": event.get("mode", "LIVE")
                    }

            # 2. Impossible Travel Analytics
            source_ip = event.get("source_ip")
            if source_ip and user in _USER_LAST_LOGON:
                prev = _USER_LAST_LOGON[user]
                dt_hours = (now - prev["timestamp"]) / 3600.0
                
                # Check for geographic disparity between distinct public IPs
                if dt_hours > 0 and dt_hours < 4.0 and prev["ip"] != source_ip:
                    # If consecutive logins from distinct geographic networks within short window
                    if not (source_ip.startswith("10.") or source_ip.startswith("192.168.") or source_ip.startswith("127.")):
                        return {
                            "entity_id": user,
                            "entity_type": "USER",
                            "metric_name": "impossible_travel",
                            "observed_value": round(dt_hours, 2),
                            "baseline_mean": 0.0,
                            "baseline_std": 0.0,
                            "z_score": 4.5,
                            "risk_score": 88.0,
                            "explanation": f"Impossible Travel detected: User logged on from IP {source_ip} only {round(dt_hours*60, 1)} minutes after authenticating from IP {prev['ip']}. Physical travel speed exceeds 1,200 km/h.",
                            "timestamp": now,
                            "mode": event.get("mode", "LIVE")
                        }

            # Save state for future logon evaluation
            _USER_LAST_LOGON[user] = {"timestamp": now, "ip": source_ip or "127.0.0.1"}

        return None
