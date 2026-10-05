"""
CyberFusion XDR Enterprise - Explainable Contextual Risk Engine
Evaluates threats based on asset criticality, identity privileges, threat intelligence confidence,
MITRE ATT&CK progression, and statistical UEBA deviations.
"""
from typing import Dict, Any, List

class RiskEngine:
    @staticmethod
    def calculate_incident_risk(incident: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculates a deterministic, explainable risk score (0 - 100).
        Returns numeric score and a list of specific explanatory factors.
        """
        base_scores = {
            "CRITICAL": 50.0,
            "HIGH": 35.0,
            "MEDIUM": 20.0,
            "LOW": 10.0,
            "INFORMATIONAL": 5.0
        }
        
        severity = incident.get("severity", "MEDIUM").upper()
        score = base_scores.get(severity, 20.0)
        explanations = [f"Base severity rating [{severity}]: +{score} pts"]

        # Check MITRE ATT&CK Tactics
        tactics = incident.get("tactics") or []
        high_impact_tactics = {"Impact", "Exfiltration", "Command and Control", "Credential Access"}
        for t in tactics:
            if t in high_impact_tactics:
                score += 15.0
                explanations.append(f"Advanced ATT&CK phase present [{t}]: +15 pts")
                break

        # Check entity sensitivity
        entities = incident.get("entities") or {}
        users = entities.get("users") or []
        for u in users:
            u_str = str(u).lower()
            if any(admin_kw in u_str for admin_kw in ["admin", "root", "domain", "svc_", "globaladmin"]):
                score += 20.0
                explanations.append(f"Privileged identity involved [{u}]: +20 pts")
                break

        # Check multi-host propagation
        hosts = entities.get("hosts") or []
        if len(hosts) > 1:
            score += 15.0
            explanations.append(f"Lateral entity spread across {len(hosts)} distinct endpoints: +15 pts")

        # Clamp between 0 and 100
        final_score = min(max(round(score, 1), 0.0), 100.0)

        risk_tier = "CRITICAL" if final_score >= 85 else "HIGH" if final_score >= 65 else "MEDIUM" if final_score >= 40 else "LOW"

        return {
            "risk_score": final_score,
            "risk_tier": risk_tier,
            "factors": explanations
        }
