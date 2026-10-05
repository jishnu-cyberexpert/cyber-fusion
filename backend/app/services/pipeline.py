"""
CyberFusion XDR Enterprise - Real-Time Pipeline Orchestrator
Executes: Normalization -> TIP Enrichment -> Detection -> Correlation -> UEBA -> Risk -> Storage -> WebSocket.
"""
import time
import json
from typing import Dict, Any, List
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import AsyncSessionLocal
from app.models.models import SecurityEvent, Alert, Incident, UEBAAnomaly, CorrelatedThreat
import uuid
from app.services.normalizer import TelemetryNormalizer
from app.services.tip_service import ThreatIntelService
from app.services.detection_engine import DetectionEngine
from app.services.correlation_engine import XDRCorrelationEngine
from app.services.ueba_engine import UEBAEngine
from app.services.ml_engine import LocalMLEndpointEngine
from app.services.risk_engine import RiskEngine
from app.services.mongodb_service import mongodb_service
from app.api.v1.websocket import ws_manager
import logging

logger = logging.getLogger("cyberfusion.pipeline")

class PipelineOrchestrator:
    @staticmethod
    async def process_raw_event(
        raw_event: Dict[str, Any],
        data_source: str = "EDR",
        mode: str = "LIVE",
        tenant_id: str = "tenant-enterprise-secops"
    ) -> Dict[str, Any]:
        """
        Full real-time event pipeline execution for a single event.
        """
        start_time = time.time()
        
        # 1. Normalization (ECS/OCSF)
        normalized = TelemetryNormalizer.normalize(
            raw=raw_event,
            data_source=data_source,
            mode=mode,
            tenant_id=tenant_id
        )

        # 2. Threat Intelligence Real-Time Enrichment
        tip_enrichment = ThreatIntelService.enrich_event(normalized)
        if tip_enrichment:
            normalized["_tip_enrichment"] = tip_enrichment

        # 3. Detection Engine Evaluation
        alerts = DetectionEngine.evaluate_event(normalized)
        
        # 4. UEBA Behavioral Evaluation
        ueba_anomaly = UEBAEngine.evaluate_behavior(normalized)

        # 4b. Local ML Anomaly & Behavioral Inference
        ml_alert = LocalMLEndpointEngine.evaluate_telemetry(normalized)
        if ml_alert:
            ml_alert["event_ids"] = [normalized["event_uuid"]]
            ml_alert["created_at"] = normalized.get("timestamp") or time.time()
            alerts.append(ml_alert)

        # 5. Database Persistence & Correlation
        async with AsyncSessionLocal() as db:
            # Save normalized event
            sec_event = SecurityEvent(
                event_uuid=normalized["event_uuid"],
                timestamp=normalized["timestamp"],
                tenant_id=tenant_id,
                mode=mode,
                data_source=data_source,
                category=normalized["category"],
                action=normalized["action"],
                severity=normalized["severity"],
                source_ip=normalized.get("source_ip"),
                dest_ip=normalized.get("dest_ip"),
                source_port=normalized.get("source_port"),
                dest_port=normalized.get("dest_port"),
                protocol=normalized.get("protocol"),
                hostname=normalized.get("hostname"),
                user_identity=normalized.get("user_identity"),
                process_name=normalized.get("process_name"),
                process_pid=normalized.get("process_pid"),
                parent_process=normalized.get("parent_process"),
                command_line=normalized.get("command_line"),
                file_path=normalized.get("file_path"),
                file_hash=normalized.get("file_hash"),
                domain=normalized.get("domain"),
                url=normalized.get("url"),
                http_method=normalized.get("http_method"),
                http_status=normalized.get("http_status"),
                raw_payload=normalized.get("raw_payload"),
                normalized_payload=json.dumps(normalized),
                is_alert=len(alerts) > 0
            )
            db.add(sec_event)

            # Evaluate Threat Intel for CorrelatedThreat (Zero False Positive Check)
            if tip_enrichment and tip_enrichment.get("matched") and tip_enrichment.get("confidence", 0) >= 0.90:
                threat_id = f"CTI-{int(time.time())}-{uuid.uuid4().hex[:6].upper()}"
                all_matches = tip_enrichment.get("all_matches", [])
                primary_ioc = all_matches[0]["ioc"] if all_matches else {}
                corr_threat = CorrelatedThreat(
                    threat_id=threat_id,
                    tenant_id=tenant_id,
                    mode=mode,
                    indicator_value=primary_ioc.get("value", "UNKNOWN"),
                    indicator_type=primary_ioc.get("ioc_type", "UNKNOWN"),
                    threat_verdict="MALICIOUS",
                    severity=tip_enrichment.get("severity", "HIGH"),
                    confidence=tip_enrichment.get("confidence", 0.95),
                    vendor_ratio="VERIFIED",
                    detection_sources=json.dumps([tip_enrichment.get("source", "CTI Engine")]),
                    threat_actor=tip_enrichment.get("threat_actor"),
                    campaign=tip_enrichment.get("campaign"),
                    malware_family=tip_enrichment.get("malware_family"),
                    ioc_definition=json.dumps(primary_ioc),
                    associated_events_count=1,
                    associated_event_uuids=json.dumps([normalized.get("event_uuid")]),
                    associated_hosts=json.dumps([normalized.get("hostname")] if normalized.get("hostname") else []),
                    associated_users=json.dumps([normalized.get("user_identity")] if normalized.get("user_identity") else []),
                    status="ACTIVE"
                )
                db.add(corr_threat)

            # Save UEBA Anomaly if found
            if ueba_anomaly:
                anom = UEBAAnomaly(
                    tenant_id=tenant_id,
                    entity_type=ueba_anomaly["entity_type"],
                    entity_id=ueba_anomaly["entity_id"],
                    metric_name=ueba_anomaly["metric_name"],
                    observed_value=ueba_anomaly["observed_value"],
                    baseline_mean=ueba_anomaly["baseline_mean"],
                    baseline_std=ueba_anomaly["baseline_std"],
                    z_score=ueba_anomaly["z_score"],
                    risk_score=ueba_anomaly["risk_score"],
                    explanation=ueba_anomaly["explanation"],
                    timestamp=ueba_anomaly["timestamp"],
                    mode=mode
                )
                db.add(anom)

            # Process any alerts through XDR Correlation & Risk Engine
            for alert_data in alerts:
                alert_obj = Alert(
                    alert_id=alert_data["alert_id"],
                    tenant_id=tenant_id,
                    mode=mode,
                    title=alert_data["title"],
                    description=alert_data["description"],
                    severity=alert_data["severity"],
                    confidence=alert_data["confidence"],
                    rule_id=alert_data["rule_id"],
                    rule_name=alert_data["rule_name"],
                    mitre_tactic=alert_data["mitre_tactic"],
                    mitre_technique=alert_data["mitre_technique"],
                    mitre_subtechnique=alert_data["mitre_subtechnique"],
                    source_ip=alert_data.get("source_ip"),
                    dest_ip=alert_data.get("dest_ip"),
                    affected_host=alert_data.get("affected_host"),
                    affected_user=alert_data.get("affected_user"),
                    event_ids=json.dumps(alert_data.get("event_ids", [])),
                    status="NEW",
                    created_at=alert_data["created_at"]
                )
                db.add(alert_obj)

                # Cross-domain correlation into Incident
                correlation_res = XDRCorrelationEngine.correlate_alert(alert_data)
                inc_payload = correlation_res["incident_payload"]
                
                # Calculate explainable risk score
                risk_res = RiskEngine.calculate_incident_risk(inc_payload)
                
                if correlation_res["is_new"]:
                    inc_obj = Incident(
                        incident_id=inc_payload["incident_id"],
                        tenant_id=tenant_id,
                        mode=mode,
                        title=inc_payload["title"],
                        description=f"{inc_payload['description']} [Risk Score: {risk_res['risk_score']}/100 - {risk_res['risk_tier']}]",
                        severity=inc_payload["severity"],
                        status="OPEN",
                        assignee="SecOps Triage Queue",
                        mitre_tactics=json.dumps(list(inc_payload["tactics"])),
                        entities=json.dumps({
                            "hosts": list(inc_payload["entities"]["hosts"]),
                            "users": list(inc_payload["entities"]["users"]),
                            "ips": list(inc_payload["entities"]["ips"]),
                        }),
                        evidence_count=1,
                        lead_alert_id=inc_payload["lead_alert_id"],
                        sla_deadline=inc_payload["sla_deadline"],
                        created_at=inc_payload["created_at"],
                        updated_at=inc_payload["updated_at"]
                    )
                    db.add(inc_obj)

                # Link alert to incident
                alert_obj.incident_id = inc_payload["incident_id"]

            await db.commit()

        # 5b. Asynchronously inject log into MongoDB Atlas
        try:
            await mongodb_service.insert_log(normalized)
        except Exception as mongo_err:
            logger.warning(f"MongoDB log injection skipped: {mongo_err}")

        # 6. Broadcast Real-Time Updates via WebSockets
        latency_ms = round((time.time() - start_time) * 1000.0, 2)
        await ws_manager.broadcast({
            "type": "TELEMETRY_INGESTED",
            "event": {
                "event_uuid": normalized["event_uuid"],
                "uuid": normalized["event_uuid"],
                "category": normalized["category"],
                "action": normalized.get("action", "unknown_action"),
                "data_source": data_source,
                "hostname": normalized.get("hostname"),
                "user": normalized.get("user_identity"),
                "user_identity": normalized.get("user_identity"),
                "process": normalized.get("process_name"),
                "process_name": normalized.get("process_name"),
                "pid": normalized.get("process_pid"),
                "command_line": normalized.get("command_line"),
                "source_ip": normalized.get("source_ip"),
                "dest_ip": normalized.get("dest_ip"),
                "dest_port": normalized.get("dest_port"),
                "file_path": normalized.get("file_path"),
                "domain": normalized.get("domain"),
                "mode": mode,
                "timestamp": normalized["timestamp"]
            },
            "alerts": alerts,
            "latency_ms": latency_ms
        })

        return {
            "status": "PROCESSED",
            "event_uuid": normalized["event_uuid"],
            "alerts_generated": len(alerts),
            "latency_ms": latency_ms
        }
