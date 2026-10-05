"""
CyberFusion XDR Enterprise - Telemetry Normalization Engine
Normalizes heterogeneous logs (Syslog, CEF, LEEF, Windows Events, Agent JSON, Zeek, WAF)
into canonical ECS/OCSF compliant event structures.
"""
import uuid
import time
import re
from typing import Dict, Any, Optional

class TelemetryNormalizer:
    @staticmethod
    def normalize(raw: Dict[str, Any], data_source: str = "EDR", mode: str = "LIVE", tenant_id: str = "tenant-enterprise-secops") -> Dict[str, Any]:
        """Convert any ingested event into unified normalized security schema."""
        event_uuid = raw.get("uuid") or raw.get("event_uuid") or str(uuid.uuid4())
        timestamp = float(raw.get("timestamp") or time.time())
        category = raw.get("category") or "security_telemetry"
        action = raw.get("action") or "observed"
        severity = raw.get("severity", "INFORMATIONAL").upper()

        # Extract Network
        source_ip = raw.get("source_ip") or raw.get("src_ip") or raw.get("client_ip")
        dest_ip = raw.get("dest_ip") or raw.get("dst_ip") or raw.get("target_ip")
        source_port = int(raw.get("source_port") or raw.get("src_port") or 0) or None
        dest_port = int(raw.get("dest_port") or raw.get("dst_port") or 0) or None
        protocol = (raw.get("protocol") or raw.get("proto") or "").upper() or None

        # Extract Endpoint / Process
        hostname = raw.get("hostname") or raw.get("host") or raw.get("computer_name")
        user_identity = raw.get("user") or raw.get("username") or raw.get("user_identity") or raw.get("user_name")
        process_name = raw.get("process_name") or raw.get("proc") or raw.get("image")
        process_pid = int(raw.get("process_pid") or raw.get("pid") or 0) or None
        parent_process = raw.get("parent_process") or raw.get("parent_image")
        command_line = raw.get("command_line") or raw.get("cmdline") or raw.get("cmd")
        file_path = raw.get("file_path") or raw.get("target_path") or raw.get("path")
        file_hash = raw.get("file_hash") or raw.get("sha256") or raw.get("md5")

        # Extract Web / Cloud
        domain = raw.get("domain") or raw.get("query") or raw.get("host_header")
        url = raw.get("url") or raw.get("uri")
        http_method = (raw.get("http_method") or raw.get("method") or "").upper() or None
        http_status = int(raw.get("http_status") or raw.get("status_code") or 0) or None

        # Check for CEF formatting
        raw_text = str(raw.get("raw") or "")
        if "CEF:" in raw_text:
            cef_parts = raw_text.split("|")
            if len(cef_parts) >= 8:
                data_source = cef_parts[1] or data_source
                category = cef_parts[4] or category
                action = cef_parts[5] or action
                severity = cef_parts[6] or severity
                # Parse key-values in extension
                ext = cef_parts[7]
                for match in re.finditer(r'(\w+)=([^=]+)(?:\s+|$)', ext):
                    k, v = match.group(1), match.group(2).strip()
                    if k in ["src", "src_ip"]: source_ip = v
                    elif k in ["dst", "dst_ip"]: dest_ip = v
                    elif k in ["spt", "src_port"]: source_port = int(v) if v.isdigit() else None
                    elif k in ["dpt", "dst_port"]: dest_port = int(v) if v.isdigit() else None
                    elif k in ["suser", "user"]: user_identity = v
                    elif k in ["dhost", "host"]: hostname = v

        # Extract OSINT and Endpoint Detection Tags
        threat_verdict = raw.get("threat_verdict") or ("MALICIOUS" if raw.get("is_malicious") else "BENIGN")
        risk_score = int(raw.get("risk_score") or 0)
        is_malicious = bool(raw.get("is_malicious") or threat_verdict in ["MALICIOUS", "CRITICAL"])
        detection_reasons = raw.get("detection_reasons") or []
        mitre_tactics = raw.get("mitre_tactics") or []
        mitre_techniques = raw.get("mitre_techniques") or []
        osint_intel = raw.get("osint_intel") or {}

        normalized = {
            "event_uuid": event_uuid,
            "timestamp": timestamp,
            "tenant_id": tenant_id,
            "mode": mode,
            "data_source": data_source,
            "category": category,
            "action": action,
            "severity": severity,
            "threat_verdict": threat_verdict,
            "risk_score": risk_score,
            "is_malicious": is_malicious,
            "detection_reasons": detection_reasons,
            "mitre_tactics": mitre_tactics,
            "mitre_techniques": mitre_techniques,
            "osint_intel": osint_intel,
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "source_port": source_port,
            "dest_port": dest_port,
            "protocol": protocol,
            "hostname": hostname,
            "user_identity": user_identity,
            "process_name": process_name,
            "process_pid": process_pid,
            "parent_process": parent_process,
            "command_line": command_line,
            "file_path": file_path,
            "file_hash": file_hash,
            "domain": domain,
            "url": url,
            "http_method": http_method,
            "http_status": http_status,
            "raw_payload": str(raw),
            "normalized_payload": raw
        }
        return normalized
