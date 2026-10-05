"""
CyberFusion XDR Enterprise - Production Detection Engine
Supports Sigma-compatible rules, IOC matching, threshold frequency detection,
and stateful sequence correlation mapped to MITRE ATT&CK.
"""
import time
import re
import uuid
from typing import Dict, Any, List, Optional
from collections import defaultdict, deque
import logging

logger = logging.getLogger("cyberfusion.detections")

# Sliding window state cache for threshold detections: (entity, rule_id) -> deque([timestamps])
_THRESHOLD_CACHE = defaultdict(lambda: deque(maxlen=200))

# Enterprise Sigma & Behavioral Rule Catalog
PRODUCTION_DETECTION_RULES = [
    {
        "rule_id": "SIGMA-T1059-001",
        "name": "Suspicious PowerShell Encoded Execution or Cradle",
        "description": "Detects execution of PowerShell with Base64 encoded payload, download cradle (IEX/DownloadString), or hidden execution window.",
        "severity": "HIGH",
        "confidence": 0.95,
        "data_sources": ["EDR", "WINDOWS_SECURITY"],
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059.001",
        "mitre_subtechnique": "Command and Scripting Interpreter: PowerShell",
        "rule_type": "SIGMA",
        "version": "2.1.0",
        "author": "CyberFusion SecOps Engineering",
        "false_positive_guidance": "Legitimate enterprise software deployment scripts (e.g. SCCM, Intune) running signed encoded blocks. Verify parent process.",
        "match_func": lambda e: (
            e.get("process_name") in ["powershell.exe", "pwsh.exe", "powershell_ise.exe"] and (
                any(arg in (e.get("command_line") or "").lower() for arg in [
                    "-enc", "-encodedcommand", "downloadstring", "iex(", "webclient", "bypass -nop"
                ])
            )
        )
    },
    {
        "rule_id": "SIGMA-T1003-001",
        "name": "LSASS Memory Access or Credential Dumping Attempt",
        "description": "Detects processes attempting to dump or read LSASS memory, typical of Mimikatz or ProcDump credential theft.",
        "severity": "CRITICAL",
        "confidence": 0.98,
        "data_sources": ["EDR"],
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1003.001",
        "mitre_subtechnique": "OS Credential Dumping: LSASS Memory",
        "rule_type": "SIGMA",
        "version": "1.8.0",
        "author": "CyberFusion Threat Research",
        "false_positive_guidance": "Authorized endpoint DLP, enterprise antivirus scanners, or Microsoft Defender processes.",
        "match_func": lambda e: (
            "lsass.dmp" in (e.get("command_line") or "").lower() or
            ("procdump" in (e.get("process_name") or "").lower() and "lsass" in (e.get("command_line") or "").lower()) or
            "sekurlsa" in (e.get("command_line") or "").lower()
        )
    },
    {
        "rule_id": "NDR-T1071-001",
        "name": "Outbound Beaconing or Connection to Malicious C2 Infrastructure",
        "description": "Detects high-frequency outbound beaconing or network connections to known command and control infrastructure.",
        "severity": "CRITICAL",
        "confidence": 0.96,
        "data_sources": ["NDR", "EDR", "FIREWALL"],
        "mitre_tactic": "Command and Control",
        "mitre_technique": "T1071.001",
        "mitre_subtechnique": "Application Layer Protocol: Web Protocols",
        "rule_type": "IOC",
        "version": "1.5.0",
        "author": "CyberFusion CTI Team",
        "false_positive_guidance": "Rare benign external CDNs or shared cloud reverse proxies. Check destination IP threat reputation.",
        "match_func": lambda e: e.get("_tip_enrichment") and e["_tip_enrichment"].get("matched") is True
    },
    {
        "rule_id": "IAM-T1110-001",
        "name": "Authentication Brute Force Burst or Password Spray",
        "description": "Detects 5 or more authentication failures within a 60-second window targeting an identity or host.",
        "severity": "HIGH",
        "confidence": 0.88,
        "data_sources": ["IAM", "ACTIVE_DIRECTORY", "ENTRA_ID"],
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110.001",
        "mitre_subtechnique": "Brute Force: Password Guessing",
        "rule_type": "THRESHOLD",
        "version": "2.0.0",
        "author": "CyberFusion IAM Analytics",
        "false_positive_guidance": "Users with expired passwords after enterprise-wide password rotation schedules.",
        "match_func": None # Evaluated via threshold logic
    },
    {
        "rule_id": "WAF-T1190-001",
        "name": "Exploitation Attempt: SQL Injection / Web Application Attack",
        "description": "Detects SQL injection syntax or command injection probes targeting web applications and APIs.",
        "severity": "HIGH",
        "confidence": 0.92,
        "data_sources": ["WAF", "NGINX", "MODSECURITY"],
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1190",
        "mitre_subtechnique": "Exploit Public-Facing Application",
        "rule_type": "SIGMA",
        "version": "1.3.0",
        "author": "CyberFusion AppSec",
        "false_positive_guidance": "Authorized web application penetration testing or vulnerability scans.",
        "match_func": lambda e: (
            e.get("data_source") == "WAF" and (
                any(p in (e.get("url") or "").lower() for p in ["union select", "' or 1=1", "sleep(", "../..", "<script>", "/bin/sh", "cmd.exe"])
            )
        )
    },
    {
        "rule_id": "DLP-T1048-001",
        "name": "Data Loss Prevention: Sensitive PII / Credential Leakage",
        "description": "Detects unencrypted credit cards, API keys, or confidential tags transferred across network or written to USB.",
        "severity": "HIGH",
        "confidence": 0.90,
        "data_sources": ["DLP", "EDR"],
        "mitre_tactic": "Exfiltration",
        "mitre_technique": "T1048",
        "mitre_subtechnique": "Exfiltration Over Alternative Protocol",
        "rule_type": "BEHAVIORAL",
        "version": "1.2.0",
        "author": "CyberFusion Data Security",
        "false_positive_guidance": "Legitimate test data containing synthetic dummy numbers or masking tokens.",
        "match_func": lambda e: (
            e.get("data_source") == "DLP" or
            any(w in (e.get("raw_payload") or "").lower() for w in ["bearer eyj", "aws_secret_access_key", "password=", "confidential_internal"])
        )
    },
    {
        "rule_id": "EDR-T1053-005",
        "name": "Persistence: Scheduled Task or System Service Creation",
        "description": "Detects scheduled task creation via schtasks.exe or service installation for persistence.",
        "severity": "MEDIUM",
        "confidence": 0.85,
        "data_sources": ["EDR", "WINDOWS_SECURITY"],
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1053.005",
        "mitre_subtechnique": "Scheduled Task/Job: Scheduled Task",
        "rule_type": "SIGMA",
        "version": "1.1.0",
        "author": "CyberFusion Threat Hunting",
        "false_positive_guidance": "Legitimate software installers (Google Chrome updater, Adobe updater).",
        "match_func": lambda e: (
            "schtasks.exe" in (e.get("process_name") or "").lower() and "/create" in (e.get("command_line") or "").lower()
        )
    },
    {
        "rule_id": "OSINT-THREAT-001",
        "name": "Endpoint Correlated OSINT Malicious Activity",
        "description": "Triggered when endpoint agent telemetry matches live Open Source Intelligence (AlienVault OTX, Abuse.ch Feodo Tracker, CIRCL).",
        "severity": "CRITICAL",
        "confidence": 0.96,
        "data_sources": ["EDR"],
        "mitre_tactic": "Command and Control",
        "mitre_technique": "T1071",
        "mitre_subtechnique": "Application Layer Protocol: External C2",
        "rule_type": "OSINT_INTELLIGENCE",
        "version": "1.0.0",
        "author": "CyberFusion OSINT Engine",
        "false_positive_guidance": "Review AlienVault OTX pulse names and CIRCL verification report.",
        "match_func": lambda e: (
            bool(e.get("osint_intel", {}).get("is_malicious")) and
            e.get("osint_intel", {}).get("threat_score", 0) >= 80
        )
    }
]

class DetectionEngine:
    @staticmethod
    def evaluate_event(event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Evaluate a normalized event against all active detection rules.
        Returns a list of triggered alerts.
        """
        triggered_alerts = []
        now = event.get("timestamp") or time.time()
        mode = event.get("mode", "LIVE")
        tenant_id = event.get("tenant_id", "tenant-enterprise-secops")

        for rule in PRODUCTION_DETECTION_RULES:
            rule_id = rule["rule_id"]

            # 1. Standard / Sigma / IOC / Regex match function
            if rule["match_func"]:
                try:
                    if rule["match_func"](event):
                        triggered_alerts.append(DetectionEngine._build_alert(rule, event))
                        continue
                except Exception as ex:
                    logger.error(f"Rule {rule_id} match error: {ex}")

            # 2. Threshold evaluation for Brute Force (IAM-T1110-001)
            if rule_id == "IAM-T1110-001":
                if event.get("category") == "authentication" and event.get("action") in ["logon_failed", "auth_failure", "failed"]:
                    entity_key = event.get("user_identity") or event.get("source_ip") or "unknown"
                    key = f"brute_force::{entity_key}"
                    q = _THRESHOLD_CACHE[key]
                    q.append(now)
                    # Count failures within 60 seconds
                    recent = [t for t in q if now - t <= 60.0]
                    if len(recent) >= 5:
                        alert = DetectionEngine._build_alert(rule, event)
                        alert["description"] = f"Detected {len(recent)} failed authentication attempts in 60s for entity: {entity_key}"
                        triggered_alerts.append(alert)
                        q.clear() # Reset window after triggering

        return triggered_alerts

    @staticmethod
    def _build_alert(rule: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
        alert_id = f"ALT-{int(time.time())}-{uuid.uuid4().hex[:6].upper()}"
        return {
            "alert_id": alert_id,
            "tenant_id": event.get("tenant_id", "tenant-enterprise-secops"),
            "mode": event.get("mode", "LIVE"),
            "title": rule["name"],
            "description": rule["description"],
            "severity": rule["severity"],
            "confidence": rule["confidence"],
            "rule_id": rule["rule_id"],
            "rule_name": rule["name"],
            "mitre_tactic": rule["mitre_tactic"],
            "mitre_technique": rule["mitre_technique"],
            "mitre_subtechnique": rule["mitre_subtechnique"],
            "source_ip": event.get("source_ip"),
            "dest_ip": event.get("dest_ip"),
            "affected_host": event.get("hostname"),
            "affected_user": event.get("user_identity"),
            "event_ids": [event.get("event_uuid")],
            "status": "NEW",
            "created_at": time.time()
        }
