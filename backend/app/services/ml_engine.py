"""
CyberFusion XDR Enterprise - Local Machine Learning Threat & Anomaly Inference Engine
Performs local edge/pipeline ML analysis on endpoint telemetry:
1. Behavioral feature extraction (CLI entropy, symbol ratios, rare parent-child relationships).
2. Dynamic Host Learning Mode: Profiles host normal baseline before graduating to active enforcement.
3. Persistent Host Baselines: Saves and loads profiles to disk across backend restarts.
4. Unsupervised Anomaly Detection using Isolation Forest calibrated on host baselines.
5. Supervised Heuristic Feature Scoring for Obfuscation, LOLBin Abuse & Defense Evasion.
6. Generates explainable factor attributions mapped to MITRE ATT&CK for SOC analysts.
"""

import os
import re
import math
import uuid
import time
import json
import logging
from typing import Dict, Any, List, Optional, Tuple, Set

logger = logging.getLogger("cyberfusion.ml_engine")

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn / numpy not available, running in fallback heuristic mode.")

try:
    import joblib
except ImportError:
    joblib = None

# Baseline directory for persistent learning profiles
PROFILES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "learning_profiles")
os.makedirs(PROFILES_DIR, exist_ok=True)

# Baseline benign process feature vectors for cold-start Isolation Forest calibration
_BASELINE_TRAINING_CORPUS = [
    # [cmd_len, entropy, special_ratio, digit_ratio, is_lolbin, is_script_parent]
    [25.0, 3.1, 0.05, 0.02, 0.0, 0.0],   # explorer.exe
    [45.0, 3.4, 0.08, 0.04, 0.0, 0.0],   # svchost.exe -k netsvcs
    [60.0, 3.6, 0.09, 0.05, 0.0, 0.0],   # chrome.exe --type=renderer
    [180.0, 4.3, 0.12, 0.08, 0.0, 0.0],  # msedgewebview2.exe --type=renderer --field-trial-handle=...
    [220.0, 4.4, 0.14, 0.09, 0.0, 0.0],  # chrome.exe --type=gpu-process
    [30.0, 3.2, 0.06, 0.01, 0.0, 0.0],   # taskhostw.exe
    [40.0, 3.3, 0.07, 0.03, 0.0, 0.0],   # msedge.exe
    [20.0, 2.9, 0.04, 0.00, 0.0, 0.0],   # notepad.exe
    [35.0, 3.2, 0.05, 0.02, 0.0, 0.0],   # conhost.exe
    [120.0, 3.8, 0.10, 0.05, 0.0, 0.0],  # code.exe (VS Code / Electron)
    [140.0, 4.1, 0.11, 0.06, 0.0, 0.0],  # antigravity ide.exe (IDE helper)
    [32.0, 3.1, 0.06, 0.03, 0.0, 0.0],   # git.exe status
    [48.0, 3.4, 0.07, 0.04, 0.0, 0.0],   # python.exe myscript.py
]

# High-risk LOLBins (Living-off-the-Land Binaries)
LOLBINS = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
    "vssadmin.exe", "schtasks.exe", "sc.exe", "net.exe", "whoami.exe", "wmic.exe"
}

# Known benign system, browser, and developer software to prevent false positives
BENIGN_SOFTWARE_BINARIES = {
    "msedgewebview2.exe", "msedge.exe", "chrome.exe", "firefox.exe", "brave.exe",
    "opera.exe", "explorer.exe", "svchost.exe", "taskhostw.exe", "conhost.exe",
    "dwm.exe", "searchhost.exe", "shellexperiencehost.exe", "startmenuexperiencehost.exe",
    "runtimebroker.exe", "smartscreen.exe", "widgets.exe", "code.exe",
    "antigravity ide.exe", "antigravity-ide.exe", "cursor.exe", "devenv.exe",
    "git.exe", "node.exe", "python.exe"
}

# Standard Chromium / WebView / Electron subprocess switches
CHROMIUM_BENIGN_SWITCHES = {
    "--type=renderer", "--type=gpu-process", "--type=utility",
    "--type=crashpad-handler", "--field-trial-handle", "--mojo-platform-channel-handle",
    "--user-data-dir", "--profile-directory"
}

# Suspicious parent processes for script interpreters
OFFICE_OR_BROWSER_PARENTS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "chrome.exe", "msedge.exe", "firefox.exe", "acrobat.exe"
}


class HostLearningProfile:
    """
    Maintains a persistent dynamic behavioral baseline per endpoint.
    Transitions from LEARNING -> ENFORCING mode after observing target events.
    """
    def __init__(self, host_id: str, target_events: int = 50):
        self.host_id = host_id
        self.state = "LEARNING"  # "LEARNING" | "ENFORCING"
        self.target_events = target_events
        self.events_observed = 0
        self.observed_vectors: List[List[float]] = []
        self.known_lineage: Set[Tuple[str, str]] = set()
        self.known_binaries: Set[str] = set()
        self.custom_model: Optional[Any] = None
        self.calibrated_threshold: float = -0.10
        self.learning_started_at: float = time.time()
        self.enforcing_since: Optional[float] = None

    def save_to_disk(self):
        """Persists profile metadata and calibrated model to disk."""
        safe_name = re.sub(r"[^A-Za-z0-9_-]", "_", self.host_id)
        json_path = os.path.join(PROFILES_DIR, f"{safe_name}.json")
        model_path = os.path.join(PROFILES_DIR, f"{safe_name}.model.joblib")

        payload = {
            "host_id": self.host_id,
            "state": self.state,
            "target_events": self.target_events,
            "events_observed": self.events_observed,
            "calibrated_threshold": self.calibrated_threshold,
            "learning_started_at": self.learning_started_at,
            "enforcing_since": self.enforcing_since,
            "known_lineage": [list(p) for p in self.known_lineage],
            "known_binaries": list(self.known_binaries),
            "observed_vectors": self.observed_vectors[-100:]
        }
        try:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            if self.custom_model is not None and joblib is not None:
                joblib.dump(self.custom_model, model_path)
        except Exception as e:
            logger.error(f"Error persisting profile for {self.host_id}: {e}")

    @classmethod
    def load_from_disk(cls, host_id: str) -> Optional["HostLearningProfile"]:
        """Loads persisted profile and model from disk if available."""
        safe_name = re.sub(r"[^A-Za-z0-9_-]", "_", host_id)
        json_path = os.path.join(PROFILES_DIR, f"{safe_name}.json")
        model_path = os.path.join(PROFILES_DIR, f"{safe_name}.model.joblib")

        if not os.path.isfile(json_path):
            return None

        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            profile = cls(data["host_id"], target_events=data.get("target_events", 50))
            profile.state = data.get("state", "LEARNING")
            profile.events_observed = data.get("events_observed", 0)
            profile.calibrated_threshold = data.get("calibrated_threshold", -0.10)
            profile.learning_started_at = data.get("learning_started_at", time.time())
            profile.enforcing_since = data.get("enforcing_since")
            profile.known_lineage = set(tuple(p) for p in data.get("known_lineage", []))
            profile.known_binaries = set(data.get("known_binaries", []))
            profile.observed_vectors = data.get("observed_vectors", [])

            if os.path.isfile(model_path) and joblib is not None:
                try:
                    profile.custom_model = joblib.load(model_path)
                except Exception as ex:
                    logger.debug(f"Could not load custom model for {host_id}: {ex}")
            return profile
        except Exception as e:
            logger.error(f"Failed to load profile for {host_id}: {e}")
            return None

    def ingest_learning_event(self, vector: List[float], meta: Dict[str, Any]) -> bool:
        """
        Record normal event during learning mode.
        Returns True if host just graduated to ENFORCING mode.
        """
        self.events_observed += 1
        self.observed_vectors.append(vector)

        proc = meta.get("proc_name")
        parent = meta.get("parent")
        if proc:
            self.known_binaries.add(proc)
        if parent and proc:
            self.known_lineage.add((parent, proc))

        if self.events_observed >= self.target_events and self.state == "LEARNING":
            self.finalize_calibration()
            return True
        elif self.events_observed % 5 == 0:
            self.save_to_disk()
        return False

    def finalize_calibration(self):
        """Fits custom Isolation Forest on the host's real observed telemetry."""
        if not SKLEARN_AVAILABLE or len(self.observed_vectors) < 10:
            self.state = "ENFORCING"
            self.enforcing_since = time.time()
            self.save_to_disk()
            return

        try:
            X = np.array(self.observed_vectors, dtype=np.float32)
            model = IsolationForest(
                n_estimators=50,
                contamination=0.02,
                random_state=42
            )
            model.fit(X)
            scores = model.decision_function(X)
            self.calibrated_threshold = float(np.percentile(scores, 2.0))
            self.custom_model = model
            self.state = "ENFORCING"
            self.enforcing_since = time.time()
            self.save_to_disk()
            logger.info(
                f"[LEARNING MODE] Host '{self.host_id}' successfully calibrated! "
                f"Trained on {len(X)} events. Threshold: {self.calibrated_threshold:.3f}. Switched to ENFORCING."
            )
        except Exception as e:
            logger.error(f"Failed to calibrate host model for {self.host_id}: {e}")
            self.state = "ENFORCING"
            self.enforcing_since = time.time()
            self.save_to_disk()

    def get_summary(self) -> Dict[str, Any]:
        return {
            "host_id": self.host_id,
            "state": self.state,
            "progress": f"{self.events_observed}/{self.target_events}" if self.state == "LEARNING" else "COMPLETED",
            "events_observed": self.events_observed,
            "target_events": self.target_events,
            "known_lineages_count": len(self.known_lineage),
            "known_binaries_count": len(self.known_binaries),
            "calibrated_threshold": round(self.calibrated_threshold, 3),
            "learning_started_at": self.learning_started_at,
            "enforcing_since": self.enforcing_since
        }


class LocalMLEndpointEngine:
    """
    On-premise ML threat inference engine for endpoint event analysis.
    Supports Persistent Host Learning Mode and Active Enforcing Mode.
    """
    _iso_forest: Optional[Any] = None
    _HOST_PROFILES: Dict[str, HostLearningProfile] = {}

    @classmethod
    def get_host_profile(cls, host_id: str, auto_create: bool = True, target_events: int = 50) -> Optional[HostLearningProfile]:
        """Fetch or initialize a learning profile for an endpoint (loading from disk if saved)."""
        norm_id = (host_id or "DEFAULT_HOST").upper()
        if norm_id not in cls._HOST_PROFILES:
            disk_profile = HostLearningProfile.load_from_disk(norm_id)
            if disk_profile is not None:
                cls._HOST_PROFILES[norm_id] = disk_profile
            elif auto_create:
                profile = HostLearningProfile(norm_id, target_events=target_events)
                profile.save_to_disk()
                cls._HOST_PROFILES[norm_id] = profile
        return cls._HOST_PROFILES.get(norm_id)

    @classmethod
    def list_all_profiles(cls) -> List[Dict[str, Any]]:
        """List learning summaries for all managed endpoints, including those persisted on disk."""
        if os.path.isdir(PROFILES_DIR):
            for fname in os.listdir(PROFILES_DIR):
                if fname.endswith(".json"):
                    host_name = fname[:-5]
                    if host_name not in cls._HOST_PROFILES:
                        loaded = HostLearningProfile.load_from_disk(host_name)
                        if loaded:
                            cls._HOST_PROFILES[host_name] = loaded
        return [p.get_summary() for p in cls._HOST_PROFILES.values()]

    @classmethod
    def reset_host_learning(cls, host_id: str, target_events: int = 50) -> Dict[str, Any]:
        """Reset host baseline and re-enter LEARNING mode."""
        norm_id = (host_id or "DEFAULT_HOST").upper()
        profile = HostLearningProfile(norm_id, target_events=target_events)
        profile.save_to_disk()
        cls._HOST_PROFILES[norm_id] = profile
        return profile.get_summary()

    @classmethod
    def force_enforce_host(cls, host_id: str) -> Dict[str, Any]:
        """Immediately conclude learning mode and enter ENFORCING mode."""
        profile = cls.get_host_profile(host_id, auto_create=True)
        profile.finalize_calibration()
        return profile.get_summary()

    @classmethod
    def _init_isolation_forest(cls):
        """Initializes and pre-fits the default Isolation Forest baseline model."""
        if not SKLEARN_AVAILABLE or cls._iso_forest is not None:
            return
        try:
            X = np.array(_BASELINE_TRAINING_CORPUS, dtype=np.float32)
            cls._iso_forest = IsolationForest(
                n_estimators=50,
                contamination=0.08,
                random_state=42
            )
            cls._iso_forest.fit(X)
            logger.info("Local Isolation Forest baseline successfully calibrated.")
        except Exception as e:
            logger.error(f"Failed to fit Isolation Forest: {e}")
            cls._iso_forest = None

    @staticmethod
    def calculate_shannon_entropy(text: str) -> float:
        """Calculates Shannon Entropy (H) of a string."""
        if not text:
            return 0.0
        length = len(text)
        counts = {}
        for c in text:
            counts[c] = counts.get(c, 0) + 1
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 3)

    @classmethod
    def extract_features(cls, event: Dict[str, Any]) -> Tuple[List[float], Dict[str, Any]]:
        """Extracts numerical and categorical behavioral features from normalized telemetry."""
        cmdline = event.get("command_line") or ""
        proc_name = (event.get("process_name") or "").lower()
        parent = (event.get("parent_process") or "").lower()

        cmd_len = float(len(cmdline))
        entropy = cls.calculate_shannon_entropy(cmdline)

        # Ratios of special characters and digits
        special_count = len(re.findall(r"[-/\\;:|^&%$#@!]", cmdline))
        special_ratio = special_count / max(cmd_len, 1.0)

        digit_count = len(re.findall(r"\d", cmdline))
        digit_ratio = digit_count / max(cmd_len, 1.0)

        is_lolbin = 1.0 if proc_name in LOLBINS else 0.0
        is_suspicious_parent = 1.0 if any(p in parent for p in OFFICE_OR_BROWSER_PARENTS) else 0.0

        vector = [cmd_len, entropy, special_ratio, digit_ratio, is_lolbin, is_suspicious_parent]
        meta = {
            "cmd_len": cmd_len,
            "entropy": entropy,
            "special_ratio": round(special_ratio, 3),
            "digit_ratio": round(digit_ratio, 3),
            "is_lolbin": bool(is_lolbin),
            "is_suspicious_parent": bool(is_suspicious_parent),
            "proc_name": proc_name,
            "parent": parent,
            "cmdline": cmdline
        }
        return vector, meta

    @classmethod
    def evaluate_telemetry(cls, event: Dict[str, Any], force_enforce: bool = False) -> Optional[Dict[str, Any]]:
        """
        Runs ML inference on a telemetry event for the central pipeline.
        Returns None if normal or during LEARNING mode (suppressed).
        Returns an Alert dictionary if risk >= 50.0 in ENFORCING mode.
        """
        detailed = cls.analyze_detailed(event, force_enforce=force_enforce)
        if detailed.get("is_alert"):
            return {
                "alert_id": f"ML-ALT-{uuid.uuid4().hex[:8].upper()}",
                "rule_id": "ML-ANOMALY-001",
                "rule_name": f"Local ML Anomaly: {detailed['features']['proc_name']} Suspicious Execution",
                "title": f"Local ML Threat Insight: High Risk Process ({detailed['features']['proc_name']})",
                "description": f"Local ML engine flagged process execution with risk score {detailed['risk_score']}/100. Factors: {'; '.join(detailed['factors'])}",
                "severity": detailed["severity"],
                "confidence": 0.91,
                "risk_score": detailed["risk_score"],
                "mitre_tactic": detailed["mitre_tactic"],
                "mitre_technique": detailed["mitre_technique"],
                "mitre_subtechnique": "Behavioral Anomaly & LOLBin Abuse",
                "factors": detailed["factors"],
                "features": detailed["features"],
                "timestamp": event.get("timestamp") or time.time(),
                "affected_host": event.get("hostname") or "DEFAULT_HOST",
                "affected_user": event.get("user_identity"),
                "source_ip": event.get("source_ip"),
                "mode": event.get("mode", "LIVE")
            }
        return None

    @classmethod
    def analyze_detailed(cls, event: Dict[str, Any], force_enforce: bool = False) -> Dict[str, Any]:
        """
        Detailed on-demand ML evaluation returning risk score, factors, and verdict.
        Does not silence low/medium risk scores so analysts can inspect factor contributions.
        """
        cls._init_isolation_forest()
        vector, meta = cls.extract_features(event)

        host_id = event.get("hostname") or event.get("affected_host") or "DEFAULT_HOST"
        profile = cls.get_host_profile(host_id, auto_create=True)

        is_benign = meta["proc_name"] in BENIGN_SOFTWARE_BINARIES
        cmd_lower = meta["cmdline"].lower()

        # Check for explicit high-severity attack signatures
        is_credential_dump = any(dump in cmd_lower for dump in ["lsass", "procdump", "sekurlsa", "comsvcs"])
        is_shadow_delete = any(shadow in cmd_lower for shadow in ["vssadmin.*delete", "shadowcopy.*delete"])
        is_hard_attack = is_credential_dump or is_shadow_delete

        # In live pipeline with learning mode active (unless test mode or force enforce)
        is_test_mode = event.get("mode") == "TEST" or force_enforce
        if profile.state == "LEARNING" and not is_hard_attack and not is_test_mode:
            graduated = profile.ingest_learning_event(vector, meta)
            return {
                "verdict": "LEARNING_OBSERVED",
                "risk_score": 0.0,
                "severity": "INFORMATIONAL",
                "factors": [f"Host in LEARNING mode: Event recorded to baseline profile ({profile.events_observed}/{profile.target_events})"],
                "is_alert": False,
                "features": meta,
                "mitre_tactic": "None",
                "mitre_technique": "None",
                "learning_state": profile.get_summary()
            }

        risk_score = 0.0
        factors = []
        mitre_tactic = "Execution"
        mitre_technique = "T1059"

        # Suppress routine benign system, developer, browser, and IDE binaries
        if is_benign and not is_hard_attack:
            return {
                "verdict": "BENIGN",
                "risk_score": 15.0,
                "severity": "INFORMATIONAL",
                "factors": ["Process conforms to verified benign system/developer profile"],
                "is_alert": False,
                "features": meta,
                "mitre_tactic": "None",
                "mitre_technique": "None"
            }

        # 1. Isolation Forest Anomaly Scoring
        active_model = profile.custom_model if (profile.custom_model is not None) else cls._iso_forest
        threshold = profile.calibrated_threshold if (profile.custom_model is not None) else 0.0

        if active_model is not None and SKLEARN_AVAILABLE and not is_benign:
            try:
                X_sample = np.array([vector], dtype=np.float32)
                pred = active_model.predict(X_sample)[0]
                decision_score = active_model.decision_function(X_sample)[0]

                if pred == -1 or decision_score < threshold:
                    anomaly_weight = min(abs(float(decision_score)) * 60.0 + 15.0, 25.0)
                    risk_score += anomaly_weight
                    factors.append(
                        f"Isolation Forest Anomaly: Process vector deviated from learned baseline (Score: {round(decision_score, 3)}, Threshold: {round(threshold, 3)})"
                    )
            except Exception as e:
                logger.debug(f"Isolation forest inference error: {e}")

        # 2. Novel Process Lineage Check (Learned Allowlist)
        # Evaluates if lineage is unseen AND suspicious (LOLBin or suspicious parent)
        if (profile.state == "ENFORCING" or force_enforce) and profile.known_lineage:
            pair = (meta["parent"], meta["proc_name"])
            if pair not in profile.known_lineage:
                if meta["is_lolbin"] or meta["is_suspicious_parent"]:
                    risk_score += 20.0
                    factors.append(
                        f"Unseen Suspicious Lineage: '{meta['parent']}' -> '{meta['proc_name']}' was never observed during host learning baseline"
                    )
                else:
                    factors.append(f"Novel benign process pair '{meta['parent']}' -> '{meta['proc_name']}' (within safe tolerances)")

        # 3. Shannon Entropy & Obfuscation Analysis
        has_encoded_keyword = any(k in cmd_lower for k in ["-enc", "-encodedcommand", "base64", "frombase64", "iex(", "invoke-expression"])
        is_obf_suspect = has_encoded_keyword or (meta["entropy"] >= 5.5 and meta["cmd_len"] >= 80)
        if meta["entropy"] >= 4.6 and meta["cmd_len"] >= 40 and is_obf_suspect and not is_benign:
            risk_score += 40.0
            mitre_tactic = "Defense Evasion"
            mitre_technique = "T1027"
            factors.append(
                f"Obfuscation Indicator: High command-line Shannon entropy ({meta['entropy']:.2f}) indicates Base64 or encrypted payload"
            )

        # 4. Rare Parent-Child Process Lineage
        if meta["is_suspicious_parent"] and meta["is_lolbin"]:
            risk_score += 45.0
            mitre_tactic = "Execution"
            mitre_technique = "T1204.002"
            factors.append(
                f"Abnormal Process Lineage: Office/Browser parent ({meta['parent']}) spawned script engine ({meta['proc_name']})"
            )

        # 5. Living-off-the-Land Ingress / Download Cradle Analysis
        if any(cradle in cmd_lower for cradle in ["downloadstring", "invoke-expression", "iex", "webclient", "-enc", "-encodedcommand"]):
            risk_score += 45.0
            mitre_tactic = "Execution"
            mitre_technique = "T1059.001"
            factors.append("Download Cradle / Dynamic Script Execution pattern detected in arguments")

        # 6. Credential Dumping Heuristic
        if is_credential_dump:
            risk_score += 50.0
            mitre_tactic = "Credential Access"
            mitre_technique = "T1003.001"
            factors.append("Credential harvesting artifact detected targeting LSASS memory")

        final_risk = min(max(round(risk_score, 1), 0.0), 100.0)
        has_exploit_indicator = is_hard_attack or any(k in cmd_lower for k in ["downloadstring", "-enc", "iex", "base64", "http", "cradle"])
        is_alert = (final_risk >= 50.0 and has_exploit_indicator) or final_risk >= 75.0
        risk_tier = "CRITICAL" if final_risk >= 85 else "HIGH" if final_risk >= 65 else "MEDIUM" if final_risk >= 50 else "LOW" if final_risk >= 20 else "INFORMATIONAL"

        verdict = "ANOMALY_DETECTED" if is_alert else ("SUSPICIOUS" if final_risk >= 30 else "BENIGN")

        return {
            "verdict": verdict,
            "risk_score": final_risk,
            "severity": risk_tier,
            "is_alert": is_alert,
            "factors": factors if factors else ["Process conforms to baseline distribution", "Normal entropy range"],
            "features": meta,
            "mitre_tactic": mitre_tactic if is_alert else "None",
            "mitre_technique": mitre_technique if is_alert else "None"
        }
