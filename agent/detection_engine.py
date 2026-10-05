"""
CyberFusion XDR Enterprise - Endpoint Detection & Correlation Engine
Evaluates endpoint telemetry locally:
1. Relevance Filtering (Eliminates OS noise & loopbacks, keeps security-vital events)
2. Behavioral Heuristic Rules (LOLBins, MITRE ATT&CK TTPs)
3. Online OSINT Threat Intelligence Correlation (AlienVault OTX, Feodo Tracker, CIRCL)
"""
import os
import re
import math
import hashlib
import logging
from typing import Dict, Any, List, Optional, Tuple
from osint_engine import osint_engine

logger = logging.getLogger("cyberfusion_agent.detection")

SUSPICIOUS_BINARIES = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
    "vssadmin.exe", "schtasks.exe", "sc.exe", "net.exe", "net1.exe", "whoami.exe",
    "nltest.exe", "systeminfo.exe", "taskkill.exe", "wmic.exe", "msbuild.exe",
    "installutil.exe", "reg.exe", "at.exe", "curl.exe", "wget.exe", "ncat.exe",
    "nc.exe", "psexec.exe", "bash", "sh", "zsh", "python.exe", "perl.exe"
}

SUSPICIOUS_CMD_PATTERNS = [
    (r"-(?:enc|encodedcommand)\b", "PowerShell Base64 Encoded Execution", "T1059.001", "CRITICAL"),
    (r"-bypass\b", "Execution Policy Bypass", "T1059.001", "HIGH"),
    (r"downloadstring\b", "Web Script Cradle In-Memory Download", "T1105", "CRITICAL"),
    (r"\biex\b|invoke-expression", "Invoke-Expression Dynamic Script Execution", "T1059.001", "HIGH"),
    (r"mimikatz|sekurlsa|wdigest|kerberos::", "Credential Dumping Artifact", "T1003", "CRITICAL"),
    (r"procdump.*lsass|comsvcs.*minidump", "LSASS Memory Dump Attempt", "T1003.001", "CRITICAL"),
    (r"vssadmin.*delete.*shadows", "Shadow Copy Deletion / Ransomware Prep", "T1490", "CRITICAL"),
    (r"wmic.*shadowcopy.*delete", "WMI Shadow Copy Deletion", "T1490", "CRITICAL"),
    (r"net\s+user\s+\w+\s+/add", "Unauthorized Local User Account Creation", "T1136.001", "HIGH"),
    (r"net\s+localgroup\s+administrators\s+\w+\s+/add", "Privilege Escalation to Admin Group", "T1078", "CRITICAL"),
    (r"reg\s+add.*\\(?:run|runonce)", "Registry Autorun Persistence Modification", "T1547.001", "HIGH"),
    (r"schtasks\s+/create", "Scheduled Task Persistence Creation", "T1053.005", "MEDIUM"),
    (r"certutil.*-urlcache.*-split", "CertUtil Living-off-the-Land Ingress Transfer", "T1105", "HIGH"),
    (r"bitsadmin.*/transfer", "Bitsadmin Ingress Transfer", "T1105", "MEDIUM"),
    (r"windowstyle\s+hidden|-w\s+hidden", "Hidden Window Process Launch", "T1564.003", "MEDIUM"),
    (r"nltest.*/dclist|nltest.*/domain_trusts", "Active Directory Domain Trust Discovery", "T1482", "HIGH"),
]

SUSPICIOUS_PORTS = {
    4444: ("Metasploit / Cobalt Strike Default C2", "T1071"),
    1337: ("Elite / Hacker Custom Listener", "T1071"),
    6667: ("IRC Botnet Control Channel", "T1071"),
    8888: ("Non-standard HTTP Alternate C2", "T1071.001"),
    9001: ("TOR / Alternate Proxy Port", "T1090"),
    9050: ("TOR SOCKS Proxy Listener", "T1090"),
    5555: ("Suspicious Reverse Shell Port", "T1071"),
    3389: ("RDP Outbound Lateral Traversal", "T1021.001"),
    22: ("SSH Direct Outbound Shell", "T1021.004")
}

SUSPICIOUS_PATHS = [
    r"\\appdata\\local\\temp",
    r"\\appdata\\roaming",
    r"\\users\\public",
    r"\\programdata\\",
    r"^/tmp/",
    r"^/dev/shm/",
    r"^/var/tmp/"
]

def calculate_sha256(file_path: str) -> Optional[str]:
    """Calculate SHA-256 hash of a local executable if readable."""
    if not file_path or not os.path.isfile(file_path):
        return None
    try:
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return None

class EndpointDetectionEngine:
    @staticmethod
    def is_relevant_process(name: str, cmdline: str, exe_path: Optional[str] = None) -> Tuple[bool, str]:
        """
        Determines if a process execution is security-relevant:
        - True if LOLBin, script engine, suspicious args, or executed from temp path.
        - False if mundane background OS process.
        """
        name_lower = (name or "").lower()
        cmd_lower = (cmdline or "").lower()
        path_lower = (exe_path or "").lower()

        # 1. Check known LOLBins & Script Engines
        if name_lower in SUSPICIOUS_BINARIES:
            return True, f"High-risk binary / script engine execution: {name}"

        # 2. Check suspicious command line patterns
        for pattern, desc, _, _ in SUSPICIOUS_CMD_PATTERNS:
            if re.search(pattern, cmd_lower):
                return True, f"Suspicious command line pattern: {desc}"

        # 2b. Filter out routine benign browser, WebView, and IDE subprocesses
        if name_lower in ["msedgewebview2.exe", "msedge.exe", "chrome.exe", "firefox.exe", "brave.exe", "opera.exe", "antigravity ide.exe", "code.exe"]:
            if any(sw in cmd_lower for sw in ["--type=", "--field-trial-handle", "--mojo-platform-channel-handle", "--user-data-dir"]):
                return False, "Benign browser/WebView worker subprocess"

        # 3. Check execution from suspicious directories
        for sp in SUSPICIOUS_PATHS:
            if re.search(sp, path_lower) or re.search(sp, cmd_lower):
                return True, f"Binary executed from user-writable / temporary directory"

        # 4. Check for URL / IP in arguments
        if "http://" in cmd_lower or "https://" in cmd_lower or re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", cmd_lower):
            return True, "Process invoked with embedded network URL/IP argument"

        # Otherwise noise
        return False, "Standard OS process execution"

    @staticmethod
    def is_relevant_network(dest_ip: str, dest_port: int, process_name: Optional[str] = None) -> Tuple[bool, str]:
        """
        Filters network connections:
        - Discards loopback / RFC1918 internal noise (unless on suspicious port).
        - Keeps outbound connections to external public IPs.
        - Keeps connections to suspicious ports.
        """
        if not dest_ip:
            return False, "Missing IP"

        is_private = osint_engine.is_private_or_loopback_ip(dest_ip)
        proc_lower = (process_name or "").lower()

        # Discard loopback
        if dest_ip in ["127.0.0.1", "::1", "0.0.0.0", "localhost"]:
            return False, "Loopback connection"

        # Suspicious port check
        if dest_port in SUSPICIOUS_PORTS:
            return True, f"Connection to suspicious port {dest_port} ({SUSPICIOUS_PORTS[dest_port][0]})"

        # External IP check
        if not is_private:
            return True, f"Outbound connection to public internet IP {dest_ip}:{dest_port}"

        # Script interpreter making network socket
        if proc_lower in SUSPICIOUS_BINARIES:
            return True, f"Script engine {process_name} established network socket"

        return False, "Routine private internal connection"

    @staticmethod
    def evaluate_process_telemetry(event: Dict[str, Any], exe_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Evaluates a process event with local heuristics and OSINT hash lookup.
        """
        name = event.get("process_name", "")
        cmd = event.get("command_line", "")
        cmd_lower = cmd.lower()

        verdict = "BENIGN"
        risk_score = 10
        severity = "LOW"
        reasons = []
        mitre_tactics = []
        mitre_techniques = []

        # Check heuristics
        for pattern, desc, tech, sev in SUSPICIOUS_CMD_PATTERNS:
            if re.search(pattern, cmd_lower):
                reasons.append(desc)
                mitre_techniques.append(tech)
                if sev == "CRITICAL":
                    verdict = "MALICIOUS"
                    risk_score = max(risk_score, 95)
                    severity = "CRITICAL"
                elif sev == "HIGH":
                    verdict = "SUSPICIOUS" if verdict != "MALICIOUS" else verdict
                    risk_score = max(risk_score, 80)
                    severity = "HIGH" if severity != "CRITICAL" else severity
                elif sev == "MEDIUM":
                    risk_score = max(risk_score, 50)
                    severity = "MEDIUM" if severity not in ["CRITICAL", "HIGH"] else severity

        # Edge ML Obfuscation Analysis (Shannon Entropy)
        is_benign_bin = name.lower() in [
            "msedgewebview2.exe", "msedge.exe", "chrome.exe", "firefox.exe", "brave.exe",
            "explorer.exe", "svchost.exe", "code.exe", "antigravity ide.exe", "node.exe", "git.exe"
        ]
        has_obf_token = any(k in cmd_lower for k in ["-enc", "-encodedcommand", "base64", "frombase64", "iex", "invoke-expression", "downloadstring"])
        if len(cmd) > 40 and not is_benign_bin:
            prob = [float(cmd.count(c)) / len(cmd) for c in set(cmd)]
            entropy = -sum(p * math.log2(p) for p in prob)
            if (has_obf_token and entropy >= 4.6) or (entropy >= 5.5 and len(cmd) >= 100):
                reasons.append(f"Edge ML Anomaly: High Shannon entropy ({entropy:.2f}) indicates obfuscated/base64 payload")
                mitre_tactics.append("Defense Evasion")
                mitre_techniques.append("T1027")
                verdict = "SUSPICIOUS" if verdict != "MALICIOUS" else verdict
                risk_score = max(risk_score, 78)
                severity = "HIGH" if severity != "CRITICAL" else severity

        # Calculate file hash if available
        file_hash = event.get("file_hash") or calculate_sha256(exe_path)
        if file_hash:
            event["file_hash"] = file_hash
            # Correlate with OSINT Hashlookup (CIRCL & AlienVault) only if suspicious or script engine
            if reasons or name.lower() in SUSPICIOUS_BINARIES or "temp" in (exe_path or "").lower():
                hash_intel = osint_engine.lookup_hash_reputation(file_hash)
                if hash_intel.get("is_malicious"):
                    verdict = "MALICIOUS"
                    risk_score = max(risk_score, 99)
                    severity = "CRITICAL"
                    reasons.extend(hash_intel.get("reasons", []))
                    event["osint_intel"] = hash_intel

        if name.lower() in SUSPICIOUS_BINARIES:
            mitre_tactics.append("Execution")
            if verdict == "BENIGN":
                verdict = "INFORMATIONAL"
                risk_score = max(risk_score, 30)

        event["threat_verdict"] = verdict
        event["risk_score"] = risk_score
        event["severity"] = severity
        event["is_malicious"] = verdict == "MALICIOUS"
        event["detection_reasons"] = reasons
        event["mitre_tactics"] = list(set(mitre_tactics))
        event["mitre_techniques"] = list(set(mitre_techniques))
        return event

    @staticmethod
    def evaluate_network_telemetry(event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates a network connection with OSINT correlation (Abuse.ch Feodo Tracker + AlienVault OTX).
        """
        dest_ip = event.get("dest_ip", "")
        dest_port = event.get("dest_port", 0)

        verdict = "BENIGN"
        risk_score = 15
        severity = "INFORMATIONAL"
        reasons = []
        mitre_tactics = []
        mitre_techniques = []

        # Check suspicious port
        if dest_port in SUSPICIOUS_PORTS:
            desc, tech = SUSPICIOUS_PORTS[dest_port]
            reasons.append(desc)
            mitre_techniques.append(tech)
            mitre_tactics.append("Command and Control")
            verdict = "SUSPICIOUS"
            risk_score = 75
            severity = "HIGH"

        # Correlate with live OSINT
        if not osint_engine.is_private_or_loopback_ip(dest_ip):
            ip_intel = osint_engine.lookup_ip_reputation(dest_ip)
            event["osint_intel"] = ip_intel

            if ip_intel.get("is_malicious"):
                verdict = "MALICIOUS"
                risk_score = max(risk_score, ip_intel.get("threat_score", 95))
                severity = "CRITICAL"
                mitre_tactics.append("Command and Control")
                mitre_techniques.append("T1071")
                reasons.extend(ip_intel.get("reasons", []))
            elif ip_intel.get("verdict") == "SUSPICIOUS":
                verdict = "SUSPICIOUS" if verdict != "MALICIOUS" else verdict
                risk_score = max(risk_score, 45)
                severity = "MEDIUM" if severity not in ["CRITICAL", "HIGH"] else severity
                reasons.extend(ip_intel.get("reasons", []))
            else:
                reasons.append("External Internet Communication")
                risk_score = 10

        event["threat_verdict"] = verdict
        event["risk_score"] = risk_score
        event["severity"] = severity
        event["is_malicious"] = verdict == "MALICIOUS"
        event["detection_reasons"] = reasons
        event["mitre_tactics"] = list(set(mitre_tactics))
        event["mitre_techniques"] = list(set(mitre_techniques))
        return event

detection_engine = EndpointDetectionEngine()
