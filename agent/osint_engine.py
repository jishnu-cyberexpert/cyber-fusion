"""
CyberFusion XDR Enterprise - Endpoint OSINT Intelligence Engine
Integrates live Open Source Intelligence (OSINT) tools:
- AlienVault OTX (Open Threat Exchange) Indicator Intelligence
- Abuse.ch Feodo Tracker (Botnet & Ransomware C2 IP Blocklist)
- CIRCL Hash Lookup (National CERT Luxembourg NSRL & Malware Hash DB)
- Cloudflare DoH & Reverse DNS Intelligence
"""
import time
import socket
import ipaddress
import logging
from typing import Dict, Any, Optional, List
import httpx

KNOWN_BENIGN_PUBLIC_RESOLVERS = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112"
}

# Major public cloud and CDN network CIDRs to prevent false positives from generic community pulses
TRUSTED_CLOUD_NETWORKS = [
    # Google Infrastructure & Google Cloud
    ipaddress.ip_network("8.8.8.0/24"),
    ipaddress.ip_network("8.8.4.0/24"),
    ipaddress.ip_network("172.217.0.0/16"),
    ipaddress.ip_network("142.250.0.0/15"),  # 142.250.0.0 - 142.251.255.255
    ipaddress.ip_network("74.125.0.0/16"),
    ipaddress.ip_network("216.58.192.0/19"),
    ipaddress.ip_network("173.194.0.0/16"),
    ipaddress.ip_network("34.64.0.0/10"),
    ipaddress.ip_network("34.120.0.0/16"),
    ipaddress.ip_network("35.184.0.0/13"),
    ipaddress.ip_network("35.192.0.0/11"),
    ipaddress.ip_network("35.224.0.0/11"),
    # Cloudflare Anycast & CDN
    ipaddress.ip_network("1.1.1.0/24"),
    ipaddress.ip_network("1.0.0.0/24"),
    ipaddress.ip_network("172.64.0.0/13"),
    ipaddress.ip_network("104.16.0.0/12"),  # 104.16.0.0 - 104.31.255.255
    ipaddress.ip_network("108.162.192.0/18"),
    ipaddress.ip_network("162.158.0.0/15"),
    ipaddress.ip_network("198.41.128.0/17"),
    ipaddress.ip_network("197.234.240.0/22"),
    ipaddress.ip_network("188.114.96.0/20"),
    ipaddress.ip_network("190.93.240.0/20"),
    ipaddress.ip_network("141.101.64.0/18"),
    ipaddress.ip_network("131.0.72.0/22"),
    # Microsoft Azure / Windows Update / Office 365
    ipaddress.ip_network("20.0.0.0/8"),
    ipaddress.ip_network("52.0.0.0/8"),
    ipaddress.ip_network("40.64.0.0/10"),
    ipaddress.ip_network("150.171.0.0/16"),
    ipaddress.ip_network("13.64.0.0/11"),
    ipaddress.ip_network("13.96.0.0/13"),
    ipaddress.ip_network("13.104.0.0/14"),
    # Fastly CDN
    ipaddress.ip_network("151.101.0.0/16"),
    ipaddress.ip_network("199.232.0.0/16"),
    ipaddress.ip_network("146.75.0.0/16"),
    # Akamai Technologies
    ipaddress.ip_network("23.0.0.0/8"),
    ipaddress.ip_network("104.64.0.0/10"),
    # Amazon AWS
    ipaddress.ip_network("3.0.0.0/8"),
    ipaddress.ip_network("54.0.0.0/8"),
]

TRUSTED_CLOUD_SUFFIXES = (
    ".1e100.net", ".google.com", ".microsoft.com", ".azure.com",
    ".windowsupdate.com", ".msftncsi.com", ".cloudflare.com",
    ".akamaitechnologies.com", ".akadns.net", ".fastly.net", ".amazonaws.com"
)

# High-confidence malicious indicator keywords in AlienVault pulses
HIGH_CONFIDENCE_MALWARE_TAGS = {
    "c2", "command and control", "command-and-control", "botnet", "ransomware",
    "cobalt strike", "cobaltstrike", "meterpreter", "rat", "trojan", "feodo", "emotet"
}

logger = logging.getLogger("cyberfusion_agent.osint")

class OSINTEngine:
    def __init__(self):
        self._http_client = httpx.Client(
            timeout=4.0,
            verify=False,
            headers={"User-Agent": "CyberFusion-EDR-OSINT-Agent/3.4"}
        )
        # In-memory caches with TTL (3600 seconds)
        self._ip_cache: Dict[str, Dict[str, Any]] = {}
        self._hash_cache: Dict[str, Dict[str, Any]] = {}
        self._feodo_c2_set: Dict[str, Dict[str, Any]] = {}
        self._last_feodo_sync: float = 0.0

    def is_private_or_loopback_ip(self, ip_str: str) -> bool:
        """Check if an IP address is loopback, link-local, or RFC1918 private."""
        if not ip_str or ip_str in ["127.0.0.1", "::1", "0.0.0.0", "localhost"]:
            return True
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved
        except ValueError:
            return True

    def is_trusted_cloud_or_cdn(self, ip_str: str) -> bool:
        """Check if an IP belongs to well-known CDN or Cloud provider ranges."""
        if ip_str in KNOWN_BENIGN_PUBLIC_RESOLVERS:
            return True
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return any(ip_obj in net for net in TRUSTED_CLOUD_NETWORKS)
        except ValueError:
            return False

    def sync_feodo_c2_feed(self, force: bool = False):
        """Fetch real-time Botnet / Ransomware C2 blocklist from Abuse.ch Feodo Tracker."""
        now = time.time()
        if not force and (now - self._last_feodo_sync < 1800) and self._feodo_c2_set:
            return

        try:
            resp = self._http_client.get("https://feodotracker.abuse.ch/downloads/ipblocklist.json")
            if resp.status_code == 200:
                data = resp.json()
                new_set = {}
                for item in data:
                    ip = item.get("ip_address")
                    if ip:
                        new_set[ip] = {
                            "malware": item.get("malware", "Unknown C2"),
                            "status": item.get("status", "active"),
                            "port": item.get("port"),
                            "first_seen": item.get("first_seen_utc")
                        }
                self._feodo_c2_set = new_set
                self._last_feodo_sync = now
                logger.info(f"Synchronized Abuse.ch Feodo Tracker: {len(self._feodo_c2_set)} active C2 indicators loaded.")
        except Exception as ex:
            logger.warning(f"Could not refresh Feodo Tracker C2 feed: {ex}")

    def lookup_ip_reputation(self, ip_str: str) -> Dict[str, Any]:
        """
        Correlate an external destination IP with online OSINT tools:
        1. Abuse.ch Feodo Tracker
        2. AlienVault OTX Indicator API
        3. Reverse DNS / PTR
        """
        if self.is_private_or_loopback_ip(ip_str):
            return {"verdict": "INTERNAL", "is_malicious": False}

        now = time.time()
        # Check cache
        if ip_str in self._ip_cache:
            entry = self._ip_cache[ip_str]
            if now - entry["cached_at"] < 3600:
                return entry["data"]

        # Check Feodo C2 blocklist first
        self.sync_feodo_c2_feed()
        if ip_str in self._feodo_c2_set:
            c2_info = self._feodo_c2_set[ip_str]
            result = {
                "ip": ip_str,
                "verdict": "MALICIOUS",
                "is_malicious": True,
                "threat_score": 98,
                "sources": ["Abuse.ch Feodo Tracker"],
                "reasons": [f"Confirmed Botnet C2 ({c2_info['malware']})"],
                "c2_info": c2_info
            }
            self._ip_cache[ip_str] = {"cached_at": now, "data": result}
            return result

        # Check trusted cloud / CDN CIDRs (Google, Cloudflare, Microsoft, Fastly, Akamai, AWS)
        if self.is_trusted_cloud_or_cdn(ip_str):
            result = {
                "ip": ip_str,
                "verdict": "BENIGN",
                "is_malicious": False,
                "threat_score": 0,
                "sources": ["Trusted Cloud / CDN Infrastructure"],
                "reasons": ["Verified major public cloud or CDN provider IP range"]
            }
            self._ip_cache[ip_str] = {"cached_at": now, "data": result}
            return result

        result = {
            "ip": ip_str,
            "verdict": "BENIGN",
            "is_malicious": False,
            "threat_score": 0,
            "sources": [],
            "reasons": []
        }

        # 2. AlienVault OTX Public Indicator Lookup for unknown external IPs
        try:
            otx_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_str}/general"
            resp = self._http_client.get(otx_url)
            if resp.status_code == 200:
                otx_data = resp.json()
                pulse_info = otx_data.get("pulse_info", {})
                pulse_count = pulse_info.get("count", 0)
                reputation = otx_data.get("reputation", 0)

                pulses = pulse_info.get("pulses", [])
                threat_tags = set()
                pulse_names = []
                for p in pulses[:5]:
                    pulse_names.append(p.get("name", ""))
                    for t in p.get("tags", []):
                        threat_tags.add(t.lower())

                if pulse_count > 0 or reputation < 0:
                    result["sources"].append("AlienVault OTX")
                    result["pulse_count"] = pulse_count
                    result["otx_reputation"] = reputation
                    result["threat_tags"] = list(threat_tags)[:8]
                    result["pulse_names"] = pulse_names

                    # Determine if high confidence threat tags are present
                    has_c2_tag = any(ct in threat_tags for ct in HIGH_CONFIDENCE_MALWARE_TAGS)
                    
                    if has_c2_tag and reputation <= -3 and pulse_count >= 5:
                        result["is_malicious"] = True
                        result["verdict"] = "MALICIOUS"
                        result["threat_score"] = 90
                        result["reasons"].append(f"AlienVault OTX: Confirmed active malware C2 ({', '.join(list(threat_tags)[:3])})")
                    elif pulse_count >= 5 or reputation < 0 or has_c2_tag:
                        result["is_malicious"] = False
                        result["verdict"] = "SUSPICIOUS"
                        result["threat_score"] = 45
                        result["reasons"].append(f"AlienVault OTX: {pulse_count} threat pulse references ({', '.join(list(threat_tags)[:3]) or 'general'})")
                    else:
                        result["is_malicious"] = False
                        result["verdict"] = "INFORMATIONAL"
                        result["threat_score"] = 20
                        result["reasons"].append(f"AlienVault OTX: {pulse_count} community pulse references")
        except Exception as ex:
            logger.debug(f"AlienVault lookup exception for {ip_str}: {ex}")

        # 3. Reverse DNS Lookup for Threat Signatures & Cloud CDN Allowlisting
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_str)
            result["reverse_dns"] = hostname
            host_lower = hostname.lower()

            if any(host_lower.endswith(sfx) for sfx in TRUSTED_CLOUD_SUFFIXES):
                result["is_malicious"] = False
                result["verdict"] = "BENIGN"
                result["threat_score"] = 0
                result["reasons"] = [f"Verified trusted cloud / CDN endpoint: {hostname}"]

            suspicious_domains = ["tor", "onion", "duckdns", "ngrok", "tunnel", "pastebin", "temp", "c2"]
            if any(s in host_lower for s in suspicious_domains):
                result["verdict"] = "SUSPICIOUS" if not result["is_malicious"] else result["verdict"]
                result["sources"].append("Reverse DNS")
                result["reasons"].append(f"Suspicious dynamic/proxy domain: {hostname}")
        except Exception:
            result["reverse_dns"] = None

        # Store in cache
        self._ip_cache[ip_str] = {
            "cached_at": now,
            "data": result
        }
        return result

    def lookup_hash_reputation(self, file_hash: str) -> Dict[str, Any]:
        """
        Correlate a binary SHA-256 hash with CIRCL Hashlookup & AlienVault OTX.
        """
        if not file_hash or len(file_hash) != 64:
            return {"verdict": "UNKNOWN", "is_malicious": False}

        now = time.time()
        if file_hash in self._hash_cache:
            entry = self._hash_cache[file_hash]
            if now - entry["cached_at"] < 3600:
                return entry["data"]

        result = {
            "hash": file_hash,
            "verdict": "BENIGN",
            "is_malicious": False,
            "threat_score": 0,
            "sources": [],
            "reasons": []
        }

        # 1. CIRCL Hashlookup (National CERT Luxembourg)
        try:
            circl_url = f"https://hashlookup.circl.lu/lookup/sha256/{file_hash}"
            resp = self._http_client.get(circl_url)
            if resp.status_code == 200:
                c_data = resp.json()
                is_known_malicious = c_data.get("KnownMalicious")
                file_name = c_data.get("FileName")
                result["sources"].append("CIRCL Hashlookup (CERT.lu)")
                result["circl_filename"] = file_name
                if is_known_malicious:
                    result["is_malicious"] = True
                    result["verdict"] = "MALICIOUS"
                    result["threat_score"] = 99
                    result["reasons"].append(f"CIRCL: Known Malicious Binary ({file_name})")
        except Exception as ex:
            logger.debug(f"CIRCL lookup error: {ex}")

        # 2. AlienVault OTX File Hash Intelligence
        try:
            otx_hash_url = f"https://otx.alienvault.com/api/v1/indicators/file/{file_hash}/general"
            resp = self._http_client.get(otx_hash_url)
            if resp.status_code == 200:
                h_data = resp.json()
                p_count = h_data.get("pulse_info", {}).get("count", 0)
                if p_count > 0:
                    result["sources"].append("AlienVault OTX Hash Intel")
                    result["is_malicious"] = True
                    result["verdict"] = "MALICIOUS"
                    result["threat_score"] = max(result["threat_score"], min(95, 60 + p_count * 10))
                    result["reasons"].append(f"AlienVault OTX: {p_count} threat pulses tag this hash as malware")
        except Exception:
            pass

        self._hash_cache[file_hash] = {
            "cached_at": now,
            "data": result
        }
        return result

osint_engine = OSINTEngine()
