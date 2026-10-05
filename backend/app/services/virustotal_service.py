"""
CyberFusion XDR Enterprise - VirusTotal v3 Threat Intelligence Engine
Strictly complies with VirusTotal Free Public API limitations:
- Request rate: 4 lookups / minute (sliding window throttle)
- Daily quota: 500 lookups / day (daily counter & auto-pause)
- Monthly quota: 15,500 lookups / month
- Aggressive 24-hour TTL caching to prevent duplicate API requests
- Automatic private/loopback IP filtering
"""
import asyncio
import time
import ipaddress
import logging
from collections import deque
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
import httpx
from app.core.config import settings

logger = logging.getLogger("cyberfusion.virustotal")

class VirusTotalService:
    def __init__(self):
        self._base_url = "https://www.virustotal.com/api/v3"
        self._max_per_minute = 4
        self._max_per_day = 500
        
        # Sliding window for 4 req / min
        self._minute_window: deque = deque(maxlen=20) # timestamps of requests
        self._last_request_time: float = 0.0
        self._lock = asyncio.Lock()
        
        # Daily quota tracking (UTC)
        self._current_day: str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        self._daily_requests_used: int = 0
        
        # In-memory TTL cache (24 hours = 86,400 seconds)
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._cache_ttl_seconds: int = 86400

    @property
    def api_key(self) -> Optional[str]:
        return settings.virustotal_key_resolved

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    def _check_and_reset_daily_quota(self):
        """Reset daily count at UTC midnight."""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        if today != self._current_day:
            logger.info(f"VirusTotal daily quota reset: New UTC day {today} (Previous used: {self._daily_requests_used})")
            self._current_day = today
            self._daily_requests_used = 0

    def is_private_ip(self, ip_str: str) -> bool:
        """Determines if an IP is private/loopback so we don't waste API quota."""
        if not ip_str or ip_str in ["127.0.0.1", "::1", "0.0.0.0", "localhost"]:
            return True
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved or ip_obj.is_multicast
        except ValueError:
            return False

    async def _enforce_rate_limit(self, wait_if_needed: bool = True) -> bool:
        """
        Enforces both:
        1. Daily quota (max 500 req/day)
        2. Per-minute rate limit (max 4 req/min)
        Returns True if authorized to proceed, False if rejected/throttled.
        """
        self._check_and_reset_daily_quota()

        if self._daily_requests_used >= self._max_per_day:
            logger.warning(f"VirusTotal daily quota of {self._max_per_day} reached. Request throttled.")
            return False

        async with self._lock:
            now = time.time()
            # Clean requests older than 60 seconds
            recent_requests = [t for t in self._minute_window if now - t < 60.0]
            self._minute_window = deque(recent_requests, maxlen=20)

            # Check if 4 requests have already been made in the last 60 seconds
            if len(self._minute_window) >= self._max_per_minute:
                oldest_in_window = self._minute_window[0]
                wait_time = max(0.5, 60.0 - (now - oldest_in_window) + 0.5)

                if not wait_if_needed:
                    logger.info(f"VirusTotal 4/min limit reached. wait_if_needed=False, skipping.")
                    return False

                logger.info(f"VirusTotal 4/min rate limit reached. Throttling for {round(wait_time, 2)}s to respect free quota...")
                await asyncio.sleep(wait_time)
                now = time.time()

            # Ensure minimum 14.5 seconds spacing between consecutive requests to avoid burst rejections
            time_since_last = now - self._last_request_time
            if time_since_last < 14.5 and len(self._minute_window) > 0:
                spacing_wait = 14.5 - time_since_last
                if wait_if_needed:
                    await asyncio.sleep(spacing_wait)
                    now = time.time()

            self._minute_window.append(now)
            self._last_request_time = now
            self._daily_requests_used += 1
            return True

    def get_cached(self, ioc_type: str, value: str) -> Optional[Dict[str, Any]]:
        """Retrieve from 24-hour cache if valid."""
        cache_key = f"{ioc_type.lower()}:{value.lower().strip()}"
        if cache_key in self._cache:
            entry = self._cache[cache_key]
            if time.time() - entry["cached_at"] < self._cache_ttl_seconds:
                return entry["data"]
            else:
                del self._cache[cache_key]
        return None

    def set_cache(self, ioc_type: str, value: str, data: Dict[str, Any]):
        """Save result in cache."""
        cache_key = f"{ioc_type.lower()}:{value.lower().strip()}"
        self._cache[cache_key] = {
            "cached_at": time.time(),
            "data": data
        }

    async def lookup_ip(self, ip_str: str, wait_if_needed: bool = True) -> Dict[str, Any]:
        """
        Query VirusTotal v3 for IP address reputation.
        """
        ip = ip_str.strip()
        if self.is_private_ip(ip):
            return {
                "source": "VirusTotal v3",
                "indicator": ip,
                "type": "ip",
                "verdict": "INTERNAL",
                "is_malicious": False,
                "reputation": 0,
                "note": "Private / RFC1918 / Loopback IP address"
            }

        cached = self.get_cached("ip", ip)
        if cached:
            cached["from_cache"] = True
            return cached

        if not self.is_configured:
            return {"error": "VirusTotal API key is not configured"}

        authorized = await self._enforce_rate_limit(wait_if_needed=wait_if_needed)
        if not authorized:
            return {
                "error": "VirusTotal rate limit or daily quota reached (4/min, 500/day)",
                "throttled": True
            }

        url = f"{self._base_url}/ip_addresses/{ip}"
        headers = {"x-apikey": self.api_key}

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious_count = stats.get("malicious", 0)
                    suspicious_count = stats.get("suspicious", 0)
                    harmless_count = stats.get("harmless", 0)
                    undetected_count = stats.get("undetected", 0)
                    total_engines = sum(stats.values())

                    verdict = "MALICIOUS" if malicious_count >= 2 else "SUSPICIOUS" if (malicious_count == 1 or suspicious_count >= 2) else "BENIGN"
                    score = min(100, int((malicious_count * 25) + (suspicious_count * 10))) if malicious_count > 0 else 0

                    result = {
                        "source": "VirusTotal v3",
                        "indicator": ip,
                        "type": "ip",
                        "verdict": verdict,
                        "is_malicious": verdict == "MALICIOUS",
                        "threat_score": score,
                        "as_owner": data.get("as_owner", "Unknown ASN"),
                        "country": data.get("country", "Unknown"),
                        "network": data.get("network"),
                        "reputation": data.get("reputation", 0),
                        "stats": stats,
                        "detection_ratio": f"{malicious_count}/{total_engines}",
                        "tags": data.get("tags", []),
                        "permalink": f"https://www.virustotal.com/gui/ip-address/{ip}",
                        "from_cache": False
                    }
                    self.set_cache("ip", ip, result)
                    return result
                elif resp.status_code == 429:
                    logger.warning("VirusTotal HTTP 429: Too Many Requests")
                    return {"error": "VirusTotal API rate limit exceeded (4 lookups/min max)", "status_code": 429}
                elif resp.status_code == 404:
                    result = {
                        "source": "VirusTotal v3",
                        "indicator": ip,
                        "type": "ip",
                        "verdict": "UNLISTED",
                        "is_malicious": False,
                        "stats": {},
                        "note": "IP not previously analyzed by VirusTotal"
                    }
                    self.set_cache("ip", ip, result)
                    return result
                else:
                    return {"error": f"VirusTotal API returned status {resp.status_code}: {resp.text}"}
        except Exception as ex:
            logger.error(f"Error querying VirusTotal for IP {ip}: {ex}")
            return {"error": str(ex)}

    async def lookup_domain(self, domain_str: str, wait_if_needed: bool = True) -> Dict[str, Any]:
        """Query VirusTotal v3 for domain reputation."""
        domain = domain_str.lower().strip()
        cached = self.get_cached("domain", domain)
        if cached:
            cached["from_cache"] = True
            return cached

        if not self.is_configured:
            return {"error": "VirusTotal API key is not configured"}

        authorized = await self._enforce_rate_limit(wait_if_needed=wait_if_needed)
        if not authorized:
            return {"error": "VirusTotal rate limit or daily quota reached (4/min, 500/day)", "throttled": True}

        url = f"{self._base_url}/domains/{domain}"
        headers = {"x-apikey": self.api_key}

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious_count = stats.get("malicious", 0)
                    suspicious_count = stats.get("suspicious", 0)
                    total_engines = sum(stats.values())

                    verdict = "MALICIOUS" if malicious_count >= 2 else "SUSPICIOUS" if (malicious_count == 1 or suspicious_count >= 2) else "BENIGN"
                    score = min(100, int((malicious_count * 25) + (suspicious_count * 10)))

                    result = {
                        "source": "VirusTotal v3",
                        "indicator": domain,
                        "type": "domain",
                        "verdict": verdict,
                        "is_malicious": verdict == "MALICIOUS",
                        "threat_score": score,
                        "categories": data.get("categories", {}),
                        "reputation": data.get("reputation", 0),
                        "stats": stats,
                        "detection_ratio": f"{malicious_count}/{total_engines}",
                        "tags": data.get("tags", []),
                        "permalink": f"https://www.virustotal.com/gui/domain/{domain}",
                        "from_cache": False
                    }
                    self.set_cache("domain", domain, result)
                    return result
                elif resp.status_code == 404:
                    result = {
                        "source": "VirusTotal v3",
                        "indicator": domain,
                        "type": "domain",
                        "verdict": "UNLISTED",
                        "is_malicious": False,
                        "stats": {},
                        "note": "Domain not previously analyzed by VirusTotal"
                    }
                    self.set_cache("domain", domain, result)
                    return result
                else:
                    return {"error": f"VirusTotal API status {resp.status_code}: {resp.text}"}
        except Exception as ex:
            logger.error(f"Error querying VirusTotal for domain {domain}: {ex}")
            return {"error": str(ex)}

    async def lookup_file_hash(self, file_hash: str, wait_if_needed: bool = True) -> Dict[str, Any]:
        """Query VirusTotal v3 for SHA-256 / SHA-1 / MD5 hash."""
        h = file_hash.lower().strip()
        cached = self.get_cached("sha256", h)
        if cached:
            cached["from_cache"] = True
            return cached

        if not self.is_configured:
            return {"error": "VirusTotal API key is not configured"}

        authorized = await self._enforce_rate_limit(wait_if_needed=wait_if_needed)
        if not authorized:
            return {"error": "VirusTotal rate limit or daily quota reached (4/min, 500/day)", "throttled": True}

        url = f"{self._base_url}/files/{h}"
        headers = {"x-apikey": self.api_key}

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious_count = stats.get("malicious", 0)
                    suspicious_count = stats.get("suspicious", 0)
                    total_engines = sum(stats.values())

                    verdict = "MALICIOUS" if malicious_count >= 2 else "SUSPICIOUS" if (malicious_count == 1 or suspicious_count >= 1) else "BENIGN"
                    score = min(100, int((malicious_count * 20) + (suspicious_count * 10)))

                    result = {
                        "source": "VirusTotal v3",
                        "indicator": h,
                        "type": "sha256",
                        "verdict": verdict,
                        "is_malicious": verdict == "MALICIOUS",
                        "threat_score": score,
                        "meaningful_name": data.get("meaningful_name") or data.get("type_description"),
                        "popular_threat_classification": data.get("popular_threat_classification", {}),
                        "reputation": data.get("reputation", 0),
                        "stats": stats,
                        "detection_ratio": f"{malicious_count}/{total_engines}",
                        "tags": data.get("tags", []),
                        "permalink": f"https://www.virustotal.com/gui/file/{h}",
                        "from_cache": False
                    }
                    self.set_cache("sha256", h, result)
                    return result
                elif resp.status_code == 404:
                    result = {
                        "source": "VirusTotal v3",
                        "indicator": h,
                        "type": "sha256",
                        "verdict": "UNLISTED",
                        "is_malicious": False,
                        "stats": {},
                        "note": "File hash not previously cataloged in VirusTotal"
                    }
                    self.set_cache("sha256", h, result)
                    return result
                else:
                    return {"error": f"VirusTotal API status {resp.status_code}: {resp.text}"}
        except Exception as ex:
            logger.error(f"Error querying VirusTotal for hash {h}: {ex}")
            return {"error": str(ex)}

    async def lookup_indicator(self, ioc_type: str, value: str, wait_if_needed: bool = True) -> Dict[str, Any]:
        """Unified indicator dispatcher."""
        t = ioc_type.lower().strip()
        v = value.strip()
        if t in ["ip", "ipv4", "ipv6"]:
            return await self.lookup_ip(v, wait_if_needed=wait_if_needed)
        elif t in ["domain", "host", "hostname"]:
            return await self.lookup_domain(v, wait_if_needed=wait_if_needed)
        elif t in ["sha256", "sha1", "md5", "hash"]:
            return await self.lookup_file_hash(v, wait_if_needed=wait_if_needed)
        else:
            return {"error": f"Unsupported indicator type for VirusTotal: {ioc_type}"}

    def get_quota_status(self) -> Dict[str, Any]:
        """Returns real-time status of the VirusTotal free tier usage and rate limiting."""
        self._check_and_reset_daily_quota()
        now = time.time()
        recent_requests = [t for t in self._minute_window if now - t < 60.0]
        
        masked_key = "Not Configured"
        if self.api_key:
            masked_key = f"{self.api_key[:8]}...{self.api_key[-6:]}"

        seconds_until_next_slot = 0
        if len(recent_requests) >= self._max_per_minute:
            seconds_until_next_slot = max(0, int(60 - (now - recent_requests[0])))

        return {
            "configured": self.is_configured,
            "masked_key": masked_key,
            "tier": "STANDARD_FREE_ENDUSER",
            "quotas": {
                "max_requests_per_minute": self._max_per_minute,
                "max_requests_per_day": self._max_per_day,
                "max_requests_per_month": 15500
            },
            "usage": {
                "requests_used_today": self._daily_requests_used,
                "requests_remaining_today": max(0, self._max_per_day - self._daily_requests_used),
                "requests_in_current_minute": len(recent_requests),
                "rate_limit_state": "THROTTLED" if seconds_until_next_slot > 0 else "READY",
                "seconds_until_next_slot": seconds_until_next_slot,
                "cached_indicators_count": len(self._cache),
                "cache_ttl_hours": int(self._cache_ttl_seconds / 3600)
            }
        }

virustotal_service = VirusTotalService()
