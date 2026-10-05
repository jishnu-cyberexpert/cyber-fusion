"""
CyberFusion XDR Enterprise - Attack Surface Management (ASM) Engine
Performs scoped, authorized discovery of domains, open services, SSL certificate validity,
and asset exposure.
"""
import socket
import ssl
import time
import json
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger("cyberfusion.asm")

class ASMScanner:
    COMMON_PROBE_PORTS = [80, 443, 22, 3389, 8080, 8443]

    @staticmethod
    def inspect_target(target: str, scope_confirmed: bool = False) -> Dict[str, Any]:
        """
        Inspect domain or IP for authorized attack surface exposure.
        Enforces explicit authorization requirement.
        """
        if not scope_confirmed:
            return {
                "error": "UNAUTHORIZED_SCOPE: Explicit enterprise authorization confirmation required prior to asset scanning.",
                "scanned": False
            }

        target = target.strip().replace("https://", "").replace("http://", "").split("/")[0]
        now = time.time()
        
        # 1. DNS Resolution
        resolved_ip = None
        try:
            resolved_ip = socket.gethostbyname(target)
        except Exception as e:
            logger.warning(f"DNS resolution failed for {target}: {e}")

        # 2. Port check
        open_ports = []
        if resolved_ip:
            for port in ASMScanner.COMMON_PROBE_PORTS:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.6)
                try:
                    result = s.connect_ex((resolved_ip, port))
                    if result == 0:
                        open_ports.append(port)
                except Exception:
                    pass
                finally:
                    s.close()

        # 3. SSL Certificate check
        ssl_info = {}
        if 443 in open_ports or target:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((target, 443), timeout=1.5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                        cert = ssock.getpeercert(binary_form=False)
                        if cert:
                            ssl_info["issuer"] = str(cert.get("issuer", ""))
                            ssl_info["notAfter"] = cert.get("notAfter", "")
                            ssl_info["subject"] = str(cert.get("subject", ""))
            except Exception as ssl_err:
                ssl_info["error"] = str(ssl_err)

        # 4. Exposure risk calculation
        risk = 10.0
        if 22 in open_ports or 3389 in open_ports:
            risk += 45.0 # Exposed remote management interface
        if 80 in open_ports and 443 not in open_ports:
            risk += 20.0 # Unencrypted HTTP only
        if not ssl_info.get("issuer") and 443 in open_ports:
            risk += 15.0

        return {
            "target": target,
            "resolved_ip": resolved_ip,
            "open_ports": open_ports,
            "ssl_info": ssl_info,
            "risk_score": min(risk, 100.0),
            "scanned_at": now,
            "scope_authorized": True
        }
