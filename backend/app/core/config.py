"""
CyberFusion XDR Enterprise - Core Configuration
"""
from typing import List, Optional
from pydantic_settings import BaseSettings
from pydantic import Field
import os

class Settings(BaseSettings):
    PROJECT_NAME: str = "CyberFusion XDR Enterprise"
    VERSION: str = "3.4.0-ENTERPRISE"
    API_V1_STR: str = "/api/v1"
    
    # Environment Modes: LIVE (real telemetry only), LAB (testing & attacks), DEMO (sandboxed)
    DEFAULT_ENVIRONMENT_MODE: str = Field(default="LIVE", env="CYBERFUSION_MODE")
    
    # Security
    SECRET_KEY: str = Field(default="cyberfusion-enterprise-jwt-secret-key-production-grade-2026-xdr", env="SECRET_KEY")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    
    # Storage & Database
    DATABASE_URL: str = Field(
        default="sqlite+aiosqlite:///./cyberfusion_enterprise.db",
        env="DATABASE_URL"
    )
    
    # Streaming & Event Bus
    MAX_QUEUE_SIZE: int = 50000
    WORKER_CONCURRENCY: int = 16
    DLQ_MAX_SIZE: int = 10000
    
    # Retention (Days)
    HOT_RETENTION_DAYS: int = 30
    WARM_RETENTION_DAYS: int = 90
    COLD_RETENTION_DAYS: int = 365
    
    # Syslog Ingestion Listeners
    SYSLOG_UDP_PORT: int = 1514
    SYSLOG_ENABLED: bool = True
    
    # Agent Communication
    AGENT_AUTH_TOKEN: str = Field(default="cf-agent-sec-token-998822-live-auth", env="AGENT_AUTH_TOKEN")
    AGENT_HEARTBEAT_TIMEOUT_SECONDS: int = 35
    
    # CORS
    CORS_ORIGINS: List[str] = ["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173", "*"]

    # MongoDB Atlas Integration
    MONGODB_URI: Optional[str] = Field(default=None, env="MONGODB_URI")
    MONGODB_DATABASE: str = Field(default="cyberfusion_xdr", env="MONGODB_DATABASE")
    MONGODB_COLLECTION: str = Field(default="security_logs", env="MONGODB_COLLECTION")

    # VirusTotal Integration (Free Tier: 4 req/min, 500 req/day)
    VIRUSTOTAL_API_KEY: Optional[str] = Field(default=None, env="VirusTotal_key")
    VIRUSTOTAL_MAX_PER_MINUTE: int = 4
    VIRUSTOTAL_MAX_PER_DAY: int = 500

    class Config:
        env_file = [
            ".env",
            "backend/.env",
            os.path.join(os.path.dirname(__file__), "..", "..", ".env"),
            os.path.join(os.path.dirname(__file__), "..", "..", "..", ".env")
        ]
        case_sensitive = False
        extra = "allow"

    @property
    def virustotal_key_resolved(self) -> Optional[str]:
        """Resolves VirusTotal key regardless of env var casing."""
        if self.VIRUSTOTAL_API_KEY:
            return self.VIRUSTOTAL_API_KEY.strip()
        for env_var in ["VirusTotal_key", "VIRUSTOTAL_API_KEY", "VIRUSTOTAL_KEY", "virustotal_key"]:
            val = os.environ.get(env_var)
            if val:
                return val.strip()
        # Fallback to reading directly from .env files
        try:
            from dotenv import dotenv_values
            env_paths = [
                ".env",
                "backend/.env",
                os.path.join(os.path.dirname(__file__), "..", "..", ".env"),
                os.path.join(os.path.dirname(__file__), "..", "..", "..", ".env")
            ]
            for p in env_paths:
                if os.path.isfile(p):
                    vals = dotenv_values(p)
                    for k in ["VirusTotal_key", "VIRUSTOTAL_API_KEY", "VIRUSTOTAL_KEY", "virustotal_key"]:
                        if vals.get(k):
                            return str(vals[k]).strip()
        except Exception:
            pass
        return None

settings = Settings()
