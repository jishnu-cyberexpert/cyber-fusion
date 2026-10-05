"""
CyberFusion XDR Enterprise - Main Application Gateway
"""
import asyncio
import time
import socket
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.core.config import settings
from app.core.database import engine, Base, AsyncSessionLocal
from app.core.event_bus import event_bus
from app.core.security import hash_password
from app.models.models import User, Tenant, DetectionRule
from app.services.detection_engine import PRODUCTION_DETECTION_RULES
from app.services.pipeline import PipelineOrchestrator

# Routers
from app.api.v1.auth import router as auth_router
from app.api.v1.ingestion import router as ingestion_router
from app.api.v1.endpoints import router as endpoints_router
from app.api.v1.incidents import router as incidents_router
from app.api.v1.detections import router as detections_router
from app.api.v1.hunting import router as hunting_router
from app.api.v1.threat_intel import router as tip_router
from app.api.v1.soar import router as soar_router
from app.api.v1.ueba import router as ueba_router
from app.api.v1.asm import router as asm_router
from app.api.v1.cnapp import router as cnapp_router
from app.api.v1.audit import router as audit_router
from app.api.v1.health import router as health_router
from app.api.v1.lab import router as lab_router
from app.api.v1.websocket import router as ws_router
from app.api.v1.siem import router as siem_router
from app.api.v1.ml_analytics import router as ml_router
from app.services.mongodb_service import mongodb_service

async def init_db():
    """Create all relational tables and seed essential admin / tenant records."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as session:
        # Seed default tenant
        from sqlalchemy import select
        res = await session.execute(select(Tenant).where(Tenant.tenant_id == "tenant-enterprise-secops"))
        if not res.scalar_one_or_none():
            tenant = Tenant(
                tenant_id="tenant-enterprise-secops",
                name="CyberFusion Global Enterprise SecOps",
                tier="ENTERPRISE",
                eps_quota=100000
            )
            session.add(tenant)
            
            # Additional MSSP tenant for MDR isolation demo
            tenant_finance = Tenant(
                tenant_id="tenant-finance-corp",
                name="Apex Global Financial Services (MDR Customer)",
                tier="MSSP",
                eps_quota=25000
            )
            session.add(tenant_finance)

        # Seed default admin user
        res_u = await session.execute(select(User).where(User.email == "secops@cyberfusion.enterprise"))
        if not res_u.scalar_one_or_none():
            admin = User(
                email="secops@cyberfusion.enterprise",
                hashed_password=hash_password("CyberFusion2026!"),
                full_name="Chief Information Security Officer",
                role="SUPER_ADMIN",
                tenant_id="tenant-enterprise-secops"
            )
            session.add(admin)

        await session.commit()

class SyslogUDPProtocol(asyncio.DatagramProtocol):
    def datagram_received(self, data, addr):
        try:
            line = data.decode("utf-8", errors="ignore").strip()
            asyncio.create_task(
                PipelineOrchestrator.process_raw_event(
                    raw_event={"raw": line, "source_ip": addr[0], "action": "syslog_received"},
                    data_source="SYSLOG",
                    mode="LIVE"
                )
            )
        except Exception:
            pass

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await init_db()
    event_bus.start(worker_count=settings.WORKER_CONCURRENCY)
    await mongodb_service.connect()
    
    # Start UDP Syslog listener
    syslog_transport = None
    if settings.SYSLOG_ENABLED:
        try:
            loop = asyncio.get_running_loop()
            transport, _ = await loop.create_datagram_endpoint(
                lambda: SyslogUDPProtocol(),
                local_addr=("0.0.0.0", settings.SYSLOG_UDP_PORT)
            )
            syslog_transport = transport
        except Exception as ex:
            print(f"Warning: Could not bind Syslog UDP port {settings.SYSLOG_UDP_PORT}: {ex}")

    yield
    
    # Shutdown
    if syslog_transport:
        syslog_transport.close()
    await mongodb_service.close()
    await event_bus.stop()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Unified Enterprise Cyber Defense & Security Operations Data Plane",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register Sub-APIs
app.include_router(auth_router, prefix=f"{settings.API_V1_STR}/auth", tags=["Authentication & IAM"])
app.include_router(ingestion_router, prefix=f"{settings.API_V1_STR}/ingest", tags=["Data Ingestion & Collectors"])
app.include_router(siem_router, prefix=f"{settings.API_V1_STR}/siem", tags=["SIEM Telemetry & MongoDB Logs"])
app.include_router(endpoints_router, prefix=f"{settings.API_V1_STR}/endpoints", tags=["EDR Endpoint Fleet"])
app.include_router(incidents_router, prefix=f"{settings.API_V1_STR}/incidents", tags=["Incident Response & Cases"])
app.include_router(detections_router, prefix=f"{settings.API_V1_STR}/detections", tags=["Detection Engine & Alerts"])
app.include_router(hunting_router, prefix=f"{settings.API_V1_STR}/hunting", tags=["Threat Hunting"])
app.include_router(tip_router, prefix=f"{settings.API_V1_STR}/tip", tags=["Threat Intelligence Platform"])
app.include_router(soar_router, prefix=f"{settings.API_V1_STR}/soar", tags=["SOAR Response Orchestration"])
app.include_router(ueba_router, prefix=f"{settings.API_V1_STR}/ueba", tags=["UEBA Behavioral Analytics"])
app.include_router(asm_router, prefix=f"{settings.API_V1_STR}/asm", tags=["Attack Surface Management"])
app.include_router(cnapp_router, prefix=f"{settings.API_V1_STR}/cnapp", tags=["CNAPP Cloud Security"])
app.include_router(audit_router, prefix=f"{settings.API_V1_STR}/audit", tags=["Cryptographic Audit Trail"])
app.include_router(health_router, prefix=f"{settings.API_V1_STR}/health", tags=["System Health & Observability"])
app.include_router(lab_router, prefix=f"{settings.API_V1_STR}/lab", tags=["LAB Mode Test Harness"])
app.include_router(ml_router, prefix=f"{settings.API_V1_STR}/ml", tags=["Machine Learning Inference"])
app.include_router(ws_router, prefix=settings.API_V1_STR, tags=["Real-Time WebSockets"])

@app.get("/")
async def root():
    return {
        "product": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "mode": settings.DEFAULT_ENVIRONMENT_MODE,
        "status": "OPERATIONAL",
        "docs_url": "/docs",
        "security_data_plane": "ACTIVE"
    }
