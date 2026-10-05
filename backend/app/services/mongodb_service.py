"""
CyberFusion XDR Enterprise - MongoDB Atlas Log Injection & Telemetry Store
Provides high-performance asynchronous document ingestion for real-time security logs.
"""
import asyncio
import time
import logging
from typing import Dict, Any, List, Optional
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ASCENDING, DESCENDING, UpdateOne
from pymongo.errors import PyMongoError, BulkWriteError
from app.core.config import settings

logger = logging.getLogger("cyberfusion.mongodb")

class MongoDBService:
    def __init__(self):
        self._client: Optional[AsyncIOMotorClient] = None
        self._db = None
        self._collection = None
        self._connected: bool = False
        self._last_error: Optional[str] = None
        self._total_injected: int = 0

    @property
    def is_connected(self) -> bool:
        return self._connected

    async def connect(self) -> bool:
        """Initialize connection to MongoDB Atlas and verify heartbeat."""
        if not settings.MONGODB_URI:
            logger.warning("MONGODB_URI is not set; MongoDB Atlas integration is disabled.")
            self._connected = False
            return False

        try:
            self._client = AsyncIOMotorClient(
                settings.MONGODB_URI,
                serverSelectionTimeoutMS=5000,
                connectTimeoutMS=5000,
                maxPoolSize=50,
                minPoolSize=5
            )
            # Ping database
            await self._client.admin.command("ping")
            self._db = self._client[settings.MONGODB_DATABASE]
            self._collection = self._db[settings.MONGODB_COLLECTION]
            self._connected = True
            self._last_error = None
            logger.info(f"Connected to MongoDB Atlas: database={settings.MONGODB_DATABASE}, collection={settings.MONGODB_COLLECTION}")

            # Ensure optimal indexes for fast SOC logstream queries
            await self._ensure_indexes()
            return True
        except Exception as e:
            self._connected = False
            self._last_error = str(e)
            logger.error(f"Failed to connect to MongoDB Atlas: {e}", exc_info=True)
            return False

    async def _ensure_indexes(self):
        """Create indexes on timestamp, event_uuid, data_source, etc."""
        if not self._connected or self._collection is None:
            return
        try:
            await self._collection.create_index([("timestamp", DESCENDING)])
            await self._collection.create_index([("event_uuid", ASCENDING)], unique=True, sparse=True)
            await self._collection.create_index([("data_source", ASCENDING)])
            await self._collection.create_index([("mode", ASCENDING)])
            await self._collection.create_index([("tenant_id", ASCENDING)])
            await self._collection.create_index([("category", ASCENDING)])
            await self._collection.create_index([("is_alert", ASCENDING)])
            logger.info("MongoDB Atlas indexes verified successfully.")
        except Exception as e:
            logger.warning(f"Error ensuring MongoDB indexes: {e}")

    async def insert_log(self, event_data: Dict[str, Any]) -> bool:
        """
        Inject a normalized security log/event into MongoDB Atlas.
        """
        if not self._connected or self._collection is None:
            now = time.time()
            if getattr(self, "_last_connect_attempt", 0) and now - self._last_connect_attempt < 60:
                return False
            self._last_connect_attempt = now
            # Attempt lazy reconnect if previously failed
            if settings.MONGODB_URI:
                ok = await self.connect()
                if not ok:
                    return False
            else:
                return False

        try:
            doc = {
                "event_uuid": event_data.get("event_uuid") or event_data.get("uuid"),
                "timestamp": event_data.get("timestamp", time.time()),
                "tenant_id": event_data.get("tenant_id", "tenant-enterprise-secops"),
                "mode": event_data.get("mode", "LIVE"),
                "data_source": event_data.get("data_source", "UNKNOWN"),
                "category": event_data.get("category", "telemetry"),
                "action": event_data.get("action", "unknown_action"),
                "severity": event_data.get("severity", "LOW"),
                "hostname": event_data.get("hostname"),
                "user_identity": event_data.get("user_identity") or event_data.get("user"),
                "process_name": event_data.get("process_name") or event_data.get("process"),
                "process_pid": event_data.get("process_pid") or event_data.get("pid"),
                "parent_process": event_data.get("parent_process"),
                "command_line": event_data.get("command_line"),
                "source_ip": event_data.get("source_ip"),
                "dest_ip": event_data.get("dest_ip"),
                "source_port": event_data.get("source_port"),
                "dest_port": event_data.get("dest_port"),
                "protocol": event_data.get("protocol"),
                "file_path": event_data.get("file_path"),
                "file_hash": event_data.get("file_hash"),
                "domain": event_data.get("domain"),
                "url": event_data.get("url"),
                "raw_payload": event_data.get("raw_payload"),
                "is_alert": bool(event_data.get("is_alert", False)),
                "threat_verdict": event_data.get("threat_verdict", "BENIGN"),
                "risk_score": event_data.get("risk_score", 0),
                "osint_intel": event_data.get("osint_intel") or {},
                "detection_reasons": event_data.get("detection_reasons") or [],
                "mitre_tactics": event_data.get("mitre_tactics") or [],
                "mitre_techniques": event_data.get("mitre_techniques") or [],
                "ingested_at": time.time(),
                "storage_backend": "MONGODB_ATLAS"
            }

            # Upsert by event_uuid if available to avoid duplicates
            if doc.get("event_uuid"):
                await self._collection.update_one(
                    {"event_uuid": doc["event_uuid"]},
                    {"$set": doc},
                    upsert=True
                )
            else:
                await self._collection.insert_one(doc)

            self._total_injected += 1
            return True
        except Exception as e:
            self._last_error = str(e)
            logger.error(f"Failed to inject log into MongoDB Atlas: {e}")
            return False

    async def insert_logs_batch(self, events: List[Dict[str, Any]]) -> int:
        """Bulk inject multiple logs into MongoDB Atlas."""
        if not self._connected or self._collection is None or not events:
            return 0

        operations = []
        for ev in events:
            uuid_val = ev.get("event_uuid") or ev.get("uuid")
            doc = {
                "event_uuid": uuid_val,
                "timestamp": ev.get("timestamp", time.time()),
                "tenant_id": ev.get("tenant_id", "tenant-enterprise-secops"),
                "mode": ev.get("mode", "LIVE"),
                "data_source": ev.get("data_source", "UNKNOWN"),
                "category": ev.get("category", "telemetry"),
                "action": ev.get("action", "unknown_action"),
                "severity": ev.get("severity", "LOW"),
                "hostname": ev.get("hostname"),
                "user_identity": ev.get("user_identity") or ev.get("user"),
                "process_name": ev.get("process_name") or ev.get("process"),
                "process_pid": ev.get("process_pid") or ev.get("pid"),
                "parent_process": ev.get("parent_process"),
                "command_line": ev.get("command_line"),
                "source_ip": ev.get("source_ip"),
                "dest_ip": ev.get("dest_ip"),
                "source_port": ev.get("source_port"),
                "dest_port": ev.get("dest_port"),
                "protocol": ev.get("protocol"),
                "file_path": ev.get("file_path"),
                "file_hash": ev.get("file_hash"),
                "domain": ev.get("domain"),
                "url": ev.get("url"),
                "raw_payload": ev.get("raw_payload"),
                "is_alert": bool(ev.get("is_alert", False)),
                "threat_verdict": ev.get("threat_verdict", "BENIGN"),
                "risk_score": ev.get("risk_score", 0),
                "osint_intel": ev.get("osint_intel") or {},
                "detection_reasons": ev.get("detection_reasons") or [],
                "mitre_tactics": ev.get("mitre_tactics") or [],
                "mitre_techniques": ev.get("mitre_techniques") or [],
                "ingested_at": time.time(),
                "storage_backend": "MONGODB_ATLAS"
            }
            if uuid_val:
                operations.append(UpdateOne({"event_uuid": uuid_val}, {"$set": doc}, upsert=True))

        if not operations:
            return 0

        try:
            result = await self._collection.bulk_write(operations, ordered=False)
            inserted_or_upserted = (result.upserted_count or 0) + (result.modified_count or 0) + (result.inserted_count or 0)
            self._total_injected += inserted_or_upserted
            return inserted_or_upserted
        except BulkWriteError as bwe:
            inserted_count = bwe.details.get("nUpserted", 0) + bwe.details.get("nModified", 0) + bwe.details.get("nInserted", 0)
            self._total_injected += inserted_count
            return inserted_count
        except Exception as e:
            logger.error(f"Error bulk injecting logs into MongoDB Atlas: {e}")
            return 0

    async def get_recent_logs(
        self,
        mode: str = "LIVE",
        limit: int = 100,
        data_source: Optional[str] = None,
        search: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Fetch recent security logs from MongoDB Atlas for the SIEM logstream view.
        """
        if not self._connected or self._collection is None:
            return []

        try:
            query: Dict[str, Any] = {"mode": mode}
            if data_source and data_source != "ALL":
                query["data_source"] = data_source

            if search:
                regex_pattern = {"$regex": search, "$options": "i"}
                query["$or"] = [
                    {"process_name": regex_pattern},
                    {"hostname": regex_pattern},
                    {"user_identity": regex_pattern},
                    {"category": regex_pattern},
                    {"action": regex_pattern},
                    {"source_ip": regex_pattern},
                    {"dest_ip": regex_pattern},
                    {"command_line": regex_pattern},
                    {"file_path": regex_pattern}
                ]

            cursor = self._collection.find(query).sort("timestamp", DESCENDING).limit(limit)
            logs = []
            async for doc in cursor:
                doc["_id"] = str(doc["_id"])
                # Map field names for frontend compatibility
                doc["user"] = doc.get("user_identity")
                doc["process"] = doc.get("process_name")
                doc["pid"] = doc.get("process_pid")
                logs.append(doc)
            return logs
        except Exception as e:
            logger.error(f"Failed to fetch logs from MongoDB Atlas: {e}")
            return []

    async def count_logs(self, mode: Optional[str] = None) -> int:
        """Count total logs stored in MongoDB Atlas."""
        if not self._connected or self._collection is None:
            return 0
        try:
            query = {"mode": mode} if mode else {}
            return await self._collection.count_documents(query)
        except Exception as e:
            logger.error(f"Error counting MongoDB documents: {e}")
            return 0

    async def get_status(self) -> Dict[str, Any]:
        """Get MongoDB Atlas connection status and storage statistics."""
        ping_ms = None
        doc_count = 0
        live_count = 0
        lab_count = 0
        
        if self._connected and self._client:
            try:
                start = time.time()
                await self._client.admin.command("ping")
                ping_ms = round((time.time() - start) * 1000, 2)
                doc_count = await self._collection.count_documents({})
                live_count = await self._collection.count_documents({"mode": "LIVE"})
                lab_count = await self._collection.count_documents({"mode": "LAB"})
            except Exception as e:
                self._connected = False
                self._last_error = str(e)

        # Mask URI for safe UI display
        masked_uri = "Not Configured"
        if settings.MONGODB_URI:
            parts = settings.MONGODB_URI.split("@")
            if len(parts) > 1:
                masked_uri = f"mongodb+srv://*****:*****@{parts[1]}"
            else:
                masked_uri = "mongodb+srv://*****"

        return {
            "connected": self._connected,
            "database": settings.MONGODB_DATABASE,
            "collection": settings.MONGODB_COLLECTION,
            "total_logs": doc_count,
            "live_logs": live_count,
            "lab_logs": lab_count,
            "total_injected_this_session": self._total_injected,
            "ping_ms": ping_ms,
            "masked_uri": masked_uri,
            "last_error": self._last_error
        }

    async def close(self):
        """Close MongoDB connection gracefully."""
        if self._client:
            self._client.close()
            self._connected = False
            logger.info("MongoDB Atlas client closed.")

mongodb_service = MongoDBService()
