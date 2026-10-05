"""
CyberFusion XDR Enterprise - Real-Time Security Event Bus
Scalable, thread-safe asynchronous pipeline with backpressure, DLQ, metrics, and isolation.
"""
import asyncio
import time
from typing import Dict, Any, List, Callable, Awaitable, Optional
from collections import deque
import logging

logger = logging.getLogger("cyberfusion.event_bus")

class SecurityEventBus:
    def __init__(self, max_queue_size: int = 50000, dlq_max_size: int = 5000):
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=max_queue_size)
        self._subscribers: List[Callable[[Dict[str, Any]], Awaitable[None]]] = []
        self._dead_letter_queue: deque = deque(maxlen=dlq_max_size)
        
        # Real performance metrics (NEVER fake)
        self.total_ingested: int = 0
        self.total_processed: int = 0
        self.total_dropped: int = 0
        self.total_errors: int = 0
        
        # Latency & throughput tracking
        self._recent_processing_latencies: deque = deque(maxlen=200)
        self._eps_window: deque = deque(maxlen=50) # (timestamp, count)
        self._last_eps_calc_time = time.time()
        self._current_window_count = 0
        self._measured_eps: float = 0.0
        
        self._running = False
        self._worker_tasks: List[asyncio.Task] = []

    def start(self, worker_count: int = 4):
        if self._running:
            return
        self._running = True
        for i in range(worker_count):
            task = asyncio.create_task(self._worker_loop(f"event-worker-{i}"))
            self._worker_tasks.append(task)
        logger.info(f"SecurityEventBus initialized with {worker_count} workers.")

    async def stop(self):
        self._running = False
        for task in self._worker_tasks:
            task.cancel()
        await asyncio.gather(*self._worker_tasks, return_exceptions=True)
        self._worker_tasks.clear()

    def subscribe(self, callback: Callable[[Dict[str, Any]], Awaitable[None]]):
        """Register an async consumer in the pipeline (detection, storage, correlation, websocket)."""
        self._subscribers.append(callback)

    async def publish(self, event: Dict[str, Any]) -> bool:
        """
        Publish an event to the security data plane.
        Enforces queue backpressure and timestamps.
        """
        if not self._running:
            self.start()

        now = time.time()
        # Track EPS
        self._current_window_count += 1
        if now - self._last_eps_calc_time >= 1.0:
            dt = now - self._last_eps_calc_time
            self._measured_eps = round(self._current_window_count / dt, 2)
            self._last_eps_calc_time = now
            self._current_window_count = 0

        event["_bus_ingest_time"] = now
        self.total_ingested += 1

        try:
            self._queue.put_nowait(event)
            return True
        except asyncio.QueueFull:
            self.total_dropped += 1
            logger.warning("Event bus queue full. Backpressure dropping event.")
            return False

    async def _worker_loop(self, name: str):
        while self._running:
            try:
                event = await self._queue.get()
                start_process = time.time()
                
                # Execute subscribers
                for subscriber in self._subscribers:
                    try:
                        await subscriber(event)
                    except Exception as sub_err:
                        self.total_errors += 1
                        logger.error(f"Error in subscriber {subscriber.__name__ if hasattr(subscriber, '__name__') else 'callback'}: {sub_err}", exc_info=True)
                        self._dead_letter_queue.append({
                            "event": event,
                            "error": str(sub_err),
                            "failed_at": time.time()
                        })

                processing_time_ms = (time.time() - start_process) * 1000.0
                self._recent_processing_latencies.append(processing_time_ms)
                self.total_processed += 1
                self._queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.total_errors += 1
                logger.error(f"Worker {name} uncaught error: {e}", exc_info=True)

    def get_metrics(self) -> Dict[str, Any]:
        """Real measured metrics."""
        avg_latency = (
            round(sum(self._recent_processing_latencies) / len(self._recent_processing_latencies), 2)
            if self._recent_processing_latencies else 0.0
        )
        return {
            "queue_depth": self._queue.qsize(),
            "max_queue_size": self._queue.maxsize,
            "measured_eps": self._measured_eps,
            "total_ingested": self.total_ingested,
            "total_processed": self.total_processed,
            "total_dropped": self.total_dropped,
            "total_errors": self.total_errors,
            "avg_processing_latency_ms": avg_latency,
            "dlq_depth": len(self._dead_letter_queue)
        }

# Global singleton event bus
event_bus = SecurityEventBus()
