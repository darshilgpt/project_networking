"""Bounded queue and multi-threaded worker pipeline subsystem."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import logging
import queue
import threading
import time
from typing import Callable, Deque, Dict, List, Optional, Tuple

from dpi.dpi_engine import DPIEngine
from ids.ids_engine import IDSEngine
from ips.blocking_manager import BlockingManager
from ips.decision_engine import DecisionEngine
from models.alert_model import DecisionAction, DPIResult, IDSAlert
from models.flow_model import Flow
from models.packet_models import ParsedPacket
from parser.packet_dispatcher import PacketDispatcher
from server.client_manager import ClientContext, ClientManager
from server.ingestion import QueuedPacket

logger = logging.getLogger("dpi_ids_ips.server.worker_pool")


@dataclass
class ProcessedPacketResult:
    """Outcome of full pipeline inspection for a single packet."""
    packet: ParsedPacket
    client: ClientContext
    is_outbound: bool
    flow: Optional[Flow]
    dpi_result: Optional[DPIResult]
    alerts: List[IDSAlert]
    decision: DecisionAction
    status_msg: str
    processing_time_ms: float
    is_forwarded: bool = True
    enforcement_action: str = "ALLOW"


@dataclass
class ServerPipelineStats:
    """Cumulative processing metrics across all workers."""
    total_processed: int = 0
    total_bytes: int = 0
    total_malformed: int = 0
    total_alerts: int = 0
    total_blocks: int = 0
    security_block_decisions: int = 0
    intercepted_packets: int = 0
    actual_dropped_packets: int = 0
    forwarded_or_reinjected_packets: int = 0
    simulated_blocks: int = 0
    active_prevention_enabled: bool = False
    queue_capacity: int = 10000
    queue_current_size: int = 0
    queue_high_watermark: int = 0
    active_workers: int = 0
    start_time: float = field(default_factory=time.time)
    packets_per_sec: float = 0.0
    bytes_per_sec: float = 0.0


class PipelineWorkerPool:
    """Coordinates a pool of worker threads consuming packets from a bounded queue."""

    def __init__(
        self,
        client_manager: ClientManager,
        num_workers: int = 4,
        queue_size: int = 10000,
        active_prevention: bool = False,
        on_packet_processed: Optional[Callable[[ProcessedPacketResult], None]] = None,
        on_alert_generated: Optional[Callable[[IDSAlert, ClientContext], None]] = None,
    ) -> None:
        """
        Args:
            client_manager: ClientManager instance.
            num_workers: Number of concurrent worker threads.
            queue_size: Capacity bound for the internal packet queue.
            active_prevention: Whether IPS active blocking is enabled.
            on_packet_processed: Callback invoked when a packet completes inspection.
            on_alert_generated: Callback invoked when an IDS alert is raised.
        """
        self.client_manager = client_manager
        self.num_workers = max(1, num_workers)
        self.queue_size = queue_size
        self.active_prevention = active_prevention
        self.on_packet_processed = on_packet_processed
        self.on_alert_generated = on_alert_generated

        # Bounded packet queue
        self.packet_queue: queue.Queue[Optional[QueuedPacket]] = queue.Queue(maxsize=queue_size)

        # Core reusable engines
        self.dispatcher = PacketDispatcher()
        self.dpi_engine = DPIEngine()
        self.ids_engine = IDSEngine()
        self.decision_engine = DecisionEngine()
        self.blocking_manager = BlockingManager(active_prevention=active_prevention)

        # Thread synchronization
        self._stop_event = threading.Event()
        self._threads: List[threading.Thread] = []
        self._stats_lock = threading.Lock()
        self._engine_lock = threading.Lock()

        # Cumulative metrics & ring buffers
        self.stats = ServerPipelineStats(queue_capacity=queue_size)
        self.recent_alerts: Deque[Tuple[IDSAlert, str]] = deque(maxlen=100)
        self.recent_packets: Deque[ProcessedPacketResult] = deque(maxlen=50)

        # Rate tracking
        self._last_rate_calc_time = time.time()
        self._last_processed_count = 0
        self._last_bytes_count = 0

    def start(self) -> None:
        """Launches the worker thread pool."""
        self._stop_event.clear()
        self.stats.start_time = time.time()
        self._threads.clear()

        for i in range(self.num_workers):
            t = threading.Thread(
                target=self._worker_loop,
                name=f"SecServerWorker-{i+1}",
                daemon=True,
            )
            t.start()
            self._threads.append(t)

        self.stats.active_workers = len(self._threads)
        logger.info(f"Started worker pool with {self.num_workers} threads (Queue bound: {self.queue_size})")

    def _worker_loop(self) -> None:
        """Main loop executed by each worker thread."""
        while not self._stop_event.is_set():
            try:
                # Wait briefly for packet or shutdown signal
                item = self.packet_queue.get(timeout=0.2)
            except queue.Empty:
                continue

            if item is None:
                # Sentinel shutdown signal
                self.packet_queue.task_done()
                break

            t0 = time.perf_counter()
            try:
                result = self._process_packet(item)
                if result:
                    with self._stats_lock:
                        self.stats.total_processed += 1
                        self.stats.total_bytes += len(item.raw_bytes)
                        if result.packet.is_malformed:
                            self.stats.total_malformed += 1
                        if result.alerts:
                            self.stats.total_alerts += len(result.alerts)
                            for a in result.alerts:
                                self.recent_alerts.appendleft((a, result.client.client_name))
                        if result.decision == DecisionAction.BLOCK:
                            self.stats.total_blocks += 1

                        # Update IPS strictly distinguished metrics
                        self.stats.security_block_decisions = self.blocking_manager.security_block_decisions
                        self.stats.intercepted_packets = self.blocking_manager.intercepted_packets
                        self.stats.actual_dropped_packets = self.blocking_manager.actual_dropped_packets
                        self.stats.forwarded_or_reinjected_packets = self.blocking_manager.forwarded_or_reinjected_packets
                        self.stats.simulated_blocks = self.blocking_manager.simulated_blocks
                        self.stats.active_prevention_enabled = self.blocking_manager.active_prevention

                        self.recent_packets.appendleft(result)

                    if self.on_packet_processed:
                        try:
                            self.on_packet_processed(result)
                        except Exception as cb_err:
                            logger.error(f"Error in on_packet_processed callback: {cb_err}")

            except Exception as e:
                logger.error(f"Worker pipeline exception: {e}", exc_info=True)
            finally:
                self.packet_queue.task_done()

    def _process_packet(self, item: QueuedPacket) -> Optional[ProcessedPacketResult]:
        """Dissects, inspects, and evaluates a single queued packet."""
        # 1. Dissect packet (reusing custom struct parsers)
        parsed = self.dispatcher.dispatch(
            raw_bytes=item.raw_bytes,
            timestamp=item.timestamp,
            link_type=item.link_type,
        )

        # 2. Resolve client context (VPN IP identification)
        client_ctx, is_outbound = self.client_manager.resolve_client(parsed)
        client_ctx.record_packet(parsed, is_outbound)

        # 3. Client-Isolated Flow Tracking
        flow = client_ctx.flow_manager.process_packet(parsed)

        # 4. Client-Isolated TCP Stream Reassembly
        reassembled_data = None
        if parsed.tcp and parsed.payload:
            new_chunk, full_stream = client_ctx.tcp_reassembler.process_packet(parsed)
            reassembled_data = full_stream if full_stream else parsed.payload

        # 5. Deep Packet Inspection (DPI)
        with self._engine_lock:
            dpi_result = self.dpi_engine.inspect(
                packet=parsed,
                flow=flow,
                reassembled_payload=reassembled_data,
            )

        if flow and dpi_result.protocol not in ("None", "Unknown"):
            client_ctx.flow_manager.record_application_detection(flow, dpi_result.protocol)
            client_ctx.record_protocol(dpi_result.protocol)

        # 6. Intrusion Detection System (IDS)
        with self._engine_lock:
            alerts = self.ids_engine.evaluate(packet=parsed, dpi_result=dpi_result)

        for alert in alerts:
            client_ctx.record_alert(alert)
            if self.on_alert_generated:
                try:
                    self.on_alert_generated(alert, client_ctx)
                except Exception as a_err:
                    logger.error(f"Error in alert callback: {a_err}")

        # 7. IPS Decision Engine & Gateway Enforcement
        with self._engine_lock:
            enforce_res = self.blocking_manager.evaluate_and_enforce(
                packet=parsed,
                dpi_result=dpi_result,
                alerts=alerts,
                is_outbound=is_outbound,
                client_ip=client_ctx.client_ip,
            )

        return ProcessedPacketResult(
            packet=parsed,
            client=client_ctx,
            is_outbound=is_outbound,
            flow=flow,
            dpi_result=dpi_result,
            alerts=alerts,
            decision=enforce_res.decision,
            status_msg=enforce_res.reason,
            processing_time_ms=0.0,
            is_forwarded=enforce_res.is_forwarded,
            enforcement_action=enforce_res.effective_action,
        )

    def get_stats_snapshot(self) -> ServerPipelineStats:
        """Calculates current packet rates and returns a snapshot."""
        now = time.time()
        with self._stats_lock:
            current_q = self.packet_queue.qsize()
            self.stats.queue_current_size = current_q
            self.stats.queue_high_watermark = max(self.stats.queue_high_watermark, current_q)

            delta = now - self._last_rate_calc_time
            if delta >= 0.5:
                pkts_diff = self.stats.total_processed - self._last_processed_count
                bytes_diff = self.stats.total_bytes - self._last_bytes_count
                self.stats.packets_per_sec = round(pkts_diff / delta, 1)
                self.stats.bytes_per_sec = round(bytes_diff / delta, 1)
                self._last_processed_count = self.stats.total_processed
                self._last_bytes_count = self.stats.total_bytes
                self._last_rate_calc_time = now

            self.stats.active_workers = sum(1 for t in self._threads if t.is_alive())

            return ServerPipelineStats(
                total_processed=self.stats.total_processed,
                total_bytes=self.stats.total_bytes,
                total_malformed=self.stats.total_malformed,
                total_alerts=self.stats.total_alerts,
                total_blocks=self.stats.total_blocks,
                security_block_decisions=self.blocking_manager.security_block_decisions,
                intercepted_packets=self.blocking_manager.intercepted_packets,
                actual_dropped_packets=self.blocking_manager.actual_dropped_packets,
                forwarded_or_reinjected_packets=self.blocking_manager.forwarded_or_reinjected_packets,
                simulated_blocks=self.blocking_manager.simulated_blocks,
                active_prevention_enabled=self.blocking_manager.active_prevention,
                queue_capacity=self.stats.queue_capacity,
                queue_current_size=self.stats.queue_current_size,
                queue_high_watermark=self.stats.queue_high_watermark,
                active_workers=self.stats.active_workers,
                start_time=self.stats.start_time,
                packets_per_sec=self.stats.packets_per_sec,
                bytes_per_sec=self.stats.bytes_per_sec,
            )

    def stop(self, timeout: float = 2.0) -> None:
        """Signals workers to halt, drains pending items, and joins threads."""
        self._stop_event.set()

        # Send sentinels to wake waiting workers
        for _ in self._threads:
            try:
                self.packet_queue.put_nowait(None)
            except queue.Full:
                pass

        # Join workers
        for t in self._threads:
            if t.is_alive():
                t.join(timeout=timeout)

        self.stats.active_workers = sum(1 for t in self._threads if t.is_alive())
        # Shutdown blocking manager (stops auto-reaper and flushes firewall rules)
        self.blocking_manager.shutdown()
        logger.info("Worker pool successfully shut down.")

