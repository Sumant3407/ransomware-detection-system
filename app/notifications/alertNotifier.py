"""Alert notification system with priority queuing, quarantine integration, and multi-channel dispatch."""

import heapq
import json
import logging
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional, Union

from app.detection.riskEngine import RiskDecision, ThreatLevel
from app.logging.logger import logSecurityEvent

logger = logging.getLogger(__name__)


@dataclass(order=False)
class AlertNotification:
    """Represents a structured alert notification item."""

    notificationId: str
    occurredAt: str
    severity: str
    classification: str
    riskScore: float
    action: str
    message: str
    priority: int  # 1=Critical, 2=High, 3=Medium, 4=Low
    details: dict[str, Any] = field(default_factory=dict)
    status: str = "queued"  # queued, dispatched, failed, quarantined
    quarantineStatus: str = "none"  # none, pending, quarantined, failed
    dispatchedAt: Optional[str] = None
    errorMessage: Optional[str] = None

    def toDict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def fromDict(cls, data: dict[str, Any]) -> "AlertNotification":
        return cls(
            notificationId=data["notificationId"],
            occurredAt=data["occurredAt"],
            severity=data["severity"],
            classification=data["classification"],
            riskScore=float(data.get("riskScore", 0.0)),
            action=data.get("action", "alertOnly"),
            message=data.get("message", ""),
            priority=int(data.get("priority", 3)),
            details=data.get("details", {}),
            status=data.get("status", "queued"),
            quarantineStatus=data.get("quarantineStatus", "none"),
            dispatchedAt=data.get("dispatchedAt"),
            errorMessage=data.get("errorMessage"),
        )

    @classmethod
    def fromDecision(
        cls,
        decision: RiskDecision,
        message: str = "",
        details: Optional[dict[str, Any]] = None,
        occurredAt: Optional[datetime] = None,
    ) -> "AlertNotification":
        now = occurredAt or datetime.now(timezone.utc)
        timestampStr = now.strftime("%Y%m%d_%H%M%S_%f")[:22]
        uniqueSuffix = uuid.uuid4().hex[:6]
        notifId = f"notif_{timestampStr}_{uniqueSuffix}"

        priorityMap = {
            ThreatLevel.critical: 1,
            ThreatLevel.high: 2,
            ThreatLevel.medium: 3,
            ThreatLevel.low: 4,
        }
        priority = priorityMap.get(decision.level, 3)

        defaultMsg = message or f"Behavior classified as {decision.classification} (risk={decision.score:.2f})"

        return cls(
            notificationId=notifId,
            occurredAt=now.isoformat(),
            severity=decision.level.value,
            classification=decision.classification,
            riskScore=decision.score,
            action=decision.action,
            message=defaultMsg,
            priority=priority,
            details=details or {},
            status="queued",
            quarantineStatus="none",
        )

    def formatConsoleSummary(self) -> str:
        """Format an ASCII-safe single-line or multi-line alert summary for console."""
        prefix = {
            "critical": "[CRITICAL ALERT]",
            "high": "[HIGH ALERT]",
            "medium": "[MEDIUM ALERT]",
            "low": "[INFO]",
        }.get(self.severity, "[ALERT]")

        lines = [
            f"{prefix} {self.classification} (Score: {self.riskScore:.2f}, Priority: P{self.priority})",
            f"  ID:        {self.notificationId}",
            f"  Time:      {self.occurredAt}",
            f"  Action:    {self.action}",
            f"  Message:   {self.message}",
        ]
        if self.details:
            if "processName" in self.details:
                lines.append(f"  Process:   {self.details['processName']} (PID: {self.details.get('processId', 'N/A')})")
            if "monitoredPath" in self.details:
                lines.append(f"  Path:      {self.details['monitoredPath']}")
            if self.quarantineStatus != "none":
                lines.append(f"  Quarantine:{self.quarantineStatus}")

        return "\n".join(lines)

    def formatSyslog(self, facility: int = 16) -> str:
        """Format notification as RFC 5424 / CEF structured log line."""
        sevNum = {
            "critical": 2,  # Critical
            "high": 3,      # Error
            "medium": 4,    # Warning
            "low": 6,       # Informational
        }.get(self.severity, 4)

        pri = (facility * 8) + sevNum
        header = f"<{pri}>1 {self.occurredAt} RansomwareDetector RansomwareApp - {self.notificationId}"
        cef = f"CEF:0|RansomwareDetector|Engine|2.0.0|{self.classification}|{self.message}|{sevNum}|src={self.details.get('processName', 'unknown')} pid={self.details.get('processId', 0)} riskScore={self.riskScore}"
        return f"{header} {cef}"

    def formatJson(self) -> str:
        """Serialize notification as formatted JSON string."""
        return json.dumps(self.toDict(), indent=2)


class NotificationPriorityQueue:
    """
    Thread-safe priority queue for alert notifications.
    Orders alerts strictly by severity priority (P1 Critical before P2 High, P3 Medium, P4 Low),
    and secondary by creation time (FIFO within the same priority tier).
    """

    def __init__(self, maxCapacity: int = 1000):
        self.maxCapacity = max(1, maxCapacity)
        self._heap: list[tuple[int, float, int, AlertNotification]] = []
        self._counter: int = 0  # Monotonic counter for tie-breaking
        self._lock = threading.Lock()
        self.droppedCount: int = 0

    def enqueue(self, notification: AlertNotification) -> bool:
        """
        Enqueue a notification by priority.
        If queue is full, drops the lowest priority item if the incoming item is higher priority.
        """
        with self._lock:
            # Parse timestamp to float for secondary FIFO ordering
            try:
                ts = datetime.fromisoformat(notification.occurredAt).timestamp()
            except Exception:
                ts = time.time()

            if len(self._heap) >= self.maxCapacity:
                # Find the lowest priority item (max priority number) in current heap
                maxItem = max(self._heap, key=lambda x: (x[0], -x[1]))
                if notification.priority < maxItem[0]:
                    # Incoming item has higher urgency (smaller priority number), drop the worst item
                    self._heap.remove(maxItem)
                    heapq.heapify(self._heap)
                    self.droppedCount += 1
                    logger.warning(
                        f"Notification queue full: dropped lower-priority notification {maxItem[3].notificationId} (P{maxItem[0]}) for P{notification.priority}",
                    )
                else:
                    self.droppedCount += 1
                    logger.warning(
                        f"Notification queue full: dropped incoming notification {notification.notificationId} (P{notification.priority})",
                    )
                    return False

            self._counter += 1
            heapEntry = (notification.priority, ts, self._counter, notification)
            heapq.heappush(self._heap, heapEntry)
            return True

    def dequeue(self) -> Optional[AlertNotification]:
        """Pop and return the highest priority notification."""
        with self._lock:
            if not self._heap:
                return None
            _, _, _, notif = heapq.heappop(self._heap)
            return notif

    def peek(self) -> Optional[AlertNotification]:
        """View the next highest priority notification without popping."""
        with self._lock:
            if not self._heap:
                return None
            return self._heap[0][3]

    def size(self) -> int:
        with self._lock:
            return len(self._heap)

    def isEmpty(self) -> bool:
        with self._lock:
            return len(self._heap) == 0

    def getAllQueued(self) -> list[AlertNotification]:
        """Return all queued notifications sorted by priority order."""
        with self._lock:
            sortedEntries = sorted(self._heap, key=lambda x: (x[0], x[1], x[2]))
            return [entry[3] for entry in sortedEntries]

    def clear(self) -> None:
        with self._lock:
            self._heap.clear()
            self._counter = 0


class AlertNotifier:
    """
    Central alert notification engine providing prioritized queuing,
    quarantine hook execution, and multi-dispatcher broadcasting.
    """

    def __init__(
        self,
        maxQueueSize: int = 1000,
        autoDispatch: bool = False,
        quarantineHandler: Optional[Callable[[AlertNotification], bool]] = None,
    ):
        self.queue = NotificationPriorityQueue(maxCapacity=maxQueueSize)
        self.autoDispatch = autoDispatch
        self.quarantineHandler = quarantineHandler
        self.dispatchers: dict[str, Callable[[AlertNotification], bool]] = {}

        # Telemetry
        self.totalEnqueued: int = 0
        self.totalDispatched: int = 0
        self.totalFailed: int = 0
        self.totalQuarantined: int = 0

    def registerDispatcher(
        self,
        name: str,
        handler: Callable[[AlertNotification], bool],
    ) -> None:
        """Register a notification dispatcher callback."""
        self.dispatchers[name] = handler
        logger.debug(f"Registered alert dispatcher: {name}")

    def unregisterDispatcher(self, name: str) -> bool:
        """Remove a notification dispatcher."""
        return self.dispatchers.pop(name, None) is not None

    def setQuarantineHandler(
        self,
        handler: Optional[Callable[[AlertNotification], bool]],
    ) -> None:
        """Set or replace manual quarantine callback hook."""
        self.quarantineHandler = handler

    def enqueue(self, notification: AlertNotification) -> bool:
        """
        Add a notification to the priority queue.
        If autoDispatch is enabled, dispatches immediately.
        """
        success = self.queue.enqueue(notification)
        if success:
            self.totalEnqueued += 1
            logger.info(
                f"Alert notification enqueued: ID={notification.notificationId}, severity={notification.severity}, P={notification.priority}",
                extra={
                    "event": "notification_enqueued",
                    "context": {
                        "notificationId": notification.notificationId,
                        "severity": notification.severity,
                        "priority": notification.priority,
                        "classification": notification.classification,
                    },
                },
            )

            # Check if quarantine should be triggered immediately
            if notification.action in ("quarantine", "isolate") or notification.severity == "critical":
                self._handleQuarantine(notification)

            if self.autoDispatch:
                self.dispatchNext()
        return success

    def notify(
        self,
        decision: RiskDecision,
        message: str = "",
        details: Optional[dict[str, Any]] = None,
        occurredAt: Optional[datetime] = None,
    ) -> AlertNotification:
        """Convenience helper to create and enqueue an alert from a RiskDecision."""
        notification = AlertNotification.fromDecision(
            decision,
            message=message,
            details=details,
            occurredAt=occurredAt,
        )
        self.enqueue(notification)
        return notification

    def _handleQuarantine(self, notification: AlertNotification) -> bool:
        """Execute quarantine callback hook if registered."""
        if self.quarantineHandler is None:
            notification.quarantineStatus = "pending"
            return False

        try:
            notification.quarantineStatus = "pending"
            success = self.quarantineHandler(notification)
            if success:
                notification.quarantineStatus = "quarantined"
                self.totalQuarantined += 1
                logSecurityEvent(
                    logger,
                    "quarantine_action",
                    notification.details.get("monitoredPath", "system"),
                    "success",
                    {
                        "notificationId": notification.notificationId,
                        "classification": notification.classification,
                        "processId": notification.details.get("processId"),
                    },
                )
            else:
                notification.quarantineStatus = "failed"
                logger.warning(f"Quarantine handler failed for {notification.notificationId}")
            return success
        except Exception as error:
            notification.quarantineStatus = "failed"
            logger.error(f"Error in quarantine handler: {error}", exc_info=True)
            return False

    def dispatchNotification(self, notification: AlertNotification) -> bool:
        """Dispatch a single notification across all registered channels."""
        nowUtc = datetime.now(timezone.utc).isoformat()
        notification.dispatchedAt = nowUtc
        overallSuccess = True

        if not self.dispatchers:
            # No external dispatchers registered, mark dispatched via internal queue
            notification.status = "dispatched"
            self.totalDispatched += 1
            return True

        for name, dispatcher in self.dispatchers.items():
            try:
                result = dispatcher(notification)
                if not result:
                    overallSuccess = False
                    logger.warning(f"Dispatcher '{name}' returned false for {notification.notificationId}")
            except Exception as error:
                overallSuccess = False
                notification.errorMessage = f"Dispatcher {name} error: {error}"
                logger.error(f"Dispatcher '{name}' error: {error}", exc_info=True)

        if overallSuccess:
            notification.status = "dispatched"
            self.totalDispatched += 1
        else:
            notification.status = "failed"
            self.totalFailed += 1

        return overallSuccess

    def dispatchNext(self) -> Optional[AlertNotification]:
        """Pop the highest priority notification and dispatch it."""
        notification = self.queue.dequeue()
        if notification is not None:
            self.dispatchNotification(notification)
        return notification

    def dispatchAll(self) -> list[AlertNotification]:
        """Drain queue and dispatch all queued notifications in priority order."""
        dispatched: list[AlertNotification] = []
        while not self.queue.isEmpty():
            notif = self.dispatchNext()
            if notif:
                dispatched.append(notif)
        return dispatched

    def getStats(self) -> dict[str, Any]:
        """Return notification engine telemetry."""
        return {
            "totalEnqueued": self.totalEnqueued,
            "totalDispatched": self.totalDispatched,
            "totalFailed": self.totalFailed,
            "totalDropped": self.queue.droppedCount,
            "totalQuarantined": self.totalQuarantined,
            "queueSize": self.queue.size(),
            "dispatchersCount": len(self.dispatchers),
        }

    def reset(self) -> None:
        """Reset notifier queue and counters."""
        self.queue.clear()
        self.totalEnqueued = 0
        self.totalDispatched = 0
        self.totalFailed = 0
        self.totalQuarantined = 0
