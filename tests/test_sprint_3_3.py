"""Unit and Integration Tests for Sprint 3.3: Alert Rate Limiting & Notification Queue."""

import json
import os
import shutil
import sqlite3
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Generator

import pytest

from app.detection.alertPolicy import AlertDeduplicator, AlertPolicy, TokenBucket
from app.detection.riskEngine import RiskDecision, ThreatLevel
from app.domain.schemas import FileAction, FileEvent
from app.notifications.alertNotifier import (
    AlertNotification,
    AlertNotifier,
    NotificationPriorityQueue,
)
from app.runtime.controller import DetectionController
from app.storage.sqliteStore import initializeDatabase


class TestTokenBucketRateLimiting:
    """Test token bucket rate limiter burst capacity, refill rate, and consumption."""

    def test_initial_tokens_and_consumption(self):
        t0 = datetime(2026, 10, 8, 12, 0, 0, tzinfo=timezone.utc)
        bucket = TokenBucket(capacity=5.0, refillRatePerSecond=1.0)
        assert bucket.availableTokens(now=t0) == 5.0
        assert bucket.consume(2.0, now=t0) is True
        assert bucket.availableTokens(now=t0) == 3.0
        assert bucket.consume(3.0, now=t0) is True
        assert bucket.availableTokens(now=t0) == 0.0
        assert bucket.consume(1.0, now=t0) is False

    def test_refill_over_time(self):
        bucket = TokenBucket(capacity=10.0, refillRatePerSecond=2.0)
        t0 = datetime(2026, 10, 8, 12, 0, 0, tzinfo=timezone.utc)
        bucket.lastRefillTime = t0.timestamp()
        bucket.tokens = 0.0

        # After 3 seconds, should have refilled 6 tokens
        t1 = t0 + timedelta(seconds=3)
        assert bucket.availableTokens(now=t1) == pytest.approx(6.0, rel=1e-2)
        assert bucket.consume(5.0, now=t1) is True
        assert bucket.availableTokens(now=t1) == pytest.approx(1.0, rel=1e-2)

        # After 10 seconds total, clamped to capacity (10.0)
        t2 = t0 + timedelta(seconds=10)
        assert bucket.availableTokens(now=t2) == pytest.approx(10.0, rel=1e-2)

    def test_reset_restores_capacity(self):
        t0 = datetime(2026, 10, 8, 12, 0, 0, tzinfo=timezone.utc)
        bucket = TokenBucket(capacity=5.0, refillRatePerSecond=0.1)
        bucket.consume(5.0, now=t0)
        assert bucket.availableTokens(now=t0) == 0.0
        bucket.reset()
        assert bucket.availableTokens(now=t0) == 5.0


class TestAlertDeduplication:
    """Test alert deduplicator entity tracking, sliding windows, and escalation."""

    def test_duplicate_detection_within_window(self):
        dedup = AlertDeduplicator(dedupWindowSeconds=60.0)
        t0 = datetime(2026, 10, 8, 12, 0, 0, tzinfo=timezone.utc)
        sig = "ransomwareLike:bad.exe:1234:pathHashABC"

        isDup, isEsc = dedup.isDuplicate(sig, ThreatLevel.high, now=t0)
        assert isDup is False
        assert isEsc is False
        dedup.record(sig, ThreatLevel.high, now=t0)

        # Check 10 seconds later with same threat level
        t1 = t0 + timedelta(seconds=10)
        isDup, isEsc = dedup.isDuplicate(sig, ThreatLevel.high, now=t1)
        assert isDup is True
        assert isEsc is False

    def test_escalation_detected_on_same_entity(self):
        dedup = AlertDeduplicator(dedupWindowSeconds=60.0)
        t0 = datetime(2026, 10, 8, 12, 0, 0, tzinfo=timezone.utc)
        sig = "ransomwareLike:bad.exe:1234:pathHashABC"

        dedup.record(sig, ThreatLevel.medium, now=t0)

        # Check with escalated critical threat level
        t1 = t0 + timedelta(seconds=5)
        isDup, isEsc = dedup.isDuplicate(sig, ThreatLevel.critical, now=t1)
        assert isDup is True
        assert isEsc is True

    def test_expired_window_clears_records(self):
        dedup = AlertDeduplicator(dedupWindowSeconds=30.0)
        t0 = datetime(2026, 10, 8, 12, 0, 0, tzinfo=timezone.utc)
        sig = "ransomwareLike:bad.exe:1234:pathHashABC"

        dedup.record(sig, ThreatLevel.high, now=t0)
        assert dedup.getDuplicateCount(sig) == 1

        # Check after 35 seconds (window expired)
        t1 = t0 + timedelta(seconds=35)
        isDup, isEsc = dedup.isDuplicate(sig, ThreatLevel.high, now=t1)
        assert isDup is False
        assert isEsc is False


class TestAlertPolicyRateLimitingAndCooldown:
    """Test integrated AlertPolicy behaviors: cooldown, rate limits, escalation, stats."""

    def test_low_threat_always_rejected(self):
        policy = AlertPolicy()
        lowDec = RiskDecision(ThreatLevel.low, 0.1, "benign", "logOnly")
        assert policy.shouldAlert(lowDec) is False
        assert policy.totalEvaluated == 0

    def test_first_alert_allowed_and_recorded(self):
        policy = AlertPolicy(cooldownSeconds=60)
        dec = RiskDecision(ThreatLevel.high, 0.8, "ransomwareLike", "alertOnly")
        t0 = datetime(2026, 10, 8, 12, 0, 0, tzinfo=timezone.utc)

        assert policy.shouldAlert(dec, now=t0) is True
        policy.recordAlert(dec, now=t0)
        assert policy.totalRaised == 1

    def test_cooldown_and_escalation_lifecycle(self):
        policy = AlertPolicy(cooldownSeconds=60)
        t0 = datetime(2026, 10, 8, 12, 0, 0, tzinfo=timezone.utc)

        medDec = RiskDecision(ThreatLevel.medium, 0.5, "suspicious", "notifyUser")
        highDec = RiskDecision(ThreatLevel.high, 0.8, "ransomwareLike", "alertOnly")
        critDec = RiskDecision(ThreatLevel.critical, 0.95, "ransomwareLike", "alertOnly")

        # 1. Medium alert at t0
        assert policy.shouldAlert(medDec, now=t0) is True
        policy.recordAlert(medDec, now=t0)

        # 2. Repeated medium alert at t0 + 10s should be cooldown suppressed
        t1 = t0 + timedelta(seconds=10)
        assert policy.shouldAlert(medDec, now=t1) is False
        assert policy.cooldownSuppressed == 1

        # 3. High alert at t0 + 15s (escalation) should bypass cooldown
        t2 = t0 + timedelta(seconds=15)
        assert policy.shouldAlert(highDec, now=t2) is True
        policy.recordAlert(highDec, now=t2)

        # 4. Critical alert at t0 + 20s (further escalation) should bypass cooldown
        t3 = t0 + timedelta(seconds=20)
        assert policy.shouldAlert(critDec, now=t3) is True
        policy.recordAlert(critDec, now=t3)

        # 5. Cooldown expiration at t0 + 90s allows next alert
        t4 = t0 + timedelta(seconds=90)
        assert policy.shouldAlert(critDec, now=t4) is True

    def test_token_bucket_burst_rate_limiting(self):
        # Configure bucket with burst capacity of 3 alerts, 0.001 refill/sec
        policy = AlertPolicy(
            cooldownSeconds=0,  # disable cooldown to isolate rate limit
            maxAlertsPerMinute=1,
            burstCapacity=3,
            enableRateLimiting=True,
            enableDeduplication=False,
        )
        t0 = datetime(2026, 10, 8, 12, 0, 0, tzinfo=timezone.utc)
        highDec = RiskDecision(ThreatLevel.high, 0.8, "ransomwareLike", "alertOnly")

        # 1st alert: allowed
        assert policy.shouldAlert(highDec, now=t0) is True
        policy.recordAlert(highDec, now=t0)

        # 2nd alert: allowed
        t1 = t0 + timedelta(milliseconds=100)
        assert policy.shouldAlert(highDec, now=t1) is True
        policy.recordAlert(highDec, now=t1)

        # 3rd alert: allowed
        t2 = t0 + timedelta(milliseconds=200)
        assert policy.shouldAlert(highDec, now=t2) is True
        policy.recordAlert(highDec, now=t2)

        # 4th alert: tokens exhausted, should be rate limited!
        t3 = t0 + timedelta(milliseconds=300)
        assert policy.shouldAlert(highDec, now=t3) is False
        assert policy.rateLimitedSuppressed == 1

    def test_deduplication_under_alert_policy(self):
        policy = AlertPolicy(
            cooldownSeconds=0,  # Zero cooldown to isolate deduplication
            maxAlertsPerMinute=100,
            burstCapacity=100,
            dedupWindowSeconds=60,
            enableRateLimiting=False,
            enableDeduplication=True,
        )
        t0 = datetime(2026, 10, 8, 12, 0, 0, tzinfo=timezone.utc)
        dec = RiskDecision(ThreatLevel.high, 0.8, "ransomwareLike", "alertOnly")
        ctx = {"processId": 1234, "processName": "malware.exe", "pathHash": "abc"}

        # 1. First alert is allowed
        assert policy.shouldAlert(dec, now=t0, context=ctx) is True
        policy.recordAlert(dec, now=t0, context=ctx)

        # 2. Duplicate alert with identical context 10s later is suppressed by deduplication
        t1 = t0 + timedelta(seconds=10)
        assert policy.shouldAlert(dec, now=t1, context=ctx) is False
        assert policy.deduplicatedSuppressed == 1

        # 3. Different process context is allowed
        ctx2 = {"processId": 5678, "processName": "different.exe", "pathHash": "xyz"}
        assert policy.shouldAlert(dec, now=t1, context=ctx2) is True

    def test_statistics_telemetry(self):
        policy = AlertPolicy(cooldownSeconds=60)
        dec = RiskDecision(ThreatLevel.high, 0.8, "ransomwareLike", "alertOnly")
        t0 = datetime(2026, 10, 8, 12, 0, 0, tzinfo=timezone.utc)

        policy.shouldAlert(dec, now=t0)
        policy.recordAlert(dec, now=t0)
        policy.shouldAlert(dec, now=t0 + timedelta(seconds=5))

        stats = policy.getStatistics()
        assert stats["totalEvaluated"] == 2
        assert stats["totalRaised"] == 1
        assert stats["cooldownSuppressed"] == 1
        assert "availableTokens" in stats


class TestNotificationPriorityQueue:
    """Test notification data structures, priority sorting, overflow handling, and formats."""

    def test_priority_ordering_critical_first(self):
        queue = NotificationPriorityQueue(maxCapacity=10)

        # Create notifications in mixed order: Medium -> Critical -> High -> Low
        notifMed = AlertNotification.fromDecision(
            RiskDecision(ThreatLevel.medium, 0.5, "suspicious", "notifyUser"),
            message="Medium threat",
        )
        notifCrit = AlertNotification.fromDecision(
            RiskDecision(ThreatLevel.critical, 0.95, "ransomwareLike", "quarantine"),
            message="Critical threat",
        )
        notifHigh = AlertNotification.fromDecision(
            RiskDecision(ThreatLevel.high, 0.8, "ransomwareLike", "alertOnly"),
            message="High threat",
        )
        notifLow = AlertNotification.fromDecision(
            RiskDecision(ThreatLevel.low, 0.1, "benign", "logOnly"),
            message="Low info",
        )

        queue.enqueue(notifMed)
        queue.enqueue(notifCrit)
        queue.enqueue(notifHigh)
        queue.enqueue(notifLow)

        assert queue.size() == 4

        # Dequeue must return in priority order: P1 (Critical) -> P2 (High) -> P3 (Medium) -> P4 (Low)
        item1 = queue.dequeue()
        assert item1.priority == 1
        assert item1.severity == "critical"

        item2 = queue.dequeue()
        assert item2.priority == 2
        assert item2.severity == "high"

        item3 = queue.dequeue()
        assert item3.priority == 3
        assert item3.severity == "medium"

        item4 = queue.dequeue()
        assert item4.priority == 4
        assert item4.severity == "low"

        assert queue.isEmpty() is True

    def test_fifo_ordering_within_same_priority(self):
        queue = NotificationPriorityQueue(maxCapacity=10)
        t0 = datetime(2026, 10, 8, 12, 0, 0, tzinfo=timezone.utc)

        notif1 = AlertNotification.fromDecision(
            RiskDecision(ThreatLevel.high, 0.75, "ransomwareLike"),
            message="First High",
            occurredAt=t0,
        )
        notif2 = AlertNotification.fromDecision(
            RiskDecision(ThreatLevel.high, 0.85, "ransomwareLike"),
            message="Second High",
            occurredAt=t0 + timedelta(seconds=1),
        )

        queue.enqueue(notif1)
        queue.enqueue(notif2)

        p1 = queue.dequeue()
        p2 = queue.dequeue()
        assert p1.message == "First High"
        assert p2.message == "Second High"

    def test_queue_overflow_drops_lower_priority(self):
        queue = NotificationPriorityQueue(maxCapacity=2)

        notifMed1 = AlertNotification.fromDecision(
            RiskDecision(ThreatLevel.medium, 0.5, "suspicious"), message="Med 1"
        )
        notifMed2 = AlertNotification.fromDecision(
            RiskDecision(ThreatLevel.medium, 0.5, "suspicious"), message="Med 2"
        )
        notifCrit = AlertNotification.fromDecision(
            RiskDecision(ThreatLevel.critical, 0.95, "ransomwareLike"), message="Critical 1"
        )

        assert queue.enqueue(notifMed1) is True
        assert queue.enqueue(notifMed2) is True
        assert queue.size() == 2

        # Enqueueing Critical should displace one of the Medium notifications
        assert queue.enqueue(notifCrit) is True
        assert queue.size() == 2
        assert queue.droppedCount == 1

        top = queue.dequeue()
        assert top.priority == 1
        assert top.message == "Critical 1"

    def test_notification_formatting_and_serialization(self):
        dec = RiskDecision(ThreatLevel.critical, 0.95, "ransomwareLike", "quarantine")
        notif = AlertNotification.fromDecision(
            dec,
            message="Ransomware detected!",
            details={"processName": "malware.exe", "processId": 4567, "monitoredPath": "C:\\Data"},
        )

        # 1. Dict roundtrip
        notifDict = notif.toDict()
        reconstructed = AlertNotification.fromDict(notifDict)
        assert reconstructed.notificationId == notif.notificationId
        assert reconstructed.priority == 1
        assert reconstructed.details["processId"] == 4567

        # 2. Console Summary formatting (ASCII safe)
        consoleSummary = notif.formatConsoleSummary()
        assert "[CRITICAL ALERT]" in consoleSummary
        assert "malware.exe" in consoleSummary
        assert "4567" in consoleSummary

        # 3. Syslog / CEF formatting
        syslog = notif.formatSyslog()
        assert "CEF:0|RansomwareDetector" in syslog
        assert "src=malware.exe" in syslog

        # 4. JSON formatting
        jsonStr = notif.formatJson()
        parsed = json.loads(jsonStr)
        assert parsed["severity"] == "critical"


class TestAlertNotifierAndQuarantine:
    """Test notifier dispatcher channels, quarantine callbacks, and dispatch draining."""

    def test_notifier_dispatch_to_callbacks(self):
        notifier = AlertNotifier(autoDispatch=False)
        dispatchedRecords = []

        def customDispatcher(notif: AlertNotification) -> bool:
            dispatchedRecords.append(notif.notificationId)
            return True

        notifier.registerDispatcher("testChannel", customDispatcher)

        dec = RiskDecision(ThreatLevel.high, 0.8, "ransomwareLike", "alertOnly")
        notif = notifier.notify(dec, message="Test dispatch")

        assert notifier.queue.size() == 1
        assert len(dispatchedRecords) == 0

        # Dispatch all
        dispatchedList = notifier.dispatchAll()
        assert len(dispatchedList) == 1
        assert len(dispatchedRecords) == 1
        assert dispatchedRecords[0] == notif.notificationId
        assert notif.status == "dispatched"
        assert notifier.totalDispatched == 1

    def test_quarantine_hook_executed_for_critical_alerts(self):
        quarantinedPids = []

        def mockQuarantineHook(notif: AlertNotification) -> bool:
            pid = notif.details.get("processId")
            if pid:
                quarantinedPids.append(pid)
            return True

        notifier = AlertNotifier(quarantineHandler=mockQuarantineHook)

        critDec = RiskDecision(ThreatLevel.critical, 0.95, "ransomwareLike", "quarantine")
        notif = notifier.notify(
            critDec,
            details={"processId": 9999, "processName": "cryptor.exe"},
        )

        assert notif.quarantineStatus == "quarantined"
        assert 9999 in quarantinedPids
        assert notifier.totalQuarantined == 1

    def test_notifier_stats_and_reset(self):
        notifier = AlertNotifier()
        dec = RiskDecision(ThreatLevel.medium, 0.5, "suspicious")
        notifier.notify(dec)

        stats = notifier.getStats()
        assert stats["totalEnqueued"] == 1
        assert stats["queueSize"] == 1

        notifier.reset()
        assert notifier.queue.size() == 0
        assert notifier.totalEnqueued == 0


class TestControllerAlertIntegration:
    """End-to-end integration of DetectionController with AlertPolicy and AlertNotifier."""

    @pytest.fixture
    def testEnvironment(self) -> Generator[dict, None, None]:
        tempDir = Path(tempfile.mkdtemp(prefix="controller_alert_test_"))
        monitoredDir = tempDir / "monitored"
        monitoredDir.mkdir()
        dbPath = tempDir / "detector.sqlite3"
        yield {
            "tempDir": tempDir,
            "monitoredDir": monitoredDir,
            "dbPath": dbPath,
        }
        shutil.rmtree(tempDir, ignore_errors=True)

    def test_controller_burst_activity_rate_limited_and_queued(self, testEnvironment: dict):
        env = testEnvironment
        notifier = AlertNotifier()
        controller = DetectionController(
            monitoredPath=env["monitoredDir"],
            databasePath=env["dbPath"],
            alertCooldownSeconds=60,
            notifier=notifier,
        )

        # Inject 5 high-threat simulated file events
        for i in range(5):
            event = FileEvent(
                path=str(env["monitoredDir"] / f"file_{i}.locky"),
                action=FileAction.created,
                occurredAt=datetime.now(timezone.utc),
                source="watcher",
                processId=1234,
                processName="ransom_sim.exe",
                monitoredPath=str(env["monitoredDir"]),
            )
            controller.featureWindow.addEvents([event])

        # Run collection cycle
        decision = controller.collectOnce()
        controller.close()

        # Check that alert was evaluated, persisted in database, and queued in notifier
        assert decision.level != ThreatLevel.low
        assert controller.alertPolicy.totalRaised == 1

        # Check SQLite alerts table
        conn = sqlite3.connect(str(env["dbPath"]))
        alertCount = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        conn.close()
        assert alertCount == 1

        # Check Notifier priority queue
        assert notifier.queue.size() == 1
        queuedItem = notifier.queue.peek()
        assert queuedItem.classification == decision.classification
        assert queuedItem.details["processName"] == "ransom_sim.exe"
        assert queuedItem.details["processId"] == 1234
