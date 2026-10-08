"""Alert deduplication, rate limiting, and cooldown policy with structured logging."""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from app.detection.riskEngine import RiskDecision, ThreatLevel

logger = logging.getLogger(__name__)


class TokenBucket:
    """
    Token bucket rate limiter providing burst capacity and steady-state refill rate.
    """

    def __init__(self, capacity: float = 10.0, refillRatePerSecond: float = 0.1667):
        self.capacity = max(1.0, float(capacity))
        self.refillRate = max(0.0001, float(refillRatePerSecond))
        self.tokens = self.capacity
        self.lastRefillTime: float = 0.0

    def _getTimestamp(self, now: Optional[datetime | float] = None) -> float:
        if now is None:
            return datetime.now(timezone.utc).timestamp()
        if isinstance(now, datetime):
            return now.timestamp()
        return float(now)

    def refill(self, now: Optional[datetime | float] = None) -> None:
        currentTime = self._getTimestamp(now)
        if self.lastRefillTime == 0.0:
            self.lastRefillTime = currentTime
            return

        elapsed = max(0.0, currentTime - self.lastRefillTime)
        if elapsed > 0:
            newTokens = elapsed * self.refillRate
            self.tokens = min(self.capacity, self.tokens + newTokens)
            self.lastRefillTime = currentTime

    def consume(self, tokens: float = 1.0, now: Optional[datetime | float] = None) -> bool:
        """
        Attempt to consume specified tokens from the bucket.

        Returns:
            True if tokens were consumed, False if insufficient tokens.
        """
        self.refill(now)
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False

    def availableTokens(self, now: Optional[datetime | float] = None) -> float:
        self.refill(now)
        return self.tokens

    def reset(self) -> None:
        self.tokens = self.capacity
        self.lastRefillTime = 0.0


class AlertDeduplicator:
    """
    Deduplicates repetitive alert events within a sliding time window.
    """

    def __init__(self, dedupWindowSeconds: float = 120.0):
        self.dedupWindow = timedelta(seconds=max(1.0, dedupWindowSeconds))
        self.records: dict[str, dict[str, Any]] = {}

    def _purgeExpired(self, currentTime: datetime) -> None:
        expiredKeys = [
            k
            for k, v in self.records.items()
            if (currentTime - v["lastSeenAt"]) > self.dedupWindow
        ]
        for k in expiredKeys:
            del self.records[k]

    def isDuplicate(
        self,
        signature: str,
        level: ThreatLevel,
        now: Optional[datetime] = None,
    ) -> tuple[bool, bool]:
        """
        Check if an alert signature is a duplicate.

        Returns:
            (isDuplicate, isEscalation)
        """
        currentTime = now or datetime.now(timezone.utc)
        self._purgeExpired(currentTime)

        if signature not in self.records:
            return False, False

        entry = self.records[signature]
        prevLevel = entry["level"]
        levelRank = {
            ThreatLevel.low: 0,
            ThreatLevel.medium: 1,
            ThreatLevel.high: 2,
            ThreatLevel.critical: 3,
        }

        isEscalation = levelRank.get(level, 0) > levelRank.get(prevLevel, 0)
        return True, isEscalation

    def record(
        self,
        signature: str,
        level: ThreatLevel,
        now: Optional[datetime] = None,
    ) -> None:
        currentTime = now or datetime.now(timezone.utc)
        if signature in self.records:
            self.records[signature]["count"] += 1
            self.records[signature]["lastSeenAt"] = currentTime
            self.records[signature]["level"] = level
        else:
            self.records[signature] = {
                "firstSeenAt": currentTime,
                "lastSeenAt": currentTime,
                "level": level,
                "count": 1,
            }

    def getDuplicateCount(self, signature: str) -> int:
        return self.records.get(signature, {}).get("count", 0)

    def reset(self) -> None:
        self.records.clear()


class AlertPolicy:
    """
    Comprehensive Alert Policy managing token bucket rate limiting, deduplication,
    escalation bypass, and cooldown suppression.
    """

    def __init__(
        self,
        cooldownSeconds: int = 60,
        maxAlertsPerMinute: int = 10,
        burstCapacity: int = 10,
        dedupWindowSeconds: int = 120,
        enableRateLimiting: bool = True,
        enableDeduplication: bool = True,
    ):
        self.cooldown = timedelta(seconds=max(0, cooldownSeconds))
        self.lastAlertAt: Optional[datetime] = None
        self.lastLevel: Optional[ThreatLevel] = None

        # Rate Limiting
        self.enableRateLimiting = enableRateLimiting
        refillRate = maxAlertsPerMinute / 60.0
        self.rateLimiter = TokenBucket(capacity=burstCapacity, refillRatePerSecond=refillRate)

        # Deduplication
        self.enableDeduplication = enableDeduplication
        self.deduplicator = AlertDeduplicator(dedupWindowSeconds=dedupWindowSeconds)

        # Statistics & Telemetry
        self.totalEvaluated: int = 0
        self.totalRaised: int = 0
        self.cooldownSuppressed: int = 0
        self.deduplicatedSuppressed: int = 0
        self.rateLimitedSuppressed: int = 0

    @property
    def cooldownSeconds(self) -> int:
        return int(self.cooldown.total_seconds())

    @cooldownSeconds.setter
    def cooldownSeconds(self, value: int | float) -> None:
        self.cooldown = timedelta(seconds=max(0, int(value)))

    def _computeSignature(
        self,
        decision: RiskDecision,
        context: Optional[dict[str, Any]] = None,
    ) -> str:
        """Compute unique signature key for deduplication."""
        ctx = context or {}
        processId = ctx.get("processId", "any")
        processName = ctx.get("processName", "any")
        pathHash = ctx.get("pathHash", ctx.get("pathId", "any"))
        return f"{decision.classification}:{processName}:{processId}:{pathHash}"

    def _getTokenCost(self, level: ThreatLevel) -> float:
        """
        Determine token cost by threat level.
        Critical threats have lower token cost to prevent starvation during high load.
        """
        if level == ThreatLevel.critical:
            return 0.5
        elif level == ThreatLevel.high:
            return 1.0
        elif level == ThreatLevel.medium:
            return 1.0
        return 0.0

    def shouldAlert(
        self,
        decision: RiskDecision,
        now: Optional[datetime] = None,
        context: Optional[dict[str, Any]] = None,
    ) -> bool:
        """
        Determine if an alert should be raised, evaluating severity, cooldown,
        escalation, deduplication, and token bucket rate limits.
        """
        if decision.level == ThreatLevel.low:
            return False

        currentTime = now or datetime.now(timezone.utc)
        self.totalEvaluated += 1

        # 1. First alert ever
        if self.lastAlertAt is None:
            tokenCost = self._getTokenCost(decision.level)
            if self.enableRateLimiting:
                self.rateLimiter.consume(tokenCost, now=currentTime)
            sig = self._computeSignature(decision, context)
            self.deduplicator.record(sig, decision.level, now=currentTime)
            logger.info(
                f"First alert triggered: level={decision.level.value}, score={decision.score:.4f}",
                extra={
                    "event": "alert_evaluation",
                    "context": {
                        "decision": decision.classification,
                        "level": decision.level.value,
                        "score": decision.score,
                    },
                },
            )
            return True

        levelRank = {
            ThreatLevel.low: 0,
            ThreatLevel.medium: 1,
            ThreatLevel.high: 2,
            ThreatLevel.critical: 3,
        }

        # 2. Escalation check (higher threat level bypasses standard cooldown and dedup)
        prevRank = levelRank.get(self.lastLevel, 0)
        currRank = levelRank.get(decision.level, 0)
        isEscalated = currRank > prevRank

        if isEscalated:
            tokenCost = self._getTokenCost(decision.level)
            if self.enableRateLimiting and not self.rateLimiter.consume(tokenCost, now=currentTime):
                self.rateLimitedSuppressed += 1
                logger.warning(
                    f"Escalated alert rate-limited ({decision.level.value}): tokens exhausted",
                    extra={
                        "event": "alert_rate_limited",
                        "context": {
                            "level": decision.level.value,
                            "previousLevel": self.lastLevel.value if self.lastLevel else "none",
                        },
                    },
                )
                return False

            sig = self._computeSignature(decision, context)
            self.deduplicator.record(sig, decision.level, now=currentTime)
            logger.info(
                f"Alert escalated: {self.lastLevel.value if self.lastLevel else 'none'} -> {decision.level.value}",
                extra={
                    "event": "alert_evaluation",
                    "context": {
                        "previousLevel": self.lastLevel.value if self.lastLevel else "none",
                        "newLevel": decision.level.value,
                        "score": decision.score,
                    },
                },
            )
            return True

        # 3. Cooldown Check (when not escalated)
        timeSinceLast = currentTime - self.lastAlertAt
        if timeSinceLast < self.cooldown:
            self.cooldownSuppressed += 1
            logger.debug(
                f"Alert suppressed by cooldown ({timeSinceLast.total_seconds():.1f}s < {self.cooldown.total_seconds():.1f}s)",
                extra={
                    "event": "alert_suppressed",
                    "context": {
                        "level": decision.level.value,
                        "cooldownRemainingSeconds": round((self.cooldown - timeSinceLast).total_seconds(), 2),
                    },
                },
            )
            return False

        # 4. Deduplication Check (active when cooldown is zero or disabled)
        if self.cooldown.total_seconds() == 0 and self.enableDeduplication:
            sig = self._computeSignature(decision, context)
            isDup, isDedupEscalation = self.deduplicator.isDuplicate(sig, decision.level, now=currentTime)
            if isDup and not isDedupEscalation:
                self.deduplicatedSuppressed += 1
                logger.debug(
                    f"Alert suppressed by deduplication (signature={sig})",
                    extra={
                        "event": "alert_deduplicated",
                        "context": {
                            "signature": sig,
                            "level": decision.level.value,
                            "duplicateCount": self.deduplicator.getDuplicateCount(sig),
                        },
                    },
                )
                return False

        # 4. Token Bucket Rate Limiter Check (cooldown has expired)
        tokenCost = self._getTokenCost(decision.level)
        if self.enableRateLimiting:
            if not self.rateLimiter.consume(tokenCost, now=currentTime):
                self.rateLimitedSuppressed += 1
                logger.warning(
                    f"Alert suppressed by token bucket rate limit ({decision.level.value})",
                    extra={
                        "event": "alert_rate_limited",
                        "context": {
                            "level": decision.level.value,
                            "availableTokens": round(self.rateLimiter.availableTokens(now=currentTime), 2),
                        },
                    },
                )
                return False

        # 5. Passed all filters
        sig = self._computeSignature(decision, context)
        self.deduplicator.record(sig, decision.level, now=currentTime)
        logger.info(
            f"Alert cooldown expired ({timeSinceLast.total_seconds():.1f}s >= {self.cooldown.total_seconds():.1f}s), raising alert",
            extra={
                "event": "alert_evaluation",
                "context": {
                    "level": decision.level.value,
                    "score": decision.score,
                },
            },
        )
        return True

    def recordAlert(
        self,
        decision: RiskDecision,
        now: Optional[datetime] = None,
        context: Optional[dict[str, Any]] = None,
    ) -> None:
        """Record an alert occurrence and update state."""
        self.lastAlertAt = now or datetime.now(timezone.utc)
        self.lastLevel = decision.level
        self.totalRaised += 1

        sig = self._computeSignature(decision, context)
        self.deduplicator.record(sig, decision.level, now=self.lastAlertAt)

        logger.debug(
            f"Recorded alert at {self.lastAlertAt.isoformat()}: level={decision.level.value}",
            extra={
                "event": "alert_recorded",
                "context": {
                    "level": decision.level.value,
                    "score": decision.score,
                },
            },
        )

    def getStatistics(self) -> dict[str, Any]:
        """Return diagnostic metrics on alert evaluations and suppressions."""
        return {
            "totalEvaluated": self.totalEvaluated,
            "totalRaised": self.totalRaised,
            "cooldownSuppressed": self.cooldownSuppressed,
            "deduplicatedSuppressed": self.deduplicatedSuppressed,
            "rateLimitedSuppressed": self.rateLimitedSuppressed,
            "availableTokens": round(self.rateLimiter.availableTokens(), 2),
            "activeDeduplicationEntries": len(self.deduplicator.records),
        }

    def reset(self) -> None:
        """Reset policy state and counters."""
        self.lastAlertAt = None
        self.lastLevel = None
        self.rateLimiter.reset()
        self.deduplicator.reset()
        self.totalEvaluated = 0
        self.totalRaised = 0
        self.cooldownSuppressed = 0
        self.deduplicatedSuppressed = 0
        self.rateLimitedSuppressed = 0
