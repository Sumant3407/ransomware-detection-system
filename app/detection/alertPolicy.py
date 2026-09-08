"""Alert deduplication and cooldown policy."""

from datetime import datetime, timedelta, timezone

from app.detection.riskEngine import RiskDecision, ThreatLevel


class AlertPolicy:
    def __init__(self, cooldownSeconds: int = 60):
        self.cooldown = timedelta(seconds=max(0, cooldownSeconds))
        self.lastAlertAt: datetime | None = None
        self.lastLevel: ThreatLevel | None = None

    def shouldAlert(self, decision: RiskDecision, now: datetime | None = None) -> bool:
        if decision.level == ThreatLevel.low:
            return False
        currentTime = now or datetime.now(timezone.utc)
        if self.lastAlertAt is None:
            return True
        levelRank = {
            ThreatLevel.low: 0,
            ThreatLevel.medium: 1,
            ThreatLevel.high: 2,
            ThreatLevel.critical: 3,
        }
        if levelRank[decision.level] > levelRank[self.lastLevel]:
            return True
        return currentTime - self.lastAlertAt >= self.cooldown

    def recordAlert(self, decision: RiskDecision, now: datetime | None = None) -> None:
        self.lastAlertAt = now or datetime.now(timezone.utc)
        self.lastLevel = decision.level
