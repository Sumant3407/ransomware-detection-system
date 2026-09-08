import unittest
from datetime import datetime, timedelta, timezone

from app.detection.alertPolicy import AlertPolicy
from app.detection.riskEngine import RiskDecision, ThreatLevel


class AlertPolicyTests(unittest.TestCase):
    def testCooldownSuppressesRepeatedAlert(self):
        policy = AlertPolicy(60)
        decision = RiskDecision(ThreatLevel.high, 0.8, "ransomwareLike", "alertOnly")
        startTime = datetime.now(timezone.utc)
        self.assertTrue(policy.shouldAlert(decision, startTime))
        policy.recordAlert(decision, startTime)
        self.assertFalse(policy.shouldAlert(decision, startTime + timedelta(seconds=1)))
        self.assertTrue(policy.shouldAlert(decision, startTime + timedelta(seconds=61)))

    def testEscalationBypassesCooldown(self):
        policy = AlertPolicy(60)
        startTime = datetime.now(timezone.utc)
        mediumDecision = RiskDecision(ThreatLevel.medium, 0.5, "suspicious", "notifyUser")
        highDecision = RiskDecision(ThreatLevel.high, 0.8, "ransomwareLike", "alertOnly")
        policy.recordAlert(mediumDecision, startTime)
        self.assertTrue(policy.shouldAlert(highDecision, startTime + timedelta(seconds=1)))


if __name__ == "__main__":
    unittest.main()