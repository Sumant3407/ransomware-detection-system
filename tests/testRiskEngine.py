import unittest

from app.detection.riskEngine import ThreatLevel, evaluateRisk


class RiskEngineTests(unittest.TestCase):
    def testLowRiskProducesLogOnlyDecision(self):
        decision = evaluateRisk(0.1, 0, 0, 0)
        self.assertEqual(decision.level, ThreatLevel.low)
        self.assertEqual(decision.action, "logOnly")

    def testHighBehaviorProducesAlertOnlyDecision(self):
        decision = evaluateRisk(0.98, 300, 100, 100)
        self.assertIn(decision.level, {ThreatLevel.high, ThreatLevel.critical})
        self.assertEqual(decision.action, "alertOnly")

    def testScoreIsBounded(self):
        decision = evaluateRisk(10, 10000, 10000, 10000)
        self.assertLessEqual(decision.score, 1.0)


if __name__ == "__main__":
    unittest.main()
