"""Conservative risk aggregation for behavioral predictions with structured logging."""

import logging
from dataclasses import dataclass
from enum import StrEnum

logger = logging.getLogger(__name__)


class ThreatLevel(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


@dataclass(frozen=True)
class RiskDecision:
    level: ThreatLevel
    score: float
    classification: str
    action: str = "logOnly"


def calculateRiskScore(
    modelProbability: float,
    modifiedPerMinute: float,
    renameCount: float,
    deleteCount: float,
    suspiciousExtensionCount: float = 0.0,
    targetedDocumentCount: float = 0.0,
    highEntropyRatio: float = 0.0,
    burstIntensity: float = 0.0,
    extensionChangeCount: float = 0.0,
) -> float:
    """
    Calculate composite risk score [0.0 - 1.0] from model inference and behavioral features.

    Combines:
    - ML Model probability (45% weight)
    - File operation velocity (modifications, renames, deletions)
    - Ransomware-specific extension markers & high entropy concentration
    - Burst intensity (short-window velocity)
    """
    boundedProbability = max(0.0, min(1.0, modelProbability))

    # Base operation counts boost
    baseBoost = min(
        0.70,
        modifiedPerMinute / 300.0
        + renameCount / 100.0
        + deleteCount / 100.0,
    )

    blendedScore = boundedProbability * 0.45 + baseBoost * 0.55

    # Specific ransomware heuristics
    ransomwareBoost = (
        min(0.40, suspiciousExtensionCount * 0.10)
        + min(0.25, extensionChangeCount * 0.02)
        + (highEntropyRatio * 0.30 if modifiedPerMinute >= 5 else 0.0)
        + (min(0.15, burstIntensity * 0.03) if modifiedPerMinute >= 15 else 0.0)
        + (min(0.15, targetedDocumentCount * 0.01) if modifiedPerMinute >= 20 else 0.0)
    )

    # When explicit high-fidelity ransomware markers are active, allow behavioral score to lead
    if suspiciousExtensionCount > 0 or (highEntropyRatio > 0.5 and modifiedPerMinute >= 10) or extensionChangeCount >= 10:
        heuristicScore = min(1.0, baseBoost + ransomwareBoost)
        composite = max(blendedScore, heuristicScore)
    else:
        composite = blendedScore

    return round(min(1.0, max(0.0, composite)), 4)


def evaluateRisk(
    modelProbability: float,
    modifiedPerMinute: float,
    renameCount: float,
    deleteCount: float,
    suspiciousExtensionCount: float = 0.0,
    targetedDocumentCount: float = 0.0,
    highEntropyRatio: float = 0.0,
    burstIntensity: float = 0.0,
    extensionChangeCount: float = 0.0,
) -> RiskDecision:
    """
    Evaluate threat decision from model prediction and behavioral telemetry.
    """
    score = calculateRiskScore(
        modelProbability,
        modifiedPerMinute,
        renameCount,
        deleteCount,
        suspiciousExtensionCount=suspiciousExtensionCount,
        targetedDocumentCount=targetedDocumentCount,
        highEntropyRatio=highEntropyRatio,
        burstIntensity=burstIntensity,
        extensionChangeCount=extensionChangeCount,
    )

    if score >= 0.85:
        decision = RiskDecision(
            ThreatLevel.critical,
            score,
            "ransomwareLike",
            "alertOnly",
        )
    elif score >= 0.65:
        decision = RiskDecision(
            ThreatLevel.high,
            score,
            "ransomwareLike",
            "alertOnly",
        )
    elif score >= 0.40:
        decision = RiskDecision(
            ThreatLevel.medium,
            score,
            "suspicious",
            "notifyUser",
        )
    else:
        decision = RiskDecision(
            ThreatLevel.low,
            score,
            "benign",
            "logOnly",
        )

    logger.debug(
        f"Risk evaluated: level={decision.level.value}, score={score:.4f}, class={decision.classification}",
        extra={
            "event": "risk_evaluation",
            "context": {
                "score": score,
                "level": decision.level.value,
                "classification": decision.classification,
                "modelProbability": modelProbability,
                "modifiedPerMinute": modifiedPerMinute,
                "renameCount": renameCount,
                "deleteCount": deleteCount,
                "suspiciousExtensionCount": suspiciousExtensionCount,
                "targetedDocumentCount": targetedDocumentCount,
                "highEntropyRatio": highEntropyRatio,
                "burstIntensity": burstIntensity,
            },
        },
    )
    return decision
