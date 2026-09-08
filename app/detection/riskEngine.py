"""Conservative risk aggregation for behavioral predictions."""

from dataclasses import dataclass
from enum import StrEnum


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
) -> float:
    boundedProbability = max(0.0, min(1.0, modelProbability))
    behaviorBoost = min(
        0.70,
        modifiedPerMinute / 300.0
        + renameCount / 100.0
        + deleteCount / 100.0,
    )
    return round(
        min(
            1.0,
            boundedProbability * 0.45
            + behaviorBoost * 0.55,
        ),
        4,
    )


def evaluateRisk(
    modelProbability: float,
    modifiedPerMinute: float,
    renameCount: float,
    deleteCount: float,
) -> RiskDecision:
    score = calculateRiskScore(
        modelProbability,
        modifiedPerMinute,
        renameCount,
        deleteCount,
    )

    if score >= 0.85:
        return RiskDecision(
            ThreatLevel.critical,
            score,
            "ransomwareLike",
            "alertOnly",
        )
    if score >= 0.65:
        return RiskDecision(
            ThreatLevel.high,
            score,
            "ransomwareLike",
            "alertOnly",
        )
    if score >= 0.40:
        return RiskDecision(
            ThreatLevel.medium,
            score,
            "suspicious",
            "notifyUser",
        )
    return RiskDecision(
        ThreatLevel.low,
        score,
        "benign",
        "logOnly",
    )
