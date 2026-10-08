#!/usr/bin/env python3
"""CLI utility for managing the automated model retraining pipeline."""

import argparse
import json
import logging
import sys
from pathlib import Path

# Add project root to sys.path
projectRoot = Path(__file__).resolve().parent.parent
if str(projectRoot) not in sys.path:
    sys.path.insert(0, str(projectRoot))

from app.config.configuration import loadConfiguration
from app.models.retrainingPipeline import (
    RetrainingConfig,
    RetrainingPipeline,
    RetrainingStatus,
    RetrainingTrigger,
)

logger = logging.getLogger("retrainPipeline")


def formatReport(report: dict) -> str:
    """Format retraining report into human-readable summary."""
    rocAucVal = report.get("cvRocAuc")
    rocAucStr = f"{rocAucVal:.4f}" if rocAucVal is not None else "N/A"

    lines = [
        "==================================================",
        "          RETRAINING PIPELINE REPORT              ",
        "==================================================",
        f"  Status:             {str(report.get('status', 'unknown')).upper()}",
        f"  Promoted:           {'YES (Active in Production)' if report.get('promoted') else 'NO'}",
        f"  Trigger:            {report.get('triggerType')}",
        f"  Baseline Version:   {report.get('baselineVersion')}",
        f"  Candidate Version:  {report.get('candidateVersion')}",
        f"  Total Samples:      {report.get('sampleCount')}",
        f"  Feedback Samples:   {report.get('feedbackSampleCount')}",
        f"  CV Accuracy:        {report.get('cvAccuracy', 0.0):.4f}",
        f"  CV F1-Score:        {report.get('cvF1', 0.0):.4f}",
        f"  Baseline F1-Score:  {report.get('baselineF1', 0.0):.4f}",
        f"  CV ROC-AUC:         {rocAucStr}",
        f"  Execution Time:     {report.get('durationSeconds', 0.0):.2f}s",
        f"  Reason:             {report.get('reason')}",
        "==================================================",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Ransomware Detection Model Retraining Pipeline CLI",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--config",
        dest="configPath",
        type=str,
        default=None,
        help="Path to configuration file (default: defaultConfig.json)",
    )
    parser.add_argument(
        "--check-triggers",
        action="store_true",
        help="Check if accumulated feedback satisfies retraining thresholds",
    )
    parser.add_argument(
        "--retrain",
        action="store_true",
        help="Execute candidate model retraining and validation workflow",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force retraining even if feedback count is below threshold",
    )
    parser.add_argument(
        "--rollback",
        action="store_true",
        help="Roll back active production model to previous version",
    )
    parser.add_argument(
        "--history",
        type=int,
        nargs="?",
        const=5,
        default=None,
        help="Display recent retraining runs from database (default: 5)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as structured JSON",
    )

    args = parser.parse_args()

    # Load configuration
    try:
        config = loadConfiguration(args.configPath)
    except Exception as error:
        print(f"Error loading configuration: {error}", file=sys.stderr)
        return 1

    modelsDir = Path(config.get("model", {}).get("modelsDirectory", "data/models"))
    dbPath = Path(config.get("storage", {}).get("databasePath", "data/storage.db"))
    datasetPath = Path(config.get("model", {}).get("datasetPath", "data/datasets/ransomwareBehaviorDataset.csv"))

    pipeline = RetrainingPipeline(
        modelsDirectory=modelsDir,
        databasePath=dbPath,
        datasetPath=datasetPath,
        config=RetrainingConfig(
            minNewFeedbackSamples=int(config["model"].get("minFeedbackSamples", 5)),
            encryptArtifacts=bool(config["model"].get("encryptModel", True)),
        ),
    )

    if args.check_triggers:
        shouldRetrain, trigger, count = pipeline.checkTriggers()
        if args.json:
            print(json.dumps({"shouldRetrain": shouldRetrain, "trigger": str(trigger), "feedbackCount": count}))
        else:
            print(f"[Trigger Check] Unused feedback samples: {count} (Threshold: {pipeline.config.minNewFeedbackSamples})")
            print(f"[Trigger Check] Retraining required: {'YES' if shouldRetrain else 'NO'}")
        return 0

    if args.rollback:
        try:
            rolledBackPath = pipeline.rollback()
            if args.json:
                print(json.dumps({"success": True, "action": "rollback", "modelPath": str(rolledBackPath)}))
            else:
                print(f"[Rollback Success] Production model successfully rolled back to: {rolledBackPath}")
            return 0
        except Exception as error:
            if args.json:
                print(json.dumps({"success": False, "action": "rollback", "error": str(error)}))
            else:
                print(f"[Rollback Error] {error}", file=sys.stderr)
            return 1

    if args.history is not None:
        runs = pipeline.getHistory(limit=args.history)
        if args.json:
            print(json.dumps(runs, indent=2))
        else:
            print(f"=== Last {len(runs)} Retraining Runs ===")
            for run in runs:
                print(
                    f"Run #{run['runId']} | {run['startedAt']} | Status: {run['status']} | "
                    f"Promoted: {run['promoted']} | F1: {run['cvF1']:.4f} | Samples: {run['sampleCount']}"
                )
        return 0

    if args.retrain:
        trigger = RetrainingTrigger.MANUAL if args.force else RetrainingTrigger.THRESHOLD
        report = pipeline.executeRetraining(triggerType=trigger, force=args.force)

        if args.json:
            print(json.dumps(report.toDict(), indent=2))
        else:
            print(formatReport(report.toDict()))

        return 0 if report.success else 1

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
