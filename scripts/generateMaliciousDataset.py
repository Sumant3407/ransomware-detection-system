"""CLI utility to generate balanced benign and synthetic ransomware behavioral datasets."""

import argparse
import sys
from pathlib import Path

# Add project root to sys.path
projectRoot = Path(__file__).resolve().parent.parent
if str(projectRoot) not in sys.path:
    sys.path.insert(0, str(projectRoot))

from trainingModel.collection.syntheticData import generateAndSaveDataset
from trainingModel.validation.datasetValidator import DatasetValidator


def getArguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate synthetic balanced dataset for ransomware behavior classifier training."
    )
    parser.add_argument(
        "--output",
        "-o",
        default="data/datasets/ransomwareBehaviorDataset.csv",
        help="Target output CSV file path (default: data/datasets/ransomwareBehaviorDataset.csv)",
    )
    parser.add_argument(
        "--samples",
        "-n",
        type=int,
        default=300,
        help="Total number of samples to generate (default: 300)",
    )
    parser.add_argument(
        "--malicious-ratio",
        "-r",
        type=float,
        default=0.5,
        help="Ratio of malicious ransomware samples [0.05 - 0.95] (default: 0.5)",
    )
    parser.add_argument(
        "--seed",
        "-s",
        type=int,
        default=42,
        help="Random seed for deterministic generation (default: 42)",
    )
    return parser.parse_args()


def main() -> int:
    args = getArguments()
    outputPath = Path(args.output)
    if not outputPath.is_absolute():
        outputPath = projectRoot / outputPath

    print("=" * 72)
    print("      SYNTHETIC BEHAVIORAL DATASET GENERATOR")
    print("=" * 72)
    print(f"Output target   : {outputPath}")
    print(f"Total samples   : {args.samples}")
    print(f"Malicious ratio : {args.malicious_ratio * 100:.1f}%")
    print(f"Random seed     : {args.seed}")
    print("-" * 72)

    df = generateAndSaveDataset(
        outputPath=outputPath,
        sampleCount=args.samples,
        maliciousRatio=args.malicious_ratio,
        seed=args.seed,
    )

    validator = DatasetValidator()
    result = validator.validate(df, strict=False)

    print(f"Dataset generated successfully: {len(df)} rows written.")
    print(f"Validation Status: {result.status} (Valid: {result.isValid})")
    print(f"Class counts     : {result.classDistribution}")
    print("=" * 72)
    return 0 if result.isValid else 1


if __name__ == "__main__":
    raise SystemExit(main())
