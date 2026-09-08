"""Command-line exact-retraining unlearning baseline."""

import argparse
from pathlib import Path

from trainingModel.unlearning.unlearnModel import unlearnLabel


def getArguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Retrain after removing a label")
    parser.add_argument("--datasetPath", required=True)
    parser.add_argument("--forget", required=True)
    parser.add_argument("--modelPath", required=True)
    return parser.parse_args()


def main() -> int:
    arguments = getArguments()
    import pandas as pd

    dataset = pd.read_csv(Path(arguments.datasetPath))
    metadata = unlearnLabel(dataset, arguments.forget, Path(arguments.modelPath))
    print(
        f"Candidate model saved to {arguments.modelPath}; "
        f"forgot label: {arguments.forget}; "
        f"remaining samples: {metadata['sampleCount']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())