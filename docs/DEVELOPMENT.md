# Development

Activate the virtual environment and run the test suite:

```powershell
.\.venv\Scripts\Activate.ps1
python -m compileall app trainingModel scripts tests
python -m unittest discover -s tests -p "test*.py"
```

Useful commands:

```text
python -m app.main --status
python -m app.main --monitor --samples 10 --interval 1
python scripts/generateTestData.py --files 100
python scripts/legacy/labActivitySimulator.py testFiles --init --count 10
python trainingModel/training/ransomwareLearner.py --datasetPath data/datasets/ransomwareBehaviorDataset.csv --modelPath data/models/candidate.joblib
python -m trainingModel.unlearning.unlearn --datasetPath data.csv --forget Ransomware --modelPath candidate.joblib
```

Use only generated files and marked disposable directories for simulations. The active collector dataset must contain at least two labels before training. Metrics are calculated from held-out data and are never fabricated.
