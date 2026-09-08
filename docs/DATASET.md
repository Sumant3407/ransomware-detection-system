# Dataset Notes

`data/datasets/ransomwareBehaviorDataset.csv` is the collector-compatible dataset. Its feature schema is defined in `app/domain/schemas.py`. It must contain both `Benign` and `Ransomware` or `RANSOMWARE_LIKE` labels before training.

For new experiments, record a scenario or experiment identifier and split by scenario or session where possible. Do not store file contents or sensitive personal data.
