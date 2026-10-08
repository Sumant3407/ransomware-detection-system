"""Sprint 2.3 - Improved Feature Engineering Test Suite.

Verifies:
1. Operation velocity, short-window rates, and burst intensity calculation.
2. Extension diversity and Shannon entropy of extension distributions.
3. Accurate extension alteration tracking (rename pairs and suspicious extension creates).
4. Targeted document classification and directory depth metrics.
5. Multi-file entropy metrics, max entropy, and high-entropy ratios with safe file filters.
6. Process event concentration and extended risk engine evaluation.
"""

import math
import os
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from app.domain.schemas import (
    KNOWN_RANSOMWARE_EXTENSIONS,
    TARGETED_DOCUMENT_EXTENSIONS,
    FeatureSample,
    FileAction,
    FileEvent,
    extendedFeatureColumns,
    featureColumns,
    getCurrentTime,
)
from app.detection.riskEngine import ThreatLevel, calculateRiskScore, evaluateRisk
from app.features.windowing import (
    DANGEROUS_EXTENSIONS,
    MAX_FILE_SIZE_FOR_ENTROPY,
    SAFE_EXTENSIONS,
    FeatureWindow,
)


# ============================================================================
# Section 1: Operation Velocity & Burst Dynamics
# ============================================================================

class TestOperationVelocityAndBursts:
    """Test short-window velocity rates and burstiness metrics."""

    def test_files_modified_per_second_calculates_recent_burst_rate(self):
        """filesModifiedPerSecond reflects modification rate in the recent 5-second subwindow."""
        window = FeatureWindow(durationSeconds=60)
        now = getCurrentTime()

        # 10 modifications within the last 2 seconds
        events = [
            FileEvent(
                action=FileAction.modified,
                path=f"C:\\docs\\file_{i}.txt",
                occurredAt=now - timedelta(seconds=1),
            )
            for i in range(10)
        ]
        window.addEvents(events)

        sample = window.createSample(observedAt=now)
        # 10 events over 5 seconds = 2.0 files/sec
        assert sample.values["filesModifiedPerSecond"] == 2.0
        assert sample.values["filesModifiedPerMinute"] == 10.0

    def test_burst_intensity_detects_concentrated_activity(self):
        """burstIntensity is elevated when events are concentrated in the recent seconds."""
        window = FeatureWindow(durationSeconds=60)
        now = getCurrentTime()

        # 20 events in the last 2 seconds out of 20 total in a 60-second window
        events = [
            FileEvent(
                action=FileAction.modified,
                path=f"C:\\data\\file_{i}.docx",
                occurredAt=now - timedelta(seconds=1),
            )
            for i in range(20)
        ]
        window.addEvents(events)

        sample = window.createSample(observedAt=now)
        # 100% of activity in 5/60 (8.33%) of window -> intensity ~12.0
        assert sample.values["burstIntensity"] > 5.0

    def test_window_enforces_max_events_cap(self):
        """FeatureWindow caps stored events at maxEvents to prevent memory blowup."""
        window = FeatureWindow(durationSeconds=60, maxEvents=200)
        now = getCurrentTime()

        events = [
            FileEvent(
                action=FileAction.modified,
                path=f"C:\\test\\file_{i}.txt",
                occurredAt=now,
            )
            for i in range(500)
        ]
        window.addEvents(events)
        assert len(window.events) == 200


# ============================================================================
# Section 2: Extension Diversity & Entropy
# ============================================================================

class TestExtensionDiversityAndEntropy:
    """Test calculation of extension diversity and extension distribution entropy."""

    def test_single_extension_yields_zero_entropy(self):
        """Uniform extension set has 0.0 Shannon entropy."""
        window = FeatureWindow(durationSeconds=60)
        now = getCurrentTime()

        events = [
            FileEvent(
                action=FileAction.modified,
                path=f"C:\\docs\\report_{i}.pdf",
                occurredAt=now,
            )
            for i in range(10)
        ]
        window.addEvents(events)

        sample = window.createSample(observedAt=now)
        assert sample.values["extensionEntropy"] == 0.0
        assert sample.values["uniqueExtensionsModified"] == 1.0

    def test_diverse_extensions_yield_high_entropy(self):
        """Diverse extension distribution yields positive Shannon entropy."""
        window = FeatureWindow(durationSeconds=60)
        now = getCurrentTime()

        # 4 different extensions equally represented (2 each)
        exts = [".doc", ".xls", ".pdf", ".jpg"]
        events = [
            FileEvent(
                action=FileAction.modified,
                path=f"C:\\data\\file_{i}{ext}",
                occurredAt=now,
            )
            for i, ext in enumerate(exts * 2)
        ]
        window.addEvents(events)

        sample = window.createSample(observedAt=now)
        # log2(4) = 2.0 bits of entropy
        assert pytest.approx(sample.values["extensionEntropy"], 0.01) == 2.0
        assert sample.values["uniqueExtensionsModified"] == 4.0


# ============================================================================
# Section 3: Extension Change & Rename Matching
# ============================================================================

class TestExtensionChangeAndRenameTracking:
    """Test detection of file extension modifications and ransomware extension markers."""

    def test_rename_with_extension_change_increments_count(self):
        """Renaming a file with a new extension increments extensionChangeCount."""
        window = FeatureWindow(durationSeconds=60)
        now = getCurrentTime()

        events = [
            FileEvent(
                action=FileAction.renamed,
                path="C:\\Users\\User\\Documents\\finances.xlsx.locked",
                oldPath="C:\\Users\\User\\Documents\\finances.xlsx",
                occurredAt=now,
            ),
            FileEvent(
                action=FileAction.renamed,
                path="C:\\Users\\User\\Documents\\resume.docx.crypto",
                oldPath="C:\\Users\\User\\Documents\\resume.docx",
                occurredAt=now,
            ),
        ]
        window.addEvents(events)

        sample = window.createSample(observedAt=now)
        assert sample.values["fileRenameCount"] == 2.0
        assert sample.values["extensionChangeCount"] == 2.0
        assert sample.values["suspiciousExtensionCount"] == 2.0

    def test_rename_without_extension_change_not_counted_as_ext_change(self):
        """Renaming a file without changing its extension does not increment extensionChangeCount."""
        window = FeatureWindow(durationSeconds=60)
        now = getCurrentTime()

        events = [
            FileEvent(
                action=FileAction.renamed,
                path="C:\\Users\\User\\Documents\\notes_final.txt",
                oldPath="C:\\Users\\User\\Documents\\notes_draft.txt",
                occurredAt=now,
            )
        ]
        window.addEvents(events)

        sample = window.createSample(observedAt=now)
        assert sample.values["fileRenameCount"] == 1.0
        assert sample.values["extensionChangeCount"] == 0.0

    def test_creation_of_ransomware_extension_flagged(self):
        """Creating files with known ransomware extensions increments suspiciousExtensionCount."""
        window = FeatureWindow(durationSeconds=60)
        now = getCurrentTime()

        events = [
            FileEvent(
                action=FileAction.created,
                path=f"C:\\Users\\User\\Documents\\file_{i}.wnry",
                occurredAt=now,
            )
            for i in range(5)
        ]
        window.addEvents(events)

        sample = window.createSample(observedAt=now)
        assert sample.values["suspiciousExtensionCount"] == 5.0
        assert sample.values["extensionChangeCount"] == 5.0


# ============================================================================
# Section 4: High-Value Target Tracking & Directory Depth
# ============================================================================

class TestTargetTrackingAndDirectoryDepth:
    """Test targeted user data classification and directory depth metrics."""

    def test_targeted_document_classification(self):
        """Common user documents and databases increment targetedDocumentCount."""
        window = FeatureWindow(durationSeconds=60)
        now = getCurrentTime()

        targeted_files = [
            "C:\\data\\budget.xlsx",
            "C:\\data\\presentation.pptx",
            "C:\\data\\database.sqlite",
            "C:\\data\\photo.jpg",
            "C:\\data\\contract.pdf",
        ]
        unrelated_files = [
            "C:\\temp\\cache.tmp",
            "C:\\temp\\output.log",
        ]

        events = [
            FileEvent(action=FileAction.modified, path=p, occurredAt=now)
            for p in (targeted_files + unrelated_files)
        ]
        window.addEvents(events)

        sample = window.createSample(observedAt=now)
        assert sample.values["targetedDocumentCount"] == 5.0
        assert sample.values["fileWriteCount"] == 7.0

    def test_directory_depth_calculation(self):
        """averageDirectoryDepth and maxDirectoryDepth accurately reflect path depths."""
        window = FeatureWindow(durationSeconds=60)
        now = getCurrentTime()

        # Depth 3: C:\Users\Alice (3 parts)
        # Depth 5: C:\Users\Alice\Documents\Work\project.docx (6 parts)
        events = [
            FileEvent(action=FileAction.created, path="C:\\Users\\Alice\\file.txt", occurredAt=now),
            FileEvent(action=FileAction.created, path="C:\\Users\\Alice\\Documents\\Work\\Deep\\doc.pdf", occurredAt=now),
        ]
        window.addEvents(events)

        sample = window.createSample(observedAt=now)
        assert sample.values["maxDirectoryDepth"] >= 6.0
        assert sample.values["averageDirectoryDepth"] > 3.0


# ============================================================================
# Section 5: File Entropy Distribution & Safety Filters
# ============================================================================

class TestFileEntropyAndSafetyFilters:
    """Test multi-file Shannon entropy aggregation and safe read guards."""

    def test_entropy_on_plain_vs_high_entropy_file(self):
        """High-entropy files (e.g. pseudo-random/encrypted) produce high average and max entropy."""
        with tempfile.TemporaryDirectory() as tmpdir:
            window = FeatureWindow(durationSeconds=60)
            now = getCurrentTime()

            # Plain text file (low entropy ~3.0 - 4.5)
            plain_path = Path(tmpdir) / "plain.txt"
            plain_path.write_text("The quick brown fox jumps over the lazy dog " * 50, encoding="utf-8")

            # Encrypted/random binary file (high entropy > 7.5)
            encrypted_path = Path(tmpdir) / "encrypted.pdf"
            encrypted_path.write_bytes(os.urandom(4096))

            events = [
                FileEvent(action=FileAction.modified, path=str(plain_path), occurredAt=now),
                FileEvent(action=FileAction.modified, path=str(encrypted_path), occurredAt=now),
            ]
            window.addEvents(events)

            sample = window.createSample(observedAt=now)
            assert sample.values["maxFileEntropy"] > 7.2
            assert sample.values["highEntropyRatio"] == 0.5  # 1 out of 2 is > 7.2
            assert sample.values["averageFileEntropy"] > 5.0

    def test_entropy_skips_dangerous_extensions(self):
        """_canReadFileForEntropy rejects executables and system libraries."""
        window = FeatureWindow()
        assert window._canReadFileForEntropy(Path("C:\\Windows\\System32\\driver.sys")) is False
        assert window._canReadFileForEntropy(Path("C:\\Tools\\malware.exe")) is False
        assert window._canReadFileForEntropy(Path("C:\\Tools\\library.dll")) is False

    def test_entropy_skips_files_exceeding_max_size(self):
        """_canReadFileForEntropy rejects files larger than MAX_FILE_SIZE_FOR_ENTROPY."""
        with tempfile.TemporaryDirectory() as tmpdir:
            large_file = Path(tmpdir) / "huge.txt"
            # Mock stat to report 5 MB
            window = FeatureWindow()
            with patch.object(Path, "stat") as mock_stat:
                mock_stat.return_value.st_size = 5 * 1024 * 1024
                assert window._canReadFileForEntropy(large_file) is False


# ============================================================================
# Section 6: Process Correlation & Extended Risk Engine Evaluation
# ============================================================================

class TestProcessCorrelationAndRiskEngine:
    """Test process event concentration and enhanced risk scoring."""

    def test_process_concentration_metrics(self):
        """uniqueProcessesActive and topProcessEventConcentration reflect process grouping."""
        window = FeatureWindow(durationSeconds=60)
        now = getCurrentTime()

        # 8 events from PID 1000, 2 events from PID 2000
        events = [
            FileEvent(action=FileAction.modified, path=f"C:\\doc_{i}.txt", occurredAt=now, processId=1000)
            for i in range(8)
        ] + [
            FileEvent(action=FileAction.modified, path=f"C:\\doc_b_{i}.txt", occurredAt=now, processId=2000)
            for i in range(2)
        ]
        window.addEvents(events)

        sample = window.createSample(observedAt=now)
        assert sample.values["uniqueProcessesActive"] == 2.0
        assert sample.values["topProcessEventConcentration"] == 0.8  # 80% from PID 1000

    def test_evaluate_risk_with_suspicious_extensions_elevates_threat(self):
        """evaluateRisk with high suspiciousExtensionCount elevates classification to ransomwareLike."""
        # Low model probability (0.1), but high ransomware-like behavioral telemetry
        decision = evaluateRisk(
            modelProbability=0.1,
            modifiedPerMinute=50.0,
            renameCount=20.0,
            deleteCount=0.0,
            suspiciousExtensionCount=15.0,
            highEntropyRatio=0.9,
            burstIntensity=8.0,
            extensionChangeCount=20.0,
        )
        assert decision.level in (ThreatLevel.high, ThreatLevel.critical)
        assert decision.classification == "ransomwareLike"
        assert decision.score >= 0.65

    def test_evaluate_risk_backward_compatibility(self):
        """evaluateRisk produces expected legacy scores when called with only 4 arguments."""
        decision_legacy = evaluateRisk(0.05, 5.0, 0.0, 0.0)
        assert decision_legacy.level == ThreatLevel.low
        assert decision_legacy.classification == "benign"

    def test_all_canonical_and_extended_feature_columns_present(self):
        """FeatureSample contains all 16 canonical feature columns and extended columns."""
        window = FeatureWindow()
        sample = window.createSample()

        for col in featureColumns:
            assert col in sample.values
            assert isinstance(sample.values[col], float)

        for col in extendedFeatureColumns:
            assert col in sample.values
            assert isinstance(sample.values[col], float)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
