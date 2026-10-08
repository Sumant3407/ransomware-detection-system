"""Demo and safe laboratory simulation engine for Ransomware Detection System."""

import logging
import os
import random
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, List, Optional

from app.config.configuration import getDataDirectory, getProjectRoot
from app.security.pathValidator import PathValidationError, PathValidator

logger = logging.getLogger(__name__)

MARKER_FILE = ".demo-sandbox"

BENIGN_TEMPLATES = {
    "txt": [
        "Quarterly Project Review Notes\nAll milestones on schedule. Team velocity increased by 14%.\n",
        "Server Deployment Checklist:\n1. Update packages\n2. Check firewall\n3. Restart daemon\n",
        "Meeting Minutes:\nDiscussed UI dashboard enhancements and ML detection metrics.\n",
    ],
    "csv": [
        "TransactionID,CustomerName,Amount,Status,Timestamp\nTX1001,Acme Corp,1450.00,COMPLETED,2026-10-08T10:00:00Z\nTX1002,Global Logistics,890.50,COMPLETED,2026-10-08T10:05:00Z\n",
        "EmployeeID,Department,Role,SalaryTier\nE091,Engineering,Security Analyst,Tier-3\nE092,Operations,DevOps Engineer,Tier-3\n",
    ],
    "json": [
        '{\n  "service": "telemetry-aggregator",\n  "status": "online",\n  "version": "2.4.0",\n  "activeConnections": 42\n}\n',
        '{\n  "dashboard": {\n    "refreshInterval": 500,\n    "theme": "dark",\n    "activeTab": "liveActivity"\n  }\n}\n',
    ],
    "docx": [
        "PK\x03\x04\x14\x00\x00\x00\x08\x00WordDocumentBinarySimulatedHeader\nStandard Office Document Text Body\n",
    ],
    "xlsx": [
        "PK\x03\x04\x14\x00\x00\x00\x08\x00ExcelSpreadsheetBinarySimulatedHeader\nFinancial Spreadsheet Data Table\n",
    ],
    "pdf": [
        "%PDF-1.4\n1 0 obj\n<< /Title (Annual Financial Summary) /Author (Finance Dept) >>\nendobj\n",
    ],
    "py": [
        "# Script for scheduled data backup\nimport os\nimport sys\n\ndef main():\n    print('Backup completed successfully')\n\nif __name__ == '__main__':\n    main()\n",
    ],
    "jpg": [
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00\xff\xdb\x00C\x00SimulatedBenignJpegImageBytes",
    ],
}

RANSOMWARE_EXTENSIONS = [".locked", ".crypto", ".enc", ".wnry", ".darkbit"]


class DemoActionType(Enum):
    GENERATE_BENIGN = "generate_benign"
    SIMULATE_NORMAL = "simulate_normal"
    SIMULATE_RANSOMWARE = "simulate_ransomware"
    CLEAN_SANDBOX = "clean_sandbox"


@dataclass
class DemoReport:
    """Summary of a completed demo operation."""
    action: DemoActionType
    targetDirectory: Path
    filesCreated: int = 0
    filesModified: int = 0
    filesRenamed: int = 0
    filesDeleted: int = 0
    durationSeconds: float = 0.0
    details: List[str] = field(default_factory=list)
    success: bool = True
    errorMessage: Optional[str] = None


class DemoEngine:
    """Safely creates benign files, normal office activity, and safe lab ransomware simulations."""

    def __init__(self, sandboxPath: Optional[Path] = None):
        """
        Initialize DemoEngine.

        Args:
            sandboxPath: Directory where demo files will be generated.
                         Defaults to projectRoot / 'testFiles'.
        """
        if sandboxPath is None:
            self.sandboxPath = (getProjectRoot() / "testFiles").resolve()
        else:
            self.sandboxPath = Path(sandboxPath).resolve()

        self.validator = PathValidator()

    def ensureSandbox(self) -> Path:
        """
        Validate safety and ensure sandbox directory exists with safety marker.

        Returns:
            Resolved Path of the sandbox directory.

        Raises:
            PathValidationError: If path fails safety validation.
        """
        # Create directory first so validator can verify it exists
        self.sandboxPath.mkdir(parents=True, exist_ok=True)

        # Validate that path is safe (not C:\Windows, not system directories)
        validated = self.validator.validate(str(self.sandboxPath))

        # Drop safety marker
        marker = validated / MARKER_FILE
        marker.touch(exist_ok=True)

        return validated

    def generateBenignFiles(
        self,
        count: int = 25,
        callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> DemoReport:
        """
        Generate realistic benign office and user files in the sandbox.

        Args:
            count: Number of files to generate (1 to 1000).
            callback: Optional progress callback (currentCount, totalCount, filename).

        Returns:
            DemoReport summarizing generated files.
        """
        startTime = time.time()
        sandbox = self.ensureSandbox()
        created = 0
        details: List[str] = []

        fileTypes = list(BENIGN_TEMPLATES.keys())
        randomGen = random.Random(42 + int(time.time() * 1000) % 10000)

        names = [
            "quarterly_financials", "employee_directory", "meeting_notes", "project_roadmap",
            "server_config", "system_architecture", "audit_log_sample", "customer_records",
            "sales_projection", "inventory_report", "presentation_draft", "tax_summary",
            "vendor_contracts", "compliance_checklist", "release_notes", "incident_summary",
        ]

        for i in range(count):
            ext = randomGen.choice(fileTypes)
            baseName = names[i % len(names)]
            filename = f"{baseName}_{i+1:03d}.{ext}"
            filePath = sandbox / filename

            template = randomGen.choice(BENIGN_TEMPLATES[ext])
            if isinstance(template, bytes):
                content = template + f"\nIndex: {i}\n".encode("utf-8")
                filePath.write_bytes(content)
            else:
                content = template + f"\nDocument Index: {i+1}\nGenerated At: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                filePath.write_text(content, encoding="utf-8")

            created += 1
            details.append(f"Created: {filename}")

            if callback:
                callback(created, count, filename)

            # Micro-pause for realistic generation rate
            time.sleep(0.01)

        duration = time.time() - startTime
        logger.info(f"DemoEngine generated {created} benign files in {sandbox} in {duration:.2f}s")
        return DemoReport(
            action=DemoActionType.GENERATE_BENIGN,
            targetDirectory=sandbox,
            filesCreated=created,
            durationSeconds=duration,
            details=details,
            success=True,
        )

    def simulateNormalActivity(
        self,
        steps: int = 10,
        delaySeconds: float = 0.15,
        callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> DemoReport:
        """
        Simulate normal user office activity (small text edits, reading, low-frequency saves).

        Args:
            steps: Number of user actions to simulate.
            delaySeconds: Delay between actions (simulates human interaction).
            callback: Optional progress callback (currentStep, totalSteps, actionDescription).

        Returns:
            DemoReport summarizing normal activity.
        """
        startTime = time.time()
        sandbox = self.ensureSandbox()

        # Ensure we have at least a few files to work with
        existingFiles = [p for p in sandbox.iterdir() if p.is_file() and p.name != MARKER_FILE]
        if not existingFiles:
            self.generateBenignFiles(count=10)
            existingFiles = [p for p in sandbox.iterdir() if p.is_file() and p.name != MARKER_FILE]

        modified = 0
        created = 0
        details: List[str] = []

        for step in range(steps):
            targetFile = random.choice(existingFiles)
            actionType = step % 3

            if actionType == 0:
                # Append a line of normal text
                with open(targetFile, "a", encoding="utf-8", errors="ignore") as f:
                    f.write(f"\n[User Edit] Appended note entry at {time.strftime('%H:%M:%S')}\n")
                modified += 1
                desc = f"Edited: {targetFile.name} (appended user note)"
            elif actionType == 1:
                # Touch / rewrite slightly
                content = targetFile.read_text(encoding="utf-8", errors="ignore")
                targetFile.write_text(content + f" // revision {step+1}", encoding="utf-8")
                modified += 1
                desc = f"Saved: {targetFile.name} (document updated)"
            else:
                # Create a small scratchpad file
                scratchName = f"scratch_memo_{step+1:02d}.txt"
                scratchPath = sandbox / scratchName
                scratchPath.write_text(f"Temporary work scratchpad {step+1}\nTask status: In progress\n", encoding="utf-8")
                existingFiles.append(scratchPath)
                created += 1
                desc = f"Created memo: {scratchName}"

            details.append(desc)
            if callback:
                callback(step + 1, steps, desc)

            time.sleep(delaySeconds)

        duration = time.time() - startTime
        logger.info(f"DemoEngine simulated {steps} normal user steps in {duration:.2f}s")
        return DemoReport(
            action=DemoActionType.SIMULATE_NORMAL,
            targetDirectory=sandbox,
            filesCreated=created,
            filesModified=modified,
            durationSeconds=duration,
            details=details,
            success=True,
        )

    def simulateRansomwareAttack(
        self,
        fileCount: int = 25,
        callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> DemoReport:
        """
        Simulate safe, sandboxed ransomware behavioral attack (mass rapid renames, high-entropy write bursts).

        All operations are STRICTLY contained within sandboxPath and operate only on disposable sample files.

        Args:
            fileCount: Number of files to target in the simulation.
            callback: Optional progress callback (currentCount, totalCount, actionDescription).

        Returns:
            DemoReport summarizing simulated attack actions.
        """
        startTime = time.time()
        sandbox = self.ensureSandbox()

        # Find existing benign files or generate them
        existingFiles = [
            p for p in sandbox.iterdir()
            if p.is_file() and p.name != MARKER_FILE and not any(p.name.endswith(ext) for ext in RANSOMWARE_EXTENSIONS)
        ]

        if len(existingFiles) < fileCount:
            self.generateBenignFiles(count=max(fileCount, 25))
            existingFiles = [
                p for p in sandbox.iterdir()
                if p.is_file() and p.name != MARKER_FILE and not any(p.name.endswith(ext) for ext in RANSOMWARE_EXTENSIONS)
            ]

        targets = existingFiles[:fileCount]
        modified = 0
        renamed = 0
        created = 0
        details: List[str] = []

        # 1. Rapid High-Entropy Overwrite & Mass Rename Loop (characteristic of ransomware)
        for i, targetFile in enumerate(targets):
            # Write high-entropy random bytes (simulating encryption payload)
            highEntropyPayload = secrets.token_bytes(2048)
            try:
                targetFile.write_bytes(highEntropyPayload)
                modified += 1
            except Exception:
                pass

            # Rename to ransomware extension
            ext = random.choice(RANSOMWARE_EXTENSIONS)
            renamedPath = sandbox / f"{targetFile.name}{ext}"
            try:
                os.replace(targetFile, renamedPath)
                renamed += 1
                desc = f"Simulated Encryption & Rename: {targetFile.name} -> {renamedPath.name}"
            except Exception as e:
                desc = f"Rename failed for {targetFile.name}: {e}"

            details.append(desc)
            if callback:
                callback(i + 1, fileCount, desc)

            # Rapid execution (5ms pause) to generate high velocity
            time.sleep(0.005)

        # 2. Drop Simulated Ransom Note (harmless text file)
        ransomNotePath = sandbox / "HOW_TO_RECOVER_FILES_README.txt"
        ransomNoteContent = (
            "====================================================================\n"
            "   [LAB SIMULATION ARTIFACT — HARMLESS TEST DEMO ONLY]\n"
            "====================================================================\n"
            "Your files were simulated as locked by the behavioral test engine.\n"
            "This confirms the real-time detection pipeline caught rapid file\n"
            "transformations and mass extension changes.\n"
            f"Simulation Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        )
        ransomNotePath.write_text(ransomNoteContent, encoding="utf-8")
        created += 1
        details.append(f"Dropped simulated note: {ransomNotePath.name}")

        duration = time.time() - startTime
        logger.warning(
            f"DemoEngine executed safe ransomware simulation on {renamed} files in {duration:.2f}s in {sandbox}",
            extra={"event": "security_audit", "context": {"status": "simulated_attack", "files_impacted": renamed}},
        )

        return DemoReport(
            action=DemoActionType.SIMULATE_RANSOMWARE,
            targetDirectory=sandbox,
            filesCreated=created,
            filesModified=modified,
            filesRenamed=renamed,
            durationSeconds=duration,
            details=details,
            success=True,
        )

    def cleanSandbox(
        self,
        callback: Optional[Callable[[str], None]] = None,
    ) -> DemoReport:
        """
        Safely clean all generated test files in the sandbox directory.

        Returns:
            DemoReport summarizing deleted files.
        """
        startTime = time.time()
        sandbox = self.ensureSandbox()
        deleted = 0
        details: List[str] = []

        for item in list(sandbox.iterdir()):
            if item.is_file() and item.name != MARKER_FILE:
                try:
                    item.unlink()
                    deleted += 1
                    desc = f"Removed: {item.name}"
                    details.append(desc)
                    if callback:
                        callback(desc)
                except Exception as e:
                    details.append(f"Failed to delete {item.name}: {e}")

        duration = time.time() - startTime
        logger.info(f"DemoEngine cleaned {deleted} files from {sandbox} in {duration:.2f}s")
        return DemoReport(
            action=DemoActionType.CLEAN_SANDBOX,
            targetDirectory=sandbox,
            filesDeleted=deleted,
            durationSeconds=duration,
            details=details,
            success=True,
        )
