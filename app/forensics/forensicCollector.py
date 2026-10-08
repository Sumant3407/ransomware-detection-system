"""Forensic data capture and analysis engine for ransomware threat investigations."""

import hashlib
import json
import logging
import os
import sqlite3
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

import psutil

from app.detection.riskEngine import RiskDecision
from app.logging.logger import logSecurityEvent

logger = logging.getLogger(__name__)


@dataclass
class ProcessInfo:
    """Detailed forensic profile of an executing process."""

    pid: int
    name: str
    exePath: Optional[str] = None
    commandLine: Optional[str] = None
    parentPid: Optional[int] = None
    parentName: Optional[str] = None
    username: Optional[str] = None
    cpuPercent: float = 0.0
    memoryRssMb: float = 0.0
    openHandles: int = 0
    createTime: Optional[str] = None

    def toDict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ForensicSnapshot:
    """Comprehensive point-in-time forensic evidence bundle associated with a threat detection."""

    capturedAt: str
    riskScore: float
    classification: str
    snapshotId: Optional[int] = None
    detectionId: Optional[int] = None
    sessionId: Optional[int] = None
    processId: Optional[int] = None
    processName: Optional[str] = None
    parentProcessId: Optional[int] = None
    processCommandLine: Optional[str] = None
    processPath: Optional[str] = None
    processUser: Optional[str] = None
    processTree: list[dict[str, Any]] = field(default_factory=list)
    openHandlesCount: int = 0
    cpuPercent: float = 0.0
    memoryRssMb: float = 0.0
    monitoredPath: Optional[str] = None
    targetFileHash: Optional[str] = None
    targetFilePath: Optional[str] = None
    featureSnapshot: dict[str, float] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def toDict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def fromDict(cls, data: dict[str, Any]) -> "ForensicSnapshot":
        return cls(
            snapshotId=data.get("snapshotId"),
            detectionId=data.get("detectionId"),
            sessionId=data.get("sessionId"),
            capturedAt=data["capturedAt"],
            riskScore=float(data.get("riskScore", 0.0)),
            classification=data.get("classification", "unknown"),
            processId=data.get("processId"),
            processName=data.get("processName"),
            parentProcessId=data.get("parentProcessId"),
            processCommandLine=data.get("processCommandLine"),
            processPath=data.get("processPath"),
            processUser=data.get("processUser"),
            processTree=data.get("processTree", []),
            openHandlesCount=int(data.get("openHandlesCount", 0)),
            cpuPercent=float(data.get("cpuPercent", 0.0)),
            memoryRssMb=float(data.get("memoryRssMb", 0.0)),
            monitoredPath=data.get("monitoredPath"),
            targetFileHash=data.get("targetFileHash"),
            targetFilePath=data.get("targetFilePath"),
            featureSnapshot=data.get("featureSnapshot", {}),
            metadata=data.get("metadata", {}),
        )

    def formatConsoleReport(self) -> str:
        """Render forensic report as clean ASCII-safe diagnostic summary."""
        lines = [
            "==================================================",
            "           FORENSIC INVESTIGATION REPORT          ",
            "==================================================",
            f"  Snapshot ID:       {self.snapshotId or 'Unsaved'}",
            f"  Detection ID:      {self.detectionId or 'N/A'}",
            f"  Timestamp:         {self.capturedAt}",
            f"  Classification:    {self.classification.upper()}",
            f"  Risk Score:        {self.riskScore:.4f}",
            "",
            "  Attributed Process Information:",
            f"    Process Name:    {self.processName or 'Unknown'}",
            f"    PID:             {self.processId or 'N/A'}",
            f"    Parent PID:      {self.parentProcessId or 'N/A'}",
            f"    Executable:      {self.processPath or 'N/A'}",
            f"    User Context:    {self.processUser or 'N/A'}",
            f"    Command Line:    {self.processCommandLine or 'N/A'}",
            f"    Memory Usage:    {self.memoryRssMb:.2f} MB (RSS)",
            f"    Open Handles:    {self.openHandlesCount}",
        ]

        if self.processTree:
            lines.extend([
                "",
                "  Process Execution Lineage (Ancestor Tree):",
            ])
            for i, p in enumerate(self.processTree):
                indent = "    " + ("  " * i)
                arrow = "+-> " if i > 0 else "[-] "
                lines.append(f"{indent}{arrow}PID {p.get('pid', 'N/A')}: {p.get('name', 'unknown')} ({p.get('exePath') or 'no exe'})")

        if self.targetFilePath or self.targetFileHash:
            lines.extend([
                "",
                "  Target File Artifacts:",
                f"    File Path:       {self.targetFilePath or 'N/A'}",
                f"    SHA-256 Hash:    {self.targetFileHash or 'N/A'}",
                f"    Monitored Root:  {self.monitoredPath or 'N/A'}",
            ])

        if self.featureSnapshot:
            lines.extend([
                "",
                "  Key Feature Contributions at Detection:",
            ])
            # Highlight top risk drivers
            for k, v in sorted(self.featureSnapshot.items(), key=lambda item: abs(item[1]), reverse=True)[:8]:
                lines.append(f"    * {k:<28}: {v:.4f}")

        lines.append("==================================================")
        return "\n".join(lines)

    def formatJson(self) -> str:
        return json.dumps(self.toDict(), indent=2)


class ForensicCollector:
    """
    Collects process lineage, memory diagnostics, file hashes, and telemetry
    for high-fidelity forensic investigations.
    """

    def __init__(self):
        self._currentProcess = psutil.Process(os.getpid())

    def captureFileHash(self, filePath: Union[str, Path], maxSizeBytes: int = 100 * 1024 * 1024) -> Optional[str]:
        """Compute SHA-256 hash of a file if present and readable."""
        p = Path(filePath)
        if not p.is_file():
            return None

        try:
            if p.stat().st_size > maxSizeBytes:
                logger.debug(f"File {p} exceeds max hash size limit ({maxSizeBytes} bytes)")
                return None

            hasher = hashlib.sha256()
            with open(p, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as error:
            logger.debug(f"Could not compute hash for {filePath}: {error}")
            return None

    def captureProcessInfo(self, processId: Optional[int]) -> ProcessInfo:
        """Gather detailed metadata on a target PID with resilient error handling."""
        if processId is None or processId <= 0:
            return ProcessInfo(pid=0, name="unknown")

        try:
            proc = psutil.Process(processId)
            name = proc.name()
            exe = None
            cmd = None
            username = None
            ppid = None
            pname = None
            rssMb = 0.0
            cpu = 0.0
            handles = 0
            createTimeStr = None

            try:
                exe = proc.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            try:
                cmdList = proc.cmdline()
                cmd = " ".join(cmdList) if cmdList else None
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            try:
                username = proc.username()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            try:
                ppid = proc.ppid()
                parent = proc.parent()
                if parent:
                    pname = parent.name()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            try:
                mem = proc.memory_info()
                rssMb = round(mem.rss / (1024 * 1024), 2)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            try:
                cpu = round(proc.cpu_percent(interval=None), 2)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            try:
                handles = proc.num_handles() if hasattr(proc, "num_handles") else proc.num_fds()
            except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
                pass

            try:
                createTime = proc.create_time()
                createTimeStr = datetime.fromtimestamp(createTime, timezone.utc).isoformat()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            return ProcessInfo(
                pid=processId,
                name=name,
                exePath=exe,
                commandLine=cmd,
                parentPid=ppid,
                parentName=pname,
                username=username,
                cpuPercent=cpu,
                memoryRssMb=rssMb,
                openHandles=handles,
                createTime=createTimeStr,
            )

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as error:
            logger.debug(f"Process {processId} unavailable for forensic inspection: {error}")
            return ProcessInfo(pid=processId, name=f"pid_{processId}_terminated")
        except Exception as error:
            logger.warning(f"Unexpected error inspecting process {processId}: {error}")
            return ProcessInfo(pid=processId, name="error")

    def captureProcessTree(self, processId: Optional[int], maxDepth: int = 5) -> list[dict[str, Any]]:
        """
        Capture the ancestor process tree from root ancestor down to the target PID.

        Returns:
            List of process dictionaries in ancestor order (top-level parent first).
        """
        if processId is None or processId <= 0:
            return []

        ancestors: list[dict[str, Any]] = []
        currentPid = processId
        visited = set()

        for _ in range(maxDepth):
            if currentPid is None or currentPid in visited:
                break
            visited.add(currentPid)

            try:
                proc = psutil.Process(currentPid)
                info = {
                    "pid": currentPid,
                    "name": proc.name(),
                    "exePath": None,
                    "commandLine": None,
                    "parentPid": None,
                }
                try:
                    info["exePath"] = proc.exe()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                try:
                    cmdList = proc.cmdline()
                    info["commandLine"] = " ".join(cmdList) if cmdList else None
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                try:
                    ppid = proc.ppid()
                    info["parentPid"] = ppid
                    ancestors.append(info)
                    currentPid = ppid if ppid != currentPid else None
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    ancestors.append(info)
                    break

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                break
            except Exception as error:
                logger.debug(f"Error inspecting parent tree for PID {currentPid}: {error}")
                break

        # Reverse so ancestors appear from root down to target process
        ancestors.reverse()
        return ancestors

    def collectSnapshot(
        self,
        decision: RiskDecision,
        processId: Optional[int] = None,
        processName: Optional[str] = None,
        targetFilePath: Optional[str] = None,
        monitoredPath: Optional[str] = None,
        featureValues: Optional[dict[str, float]] = None,
        detectionId: Optional[int] = None,
        sessionId: Optional[int] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> ForensicSnapshot:
        """
        Synthesize all available process, host, and artifact evidence into a ForensicSnapshot.
        """
        nowIso = datetime.now(timezone.utc).isoformat()
        procInfo = self.captureProcessInfo(processId)
        processTree = self.captureProcessTree(processId)
        fileHash = self.captureFileHash(targetFilePath) if targetFilePath else None

        # Resolve effective process name
        effectiveName = processName or procInfo.name

        # Collect overall host memory & connection telemetry
        extraMeta = metadata.copy() if metadata else {}
        try:
            netConns = len(psutil.net_connections(kind="inet"))
            extraMeta["networkConnections"] = netConns
        except Exception:
            pass

        try:
            extraMeta["hostCpuPercent"] = psutil.cpu_percent(interval=None)
            extraMeta["hostMemoryPercent"] = psutil.virtual_memory().percent
        except Exception:
            pass

        return ForensicSnapshot(
            snapshotId=None,
            detectionId=detectionId,
            sessionId=sessionId,
            capturedAt=nowIso,
            riskScore=decision.score,
            classification=decision.classification,
            processId=processId or procInfo.pid,
            processName=effectiveName,
            parentProcessId=procInfo.parentPid,
            processCommandLine=procInfo.commandLine,
            processPath=procInfo.exePath,
            processUser=procInfo.username,
            processTree=processTree,
            openHandlesCount=procInfo.openHandles,
            cpuPercent=procInfo.cpuPercent,
            memoryRssMb=procInfo.memoryRssMb,
            monitoredPath=monitoredPath,
            targetFileHash=fileHash,
            targetFilePath=targetFilePath,
            featureSnapshot=featureValues or {},
            metadata=extraMeta,
        )

    def saveSnapshot(self, connection: sqlite3.Connection, snapshot: ForensicSnapshot) -> int:
        """
        Persist forensic snapshot into the database.

        Returns:
            Integer snapshotId.
        """
        cursor = connection.execute(
            """
            INSERT INTO forensicSnapshots (
                detectionId, sessionId, capturedAt, processId, processName, parentProcessId,
                processCommandLine, processPath, processUser, processTreeJson, openHandlesCount,
                cpuPercent, memoryRssMb, monitoredPath, targetFileHash, targetFilePath,
                featureSnapshotJson, riskScore, classification, metadataJson
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                snapshot.detectionId,
                snapshot.sessionId,
                snapshot.capturedAt,
                snapshot.processId,
                snapshot.processName,
                snapshot.parentProcessId,
                snapshot.processCommandLine,
                snapshot.processPath,
                snapshot.processUser,
                json.dumps(snapshot.processTree),
                snapshot.openHandlesCount,
                snapshot.cpuPercent,
                snapshot.memoryRssMb,
                snapshot.monitoredPath,
                snapshot.targetFileHash,
                snapshot.targetFilePath,
                json.dumps(snapshot.featureSnapshot),
                snapshot.riskScore,
                snapshot.classification,
                json.dumps(snapshot.metadata),
            ),
        )
        snapshotId = cursor.lastrowid
        snapshot.snapshotId = snapshotId

        logSecurityEvent(
            logger,
            "forensic_snapshot_recorded",
            snapshot.processPath or snapshot.processName or "unknown_process",
            "success",
            {
                "snapshotId": snapshotId,
                "detectionId": snapshot.detectionId,
                "processId": snapshot.processId,
                "riskScore": snapshot.riskScore,
                "classification": snapshot.classification,
                "treeDepth": len(snapshot.processTree),
            },
        )
        return snapshotId

    def getSnapshotByDetectionId(
        self,
        connection: sqlite3.Connection,
        detectionId: int,
    ) -> Optional[ForensicSnapshot]:
        """Fetch and reconstruct forensic snapshot associated with a detection ID."""
        cursor = connection.execute(
            """
            SELECT snapshotId, detectionId, sessionId, capturedAt, processId, processName,
                   parentProcessId, processCommandLine, processPath, processUser, processTreeJson,
                   openHandlesCount, cpuPercent, memoryRssMb, monitoredPath, targetFileHash,
                   targetFilePath, featureSnapshotJson, riskScore, classification, metadataJson
            FROM forensicSnapshots
            WHERE detectionId = ?
            LIMIT 1
            """,
            (detectionId,),
        )
        row = cursor.fetchone()
        if row is None:
            return None

        return self._rowToSnapshot(row)

    def getSnapshotById(
        self,
        connection: sqlite3.Connection,
        snapshotId: int,
    ) -> Optional[ForensicSnapshot]:
        """Fetch and reconstruct forensic snapshot by its primary key ID."""
        cursor = connection.execute(
            """
            SELECT snapshotId, detectionId, sessionId, capturedAt, processId, processName,
                   parentProcessId, processCommandLine, processPath, processUser, processTreeJson,
                   openHandlesCount, cpuPercent, memoryRssMb, monitoredPath, targetFileHash,
                   targetFilePath, featureSnapshotJson, riskScore, classification, metadataJson
            FROM forensicSnapshots
            WHERE snapshotId = ?
            LIMIT 1
            """,
            (snapshotId,),
        )
        row = cursor.fetchone()
        if row is None:
            return None

        return self._rowToSnapshot(row)

    def getRecentSnapshots(
        self,
        connection: sqlite3.Connection,
        limit: int = 20,
    ) -> list[ForensicSnapshot]:
        """Fetch recent forensic snapshots ordered by most recent."""
        cursor = connection.execute(
            """
            SELECT snapshotId, detectionId, sessionId, capturedAt, processId, processName,
                   parentProcessId, processCommandLine, processPath, processUser, processTreeJson,
                   openHandlesCount, cpuPercent, memoryRssMb, monitoredPath, targetFileHash,
                   targetFilePath, featureSnapshotJson, riskScore, classification, metadataJson
            FROM forensicSnapshots
            ORDER BY snapshotId DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [self._rowToSnapshot(row) for row in cursor.fetchall()]

    def _rowToSnapshot(self, row: tuple) -> ForensicSnapshot:
        return ForensicSnapshot(
            snapshotId=row[0],
            detectionId=row[1],
            sessionId=row[2],
            capturedAt=row[3],
            processId=row[4],
            processName=row[5],
            parentProcessId=row[6],
            processCommandLine=row[7],
            processPath=row[8],
            processUser=row[9],
            processTree=json.loads(row[10]) if row[10] else [],
            openHandlesCount=row[11] or 0,
            cpuPercent=row[12] or 0.0,
            memoryRssMb=row[13] or 0.0,
            monitoredPath=row[14],
            targetFileHash=row[15],
            targetFilePath=row[16],
            featureSnapshot=json.loads(row[17]) if row[17] else {},
            riskScore=row[18] or 0.0,
            classification=row[19] or "unknown",
            metadata=json.loads(row[20]) if row[20] else {},
        )
