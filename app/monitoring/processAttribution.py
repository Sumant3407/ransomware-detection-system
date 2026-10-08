"""Process attribution engine using psutil and Win32 process metrics."""

import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from app.domain.schemas import FileEvent

logger = logging.getLogger(__name__)

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore


@dataclass(frozen=True)
class ProcessInfo:
    """Attributes and metrics of an operating system process."""

    processId: int
    name: str
    exe: Optional[str] = None
    parentProcessId: Optional[int] = None
    username: Optional[str] = None
    cpuPercent: float = 0.0
    memoryPercent: float = 0.0
    ioWriteBytes: int = 0
    createTime: float = 0.0


class ProcessAttributor:
    """Thread-safe, low-overhead process attribution engine with short-lived caching."""

    def __init__(self, cacheTtlSeconds: float = 0.5):
        self.cacheTtlSeconds = max(0.1, cacheTtlSeconds)
        self._processCache: dict[int, ProcessInfo] = {}
        self._lastRefreshTime: float = 0.0
        self._openFilesMap: dict[str, int] = {}
        self._currentPid = os.getpid()

    def isAvailable(self) -> bool:
        """Check if psutil is available for process inspection."""
        return psutil is not None

    def refreshProcessTable(self, force: bool = False) -> None:
        """
        Refresh process cache snapshot if TTL expired or forced.
        Catches all NoSuchProcess, AccessDenied, and ZombieProcess exceptions safely.
        """
        now = time.monotonic()
        if not force and (now - self._lastRefreshTime) < self.cacheTtlSeconds:
            return

        if psutil is None:
            return

        newCache: dict[int, ProcessInfo] = {}
        newOpenFiles: dict[str, int] = {}

        try:
            for proc in psutil.process_iter(
                ["pid", "name", "exe", "ppid", "username", "cpu_percent", "memory_percent", "create_time", "io_counters"]
            ):
                try:
                    pinfo = proc.info
                    pid = pinfo.get("pid")
                    if pid is None:
                        continue

                    ioCounters = pinfo.get("io_counters")
                    ioWriteBytes = getattr(ioCounters, "write_bytes", 0) if ioCounters is not None else 0

                    info = ProcessInfo(
                        processId=pid,
                        name=pinfo.get("name") or f"PID-{pid}",
                        exe=pinfo.get("exe"),
                        parentProcessId=pinfo.get("ppid"),
                        username=pinfo.get("username"),
                        cpuPercent=float(pinfo.get("cpu_percent") or 0.0),
                        memoryPercent=float(pinfo.get("memory_percent") or 0.0),
                        ioWriteBytes=ioWriteBytes,
                        createTime=float(pinfo.get("create_time") or 0.0),
                    )
                    newCache[pid] = info

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

        except Exception as error:
            logger.debug(f"Error during process table refresh: {error}")

        self._processCache = newCache
        self._openFilesMap = newOpenFiles
        self._lastRefreshTime = now

    def getProcessInfo(self, processId: int) -> Optional[ProcessInfo]:
        """
        Get process information for a specific PID.
        Returns cached ProcessInfo or queries psutil directly if not cached.
        """
        if processId in self._processCache:
            return self._processCache[processId]

        if psutil is None:
            return None

        try:
            proc = psutil.Process(processId)
            name = proc.name()
            exe = None
            try:
                exe = proc.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            ppid = None
            try:
                ppid = proc.ppid()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            username = None
            try:
                username = proc.username()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            ioWriteBytes = 0
            try:
                ioCounters = proc.io_counters()
                if ioCounters is not None:
                    ioWriteBytes = getattr(ioCounters, "write_bytes", 0)
            except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
                pass

            info = ProcessInfo(
                processId=processId,
                name=name,
                exe=exe,
                parentProcessId=ppid,
                username=username,
                cpuPercent=proc.cpu_percent(),
                memoryPercent=proc.memory_percent(),
                ioWriteBytes=ioWriteBytes,
                createTime=proc.create_time(),
            )
            self._processCache[processId] = info
            return info

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
        except Exception as error:
            logger.debug(f"Error inspecting process {processId}: {error}")
            return None

    def findProcessForPath(self, filePath: str | Path) -> Optional[ProcessInfo]:
        """
        Correlate a modified/accessed file path to the most likely responsible process.
        Uses cached open files or fast known PID lookups.
        """
        canonical = str(Path(filePath).resolve())

        # Check mapped open files first
        if canonical in self._openFilesMap:
            pid = self._openFilesMap[canonical]
            info = self.getProcessInfo(pid)
            if info is not None:
                return info

        return None

    def getTopIoProcesses(self, limit: int = 5) -> list[ProcessInfo]:
        """Get the most active processes by write I/O."""
        self.refreshProcessTable()
        sortedProcesses = sorted(
            self._processCache.values(),
            key=lambda p: p.ioWriteBytes,
            reverse=True,
        )
        return sortedProcesses[:limit]

    def attributeEvent(self, event: FileEvent) -> FileEvent:
        """
        Enrich a FileEvent with process metadata (processId, processName, parentProcessId).
        Non-blocking and safe against missing process information.
        """
        if event.processId is not None and event.processName is not None:
            return event

        targetPid = event.processId
        targetName = event.processName
        targetPpid = event.parentProcessId

        if targetPid is not None:
            info = self.getProcessInfo(targetPid)
            if info is not None:
                targetName = info.name
                targetPpid = info.parentProcessId
        else:
            correlated = self.findProcessForPath(event.path)
            if correlated is not None:
                targetPid = correlated.processId
                targetName = correlated.name
                targetPpid = correlated.parentProcessId

        return FileEvent(
            action=event.action,
            path=event.path,
            occurredAt=event.occurredAt,
            source=event.source,
            oldPath=event.oldPath,
            processId=targetPid,
            pathId=event.pathId,
            monitoredPath=event.monitoredPath,
            processName=targetName,
            parentProcessId=targetPpid,
        )


_globalProcessAttributor: Optional[ProcessAttributor] = None


def getProcessAttributor() -> ProcessAttributor:
    """Get or create singleton ProcessAttributor instance."""
    global _globalProcessAttributor
    if _globalProcessAttributor is None:
        _globalProcessAttributor = ProcessAttributor()
    return _globalProcessAttributor
