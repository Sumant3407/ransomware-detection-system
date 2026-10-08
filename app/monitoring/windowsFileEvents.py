"""Windows ReadDirectoryChangesW event source with recursive watching and process attribution.

The adapter is only constructed on Windows. Polling remains the portable fallback.
"""

import logging
import os
import struct
from pathlib import Path
from typing import Optional

from app.domain.schemas import FileAction, FileEvent, getCurrentTime
from app.monitoring.processAttribution import getProcessAttributor

logger = logging.getLogger(__name__)


class WindowsWatcherUnavailable(RuntimeError):
    """Raised when the native watcher cannot be used or encounters an unrecoverable failure."""


# Win32 Notification Filter Constants
FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002
FILE_NOTIFY_CHANGE_ATTRIBUTES = 0x00000004
FILE_NOTIFY_CHANGE_SIZE = 0x00000008
FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010
FILE_NOTIFY_CHANGE_SECURITY = 0x00000100

DEFAULT_NOTIFY_FILTER = (
    FILE_NOTIFY_CHANGE_FILE_NAME
    | FILE_NOTIFY_CHANGE_DIR_NAME
    | FILE_NOTIFY_CHANGE_ATTRIBUTES
    | FILE_NOTIFY_CHANGE_SIZE
    | FILE_NOTIFY_CHANGE_LAST_WRITE
    | FILE_NOTIFY_CHANGE_SECURITY
)

# Win32 Action Constants
FILE_ACTION_ADDED = 1
FILE_ACTION_REMOVED = 2
FILE_ACTION_MODIFIED = 3
FILE_ACTION_RENAMED_OLD_NAME = 4
FILE_ACTION_RENAMED_NEW_NAME = 5


# Win32 ctypes types & bindings initialized once at module level
if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    class OVERLAPPED(ctypes.Structure):
        _fields_ = [
            ("Internal", ctypes.c_size_t),
            ("InternalHigh", ctypes.c_size_t),
            ("Offset", wintypes.DWORD),
            ("OffsetHigh", wintypes.DWORD),
            ("hEvent", wintypes.HANDLE),
        ]

    kernel32 = ctypes.windll.kernel32

    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
        wintypes.HANDLE,
    ]

    kernel32.CreateEventW.restype = wintypes.HANDLE
    kernel32.CreateEventW.argtypes = [
        ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR,
    ]

    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    kernel32.ReadDirectoryChangesW.restype = wintypes.BOOL
    kernel32.ReadDirectoryChangesW.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, wintypes.BOOL,
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(OVERLAPPED), ctypes.c_void_p,
    ]

    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]

    kernel32.GetOverlappedResult.restype = wintypes.BOOL
    kernel32.GetOverlappedResult.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(OVERLAPPED),
        ctypes.POINTER(wintypes.DWORD), wintypes.BOOL,
    ]

    kernel32.GetLastError.restype = wintypes.DWORD
    kernel32.GetLastError.argtypes = []

    kernel32.CancelIo.restype = wintypes.BOOL
    kernel32.CancelIo.argtypes = [wintypes.HANDLE]
else:
    ctypes = None  # type: ignore
    wintypes = None  # type: ignore
    OVERLAPPED = None  # type: ignore


class WindowsFileEventSource:
    """
    High-performance Windows ReadDirectoryChangesW event source.
    Supports recursive directory watching, rename pair matching, full filter flags,
    and process attribution.
    """

    def __init__(
        self,
        directory: Path,
        pathId: int | None = None,
        watchSubtree: bool = True,
        notifyFilter: int = DEFAULT_NOTIFY_FILTER,
        enableProcessAttribution: bool = True,
    ):
        if os.name != "nt" or ctypes is None:
            raise WindowsWatcherUnavailable("ReadDirectoryChangesW requires Windows")

        self.ctypes = ctypes
        self.OVERLAPPED = OVERLAPPED
        self.pathId = pathId
        self.watchSubtree = watchSubtree
        self.notifyFilter = notifyFilter
        self.enableProcessAttribution = enableProcessAttribution
        self.processAttributor = getProcessAttributor() if enableProcessAttribution else None

        # Win32 constants
        self._ERROR_IO_PENDING = 997
        self._ERROR_NOTIFY_ENUM_DIR = 1022  # Buffer overflow in kernel
        self._WAIT_OBJECT_0 = 0
        self._WAIT_TIMEOUT = 258

        self.directory = directory.resolve()
        self.handle: Optional[int] = None
        self._pendingOldName: Optional[str] = None

        self._openHandle()

    def _openHandle(self) -> None:
        """Open Win32 directory handle with overlapped I/O and backup semantics."""
        if not self.directory.is_dir():
            raise WindowsWatcherUnavailable(f"Monitored path is not a directory: {self.directory}")

        self.handle = kernel32.CreateFileW(
            str(self.directory),
            0x0001,                   # FILE_LIST_DIRECTORY
            0x00000007,               # FILE_SHARE_READ | WRITE | DELETE
            None,
            3,                        # OPEN_EXISTING
            0x02000000 | 0x40000000,  # FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED
            None,
        )
        if self.handle is None or self.handle == wintypes.HANDLE(-1).value:
            err = kernel32.GetLastError()
            self.handle = None
            raise WindowsWatcherUnavailable(f"Unable to open monitored directory {self.directory} (error {err})")

    def isHealthy(self) -> bool:
        """Check if watcher handle is open and directory still exists."""
        return self.handle is not None and self.directory.is_dir()

    def reconnect(self) -> bool:
        """Attempt to re-open directory handle if invalidated."""
        self.close()
        try:
            self._openHandle()
            logger.info(f"Reconnected Windows watcher handle for {self.directory}")
            return True
        except Exception as error:
            logger.warning(f"Failed to reconnect watcher for {self.directory}: {error}")
            return False

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with guaranteed cleanup."""
        self.close()
        return False

    def __del__(self):
        """Ensure handle is closed on garbage collection."""
        self.close()

    def collectEvents(self, timeoutMilliseconds: int = 1000) -> list[FileEvent]:
        """
        Collect file events from the monitored directory.
        Uses overlapped I/O with wait timeout to allow non-blocking collection.
        Handles buffer overflow and matches rename pairs.
        """
        if self.handle is None:
            if not self.reconnect():
                raise WindowsWatcherUnavailable("Watcher handle is closed or invalid")

        kernel32 = self.ctypes.windll.kernel32
        from ctypes import wintypes

        buffer = self.ctypes.create_string_buffer(64 * 1024)
        bytesReturned = wintypes.DWORD(0)
        overlapped = self.OVERLAPPED()
        overlapped.hEvent = kernel32.CreateEventW(None, True, False, None)

        try:
            success = kernel32.ReadDirectoryChangesW(
                self.handle,
                buffer,
                len(buffer),
                wintypes.BOOL(self.watchSubtree),
                wintypes.DWORD(self.notifyFilter),
                self.ctypes.byref(bytesReturned),
                self.ctypes.byref(overlapped),
                None,
            )
            if not success:
                errorCode = kernel32.GetLastError()
                if errorCode == self._ERROR_NOTIFY_ENUM_DIR:
                    logger.warning(f"Directory change buffer overflow for {self.directory}")
                    return []
                if errorCode != self._ERROR_IO_PENDING:
                    raise WindowsWatcherUnavailable(
                        f"ReadDirectoryChangesW failed (error {errorCode})"
                    )

            waitResult = kernel32.WaitForSingleObject(
                overlapped.hEvent,
                timeoutMilliseconds,
            )
            if waitResult == self._WAIT_TIMEOUT:
                # Cancel pending I/O before returning quiet period
                kernel32.CancelIo(self.handle)
                return []

            if waitResult != self._WAIT_OBJECT_0:
                kernel32.CancelIo(self.handle)
                raise WindowsWatcherUnavailable(
                    f"Directory watch wait failed (result {waitResult})"
                )

            if not kernel32.GetOverlappedResult(
                self.handle,
                self.ctypes.byref(overlapped),
                self.ctypes.byref(bytesReturned),
                False,
            ):
                errorCode = kernel32.GetLastError()
                if errorCode == self._ERROR_NOTIFY_ENUM_DIR:
                    logger.warning(f"Buffer overflow in GetOverlappedResult for {self.directory}")
                    return []
                raise WindowsWatcherUnavailable(
                    f"GetOverlappedResult failed (error {errorCode})"
                )

            rawBytes = buffer.raw[: bytesReturned.value]
            return self._parseEvents(rawBytes)

        finally:
            kernel32.CloseHandle(overlapped.hEvent)

    def _parseEvents(self, data: bytes) -> list[FileEvent]:
        """
        Parse raw Win32 FILE_NOTIFY_INFORMATION structures into enriched FileEvent instances.
        Accurately pairs FILE_ACTION_RENAMED_OLD_NAME with FILE_ACTION_RENAMED_NEW_NAME.
        """
        events: list[FileEvent] = []
        offset = 0

        actionMap = {
            FILE_ACTION_ADDED: FileAction.created,
            FILE_ACTION_REMOVED: FileAction.deleted,
            FILE_ACTION_MODIFIED: FileAction.modified,
        }

        while offset + 12 <= len(data):
            nextOffset, action, nameLength = struct.unpack_from("<III", data, offset)
            nameStart = offset + 12
            name = data[nameStart : nameStart + nameLength].decode("utf-16-le", errors="replace")
            fullPath = str(self.directory / name)
            eventTime = getCurrentTime()

            if action in actionMap:
                event = FileEvent(
                    action=actionMap[action],
                    path=fullPath,
                    occurredAt=eventTime,
                    source="windows",
                    pathId=self.pathId,
                    monitoredPath=str(self.directory),
                )
                if self.processAttributor is not None:
                    event = self.processAttributor.attributeEvent(event)
                events.append(event)

            elif action == FILE_ACTION_RENAMED_OLD_NAME:
                self._pendingOldName = fullPath

            elif action == FILE_ACTION_RENAMED_NEW_NAME:
                oldPath = self._pendingOldName
                self._pendingOldName = None
                event = FileEvent(
                    action=FileAction.renamed,
                    path=fullPath,
                    occurredAt=eventTime,
                    source="windows",
                    oldPath=oldPath,
                    pathId=self.pathId,
                    monitoredPath=str(self.directory),
                )
                if self.processAttributor is not None:
                    event = self.processAttributor.attributeEvent(event)
                events.append(event)

            if nextOffset == 0:
                break
            offset += nextOffset

        return events

    def close(self) -> None:
        """Close open Win32 handle cleanly."""
        if getattr(self, "handle", None) is not None:
            try:
                self.ctypes.windll.kernel32.CloseHandle(self.handle)
            except Exception as error:
                logger.debug(f"Error closing Win32 handle: {error}")
            finally:
                self.handle = None

