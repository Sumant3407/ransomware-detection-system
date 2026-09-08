"""Windows ReadDirectoryChangesW event source.

The adapter is only constructed on Windows. Polling remains the portable fallback.
"""

import os
import struct
from pathlib import Path

from app.domain.schemas import FileAction, FileEvent, getCurrentTime


class WindowsWatcherUnavailable(RuntimeError):
    """Raised when the native watcher cannot be used."""


class WindowsFileEventSource:
    def __init__(self, directory: Path):
        if os.name != "nt":
            raise WindowsWatcherUnavailable("ReadDirectoryChangesW requires Windows")
        import ctypes
        from ctypes import wintypes

        self.ctypes = ctypes
        self.directory = directory.resolve()
        self.handle = ctypes.windll.kernel32.CreateFileW(
            str(self.directory),
            0x0001,
            0x00000007,
            None,
            3,
            0x02000000 | 0x40000000,
            None,
        )
        if self.handle == wintypes.HANDLE(-1).value:
            raise WindowsWatcherUnavailable("Unable to open monitored directory")

    def collectEvents(self, timeoutMilliseconds: int = 1000) -> list[FileEvent]:
        buffer = self.ctypes.create_string_buffer(64 * 1024)
        bytesReturned = self.ctypes.c_ulong(0)
        notifyFilter = 0x00000001 | 0x00000002 | 0x00000004 | 0x00000010
        success = self.ctypes.windll.kernel32.ReadDirectoryChangesW(
            self.handle,
            buffer,
            len(buffer),
            True,
            notifyFilter,
            self.ctypes.byref(bytesReturned),
            None,
            None,
        )
        if not success:
            raise WindowsWatcherUnavailable("ReadDirectoryChangesW failed")
        return self._parseEvents(buffer.raw[: bytesReturned.value])

    def _parseEvents(self, data: bytes) -> list[FileEvent]:
        events = []
        offset = 0
        actionMap = {
            1: FileAction.created,
            2: FileAction.deleted,
            3: FileAction.modified,
        }
        while offset + 12 <= len(data):
            nextOffset, action, nameLength = struct.unpack_from("<III", data, offset)
            nameStart = offset + 12
            name = data[nameStart : nameStart + nameLength].decode("utf-16-le", errors="replace")
            if action in actionMap:
                events.append(FileEvent(actionMap[action], str(self.directory / name), getCurrentTime(), "windows"))
            elif action in {4, 5}:
                events.append(FileEvent(FileAction.renamed, str(self.directory / name), getCurrentTime(), "windows"))
            if nextOffset == 0:
                break
            offset += nextOffset
        return events

    def close(self) -> None:
        if getattr(self, "handle", None) is not None:
            self.ctypes.windll.kernel32.CloseHandle(self.handle)
            self.handle = None
