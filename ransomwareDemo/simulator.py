from __future__ import annotations

from pathlib import Path
import math
import os
import random
import threading
import time

FILE_COUNT = 300
MAX_SIZE = 150 * 1024 * 1024
MIN_SIZE = 1024
CHUNK_SIZE = 256 * 1024
XOR_BYTE = 0xA5


class DemoSimulator:
    """Safe, reversible ransomware-like workload confined to demo_files."""

    def __init__(self, root: Path | None = None):
        self.root = (root or Path(__file__).resolve().parent / "demo_files").resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self._stop = threading.Event()
        self._running = False
        self._lock = threading.Lock()
        self._original_sizes: dict[Path, int] = {}

    def _safe(self, path: Path) -> bool:
        try:
            return path.resolve().parent == self.root
        except OSError:
            return False

    def _size_for_index(self, i: int) -> int:
        if FILE_COUNT <= 1:
            return MIN_SIZE
        ratio = i / (FILE_COUNT - 1)
        # Logarithmic distribution from ~1 KiB to 150 MiB.
        size = int(math.exp(math.log(MIN_SIZE) + ratio * (math.log(MAX_SIZE) - math.log(MIN_SIZE))))
        return max(MIN_SIZE, min(MAX_SIZE, size))

    def _write_pattern(self, path: Path, size: int, seed: int) -> None:
        rng = random.Random(seed)
        remaining = size
        with path.open("wb") as f:
            while remaining:
                n = min(CHUNK_SIZE, remaining)
                block = bytes(rng.randrange(256) for _ in range(n))
                f.write(block)
                remaining -= n

    def generate(self, progress=None) -> int:
        self.root.mkdir(parents=True, exist_ok=True)
        count = 0
        self._original_sizes.clear()
        for i in range(FILE_COUNT):
            path = self.root / f"demo_file_{i+1:03d}.bin"
            size = self._size_for_index(i)
            if not self._safe(path):
                raise RuntimeError("Safety check rejected demo path")
            self._write_pattern(path, size, 1000 + i)
            self._original_sizes[path] = size
            count += 1
            if progress:
                progress(count, FILE_COUNT, path.name, size)
        return count

    def _transform(self, path: Path) -> None:
        if not self._safe(path):
            return
        with path.open("r+b") as f:
            while True:
                data = f.read(CHUNK_SIZE)
                if not data:
                    break
                f.seek(-len(data), os.SEEK_CUR)
                f.write(bytes(b ^ XOR_BYTE for b in data))

    def simulate(self, progress=None, delay=0.01) -> None:
        with self._lock:
            self._stop.clear()
            self._running = True
        try:
            files = sorted(self.root.glob("demo_file_*.bin"))
            for i, path in enumerate(files, 1):
                if self._stop.is_set():
                    break
                if self._safe(path):
                    self._transform(path)
                    if progress:
                        progress(i, len(files), path.name)
                if delay:
                    time.sleep(delay)
        finally:
            with self._lock:
                self._running = False

    def stop(self) -> None:
        self._stop.set()

    @property
    def running(self) -> bool:
        with self._lock:
            return self._running

    def restore(self, progress=None) -> int:
        restored = 0
        files = sorted(self.root.glob("demo_file_*.bin"))
        for i, path in enumerate(files, 1):
            if not self._safe(path):
                continue
            size = self._original_sizes.get(path)
            if size is None:
                try:
                    size = path.stat().st_size
                except OSError:
                    continue
            self._write_pattern(path, size, 1000 + max(0, int(path.stem.split("_")[-1]) - 1))
            restored += 1
            if progress:
                progress(i, len(files), path.name)
        return restored
