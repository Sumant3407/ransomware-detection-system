"""Privacy-preserving identifiers for local paths."""

import hashlib
import hmac
from pathlib import Path


def getPathIdentifier(path: str, keyPath: Path) -> str:
    keyPath.parent.mkdir(parents=True, exist_ok=True)
    if not keyPath.is_file():
        keyPath.write_bytes(hashlib.sha256(Path.cwd().as_posix().encode("utf-8")).digest())
    key = keyPath.read_bytes()
    return hmac.new(key, path.encode("utf-8"), hashlib.sha256).hexdigest()