"""Privacy-preserving identifiers for local paths."""

import hashlib
import hmac
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def getPathIdentifier(path: str, keyPath: Path) -> str:
    try:
        keyPath.parent.mkdir(parents=True, exist_ok=True)
        if not keyPath.is_file():
            keyPath.write_bytes(hashlib.sha256(Path.cwd().as_posix().encode("utf-8")).digest())
            logger.debug(f"Generated new path privacy key at {keyPath}")
        key = keyPath.read_bytes()
        return hmac.new(key, path.encode("utf-8"), hashlib.sha256).hexdigest()
    except Exception as error:
        logger.error(f"Error computing path identifier: {error}")
        raise