# Author: Vivek Sawant
# Date: 09-10-2026

import hashlib
from pathlib import Path


def get_apk_fingerprint(apk_path: Path) -> str:
    """Generate deterministic thread_id from file SHA-256 for checkpoint caching."""
    hasher = hashlib.sha256()
    with open(apk_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()[:16]
