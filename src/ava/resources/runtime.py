# Author: Vivek Sawant
# Date: 14-10-2026

from typing import Any

# In-memory store for non-serializable runtime objects
_ANALYZE_CACHE: dict[str, Any] = {}


def set_analysis_context(key: str, dx: Any) -> None:
    _ANALYZE_CACHE[key] = dx


def get_analysis_context(key: str) -> Any | None:
    return _ANALYZE_CACHE.get(key)


def clear_analysis_context(key: str | None = None) -> None:
    if key:
        _ANALYZE_CACHE.pop(key, None)
    else:
        _ANALYZE_CACHE.clear()
