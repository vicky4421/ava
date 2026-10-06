from enum import StrEnum


class Node(StrEnum):
    """LangGraph node identifiers."""

    DECOMPILE = "decompile"
    SCAN_SECRET = "scan_secret"
    TRIAGE_SECRET = "triage_secret"
