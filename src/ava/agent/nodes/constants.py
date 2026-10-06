from enum import StrEnum


class Node(StrEnum):
    """LangGraph node identifiers."""

    DECOMPILE = "decompile"
    SCAN_SECRETS = "scan_secrets"
    TRIAGE_SECRETS = "triage_secrets"
