from enum import StrEnum


class Node(StrEnum):
    """LangGraph node identifiers."""

    DECOMPILE = "decompile"
    SCAN_SECRETS = "scan_secrets"
    TRIAGE_SECRETS = "triage_secrets"
    ANALYZE_MANIFEST = "analyze_manifest"


class RouteVerdicts(StrEnum):
    """Langgraph route indentifiers"""

    TRIAGE = "triage"
    SKIP_TRIAGE = "skip_triage"
