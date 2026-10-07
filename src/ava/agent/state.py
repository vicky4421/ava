from typing import Any, TypedDict

from langgraph.graph import MessagesState


class SecretOccurrence(TypedDict):
    file: str
    line: int


class SecretCandidate(TypedDict):
    type: str
    candidate: str
    entropy: float
    occurrences: list[SecretOccurrence]
    context_snippet: str


class AgentState(MessagesState):
    target_apk: str | None
    decompiled_path: str | None

    # secret scanning
    secret_candidates: list[SecretCandidate]
    verified_secrets: list[dict[str, Any]]

    # manifest analysis
    manifest_analysis: dict
