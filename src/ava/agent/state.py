from typing import Any, NotRequired, TypedDict

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
    target_apk: NotRequired[str | None]
    decompiled_path: NotRequired[str | None]
    secret_candidates: NotRequired[list[SecretCandidate]]
    verified_secrets: list[dict[str, Any]]
