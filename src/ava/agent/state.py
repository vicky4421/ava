from typing import Any, TypedDict

from langgraph.graph import MessagesState

from ava.agent.schemas.audit import LeadAuditResult


class SecretOccurrence(TypedDict):
    file: str
    line: int


class SecretCandidate(TypedDict):
    type: str
    candidate: str
    entropy: float
    occurrences: list[SecretOccurrence]
    context_snippet: str


class CandidateLead(TypedDict):
    rule_id: str
    category: str
    description: str
    class_name: str
    method_name: str
    file_path: str
    line_number: int
    code_snippet: str
    is_exported: bool
    is_intrinsic: bool
    confidence: str


class AgentState(MessagesState):
    target_apk: str | None
    decompiled_path: str | None

    # secret scanning
    secret_candidates: list[SecretCandidate]
    verified_secrets: list[dict[str, Any]]

    # manifest analysis
    manifest_analysis: dict

    # Vulnerability audit pipeline
    candidate_leads: list[CandidateLead]
    audit_findings: list[LeadAuditResult]
