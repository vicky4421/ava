# Author: Vivek Sawant
# Date: 12-10-2026

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class TriageVerdict(StrEnum):
    VULNERABLE = "VULNERABLE"
    SUSPICIOUS = "SUSPICIOUS"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class SeverityLevel(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class PayloadFile(BaseModel):
    filename: str = Field(
        description="Name of the payload file if required (e.g., 'test_access.html', 'test.xml', 'test.py')"
    )
    content: str = Field(
        description=(
            "CRITICAL: Complete multiline HTML/JS verification code that reads local file."
            "content into DOM for auditing. (e.g.,"
            "<!DOCTYPE html>"
            "<html><body><pre id='out'></pre><script>"
            "fetch(file:///data/data/com.example/shared_prefs/user_prefs.xml).then(r=>r.text()).then(t=>{document.getElementById('out').innerText=t;});"
            "</script></body></html>"
            " MUST NOT be empty or blank."
        )
    )


class ReachabilityStatus(StrEnum):
    DIRECTLY_EXPOSED = (
        "DIRECTLY_EXPOSED"  # Exported component directly handling external input
    )
    INTERNALLY_REACHABLE = "INTERNALLY_REACHABLE"  # Non-exported, reachable via internal IPC or shared logic
    UNREACHABLE = "UNREACHABLE"  # Dead code or guarded by rigorous pre-checks
    INDETERMINATE = "INDETERMINATE"  # Cannot determine solely from local bytecode slice


class LLMInferredDataFlow(BaseModel):
    model_config = {"extra": "ignore"}

    source: str = Field(
        description="Entry point or source of input (e.g., 'Intent.getData()', 'Intent.getStringExtra(\"url\")', 'Hardcoded Constant')."
    )
    sink: str = Field(
        description="Dangerous method or API receiving the data (e.g., 'WebView.loadUrl', 'DexClassLoader.<init>')."
    )
    extracted_extra_keys: list[str] = Field(
        default_factory=list,
        description=(
            "List of exact Intent extra keys or query parameters identified"
            " (e.g., ['url', 'redirect_uri', 'filename'])."
        ),
    )
    sanitizer_present: bool = Field(
        default=False,
        description="True if validation, origin checks, or input sanitization logic exists between source and sink.",
    )
    taint_path_summary: str = Field(
        description="Concise description of how data traverses from the source to the sink."
    )


class VerfifiedReachablePath(BaseModel):
    callers: list[dict[str, Any]]
    reached_exported_entry: bool


class LeadAuditResult(BaseModel):
    model_config = {"extra": "ignore"}

    rule_id: str
    class_name: str
    method_name: str
    verdict: TriageVerdict
    severity: SeverityLevel
    confidence: float = Field(
        ge=0.0, le=1.0, description="Confidence score between 0 and 1"
    )
    cwe_id: str | None = Field(
        default=None,
        description="Standard CWE identifier (e.g., 'CWE-749: Exposed Dangerous Method or Interface')",
    )
    reachability: ReachabilityStatus = Field(
        description="Assessment of whether external untrusted input can reach this sink."
    )
    verified_path: VerfifiedReachablePath | None = None
    data_flow: LLMInferredDataFlow | None = Field(
        default=None,
        description="Taint tracking analysis tracing source-to-sink propagation.",
    )
    evidence_code: str | None = Field(
        default=None,
        description="Exact decompiled Smali or Java code snippet showing the vulnerable API call or sink.",
    )
    analysis: str = Field(
        description="Technical breakdown of data flow or configuration defect"
    )
    remediation: str = Field(
        description="Actionable fix based on security best practices"
    )
