# Author: Vivek Sawant
# Date: 12-10-2026

from enum import StrEnum

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
    payload_file: PayloadFile | None = Field(
        default=None,
        description="Structured payload file artifact required to execute the exploit.",
    )
    poc_commands: list[str] | None = Field(
        default=None,
        description="List of clean, single-line adb or shell commands to execute        sequentially (e.g., ['adb push exploit.html /sdcard/', 'adb shell am start ...'])",
    )

    @property
    def poc_exploitation(self) -> str | None:
        """Backward-compatible helper property that formats payload and commands cleanly for UI/CLI rendering."""

        if not self.poc_commands and not self.payload_file:
            return None

        steps = []
        step_num = 1

        if (
            self.payload_file
            and self.payload_file.filename
            and self.payload_file.content
            and self.payload_file.content.strip()
        ):
            steps.append(
                f"{step_num}. Create payload file `{self.payload_file.filename}`:\n"
                f"cat << 'EOF' > {self.payload_file.filename}\n"
                f"{self.payload_file.content.strip()}\n"
                f"EOF"
            )
            step_num += 1

        if self.poc_commands:
            for cmd in self.poc_commands:
                steps.append(f"{step_num}. Run command:\n{cmd}")
                step_num += 1

        return "\n\n".join(steps)
