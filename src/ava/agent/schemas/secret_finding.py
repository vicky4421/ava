# Author: Vivek Sawant
# Date: 06-10-2026

from typing import Literal

from pydantic import BaseModel, Field


class SecretFindingSchema(BaseModel):
    candidate: str = Field(description="The detected secret string/token")
    secret_type: str = Field(
        description="Type of credential (e.g., Google API Key, AWS Key)"
    )
    is_valid_secret: bool = Field(
        description="True if an active/real credential, False if placeholder/test/dummy"
    )
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    confidence: Literal["HIGH", "MEDIUM", "LOW"]
    risk_summary: str = Field(
        description="Concise sentence explaining potential impact or why it is a false positive"
    )


class SecretAnalysisResponseSchema(BaseModel):
    findings: list[SecretFindingSchema]
