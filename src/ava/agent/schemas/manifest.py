# Author: Vivek Sawant
# Date: 07-10-2026

from pydantic import BaseModel, Field


class ComponentEntryPoint(BaseModel):
    name: str
    component_type: str  # activity, receiver, service, provider
    exported: bool
    permission: str | None = None
    intent_filters: list[str] = Field(default_factory=list)


class ManifestAnalysisResult(BaseModel):
    package_name: str
    target_sdk: int | None = None
    debuggable: bool = False
    allow_backup: bool = True
    permissions: list[str] = []
    entry_points: list[ComponentEntryPoint] = Field(default_factory=list)
