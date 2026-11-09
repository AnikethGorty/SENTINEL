from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field

class ProposalCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    origin: Literal["HUMAN", "AI", "INSTRUCTION", "SYSTEM"] = "HUMAN"
    created_by: str = Field(min_length=1, max_length=120)
    tool: str = Field(min_length=1, max_length=40)
    action: str = Field(min_length=1, max_length=60)
    target: str = Field(min_length=1, max_length=2048)
    parameters: dict[str, Any] = Field(default_factory=dict)
    reason: str = Field(min_length=1, max_length=5000)
    priority: Literal["critical", "high", "medium", "low"] = "medium"

class ProposalRevision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    edited_by: str = Field(min_length=1, max_length=120)
    tool: str = Field(min_length=1, max_length=40)
    action: str = Field(min_length=1, max_length=60)
    target: str = Field(min_length=1, max_length=2048)
    parameters: dict[str, Any] = Field(default_factory=dict)
    reason: str = Field(min_length=1, max_length=5000)
    priority: Literal["critical", "high", "medium", "low"] = "medium"

class ProposalDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reviewed_by: str = Field(min_length=1, max_length=120)
    decision: Literal["APPROVED", "REJECTED"]
    comment: str | None = Field(default=None, max_length=5000)
