from typing import Any, Literal
from pydantic import BaseModel, Field

class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = None
    authorization: dict[str, Any] = Field(default_factory=dict)

class TranscriptCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)

class InstructionExecuteRequest(BaseModel):
    transcript_id: str
    requested_by: Literal["human", "ai", "system"] = "human"
    input_data: dict[str, Any] = Field(default_factory=dict)

class InstructionLoadRequest(BaseModel):
    transcript_id: str
    requested_by: Literal["human", "ai", "system"] = "human"
