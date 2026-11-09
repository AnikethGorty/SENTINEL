import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


TOOL_ID_RE = re.compile(r"^[a-z][a-z0-9_]{2,79}$")
OPERATION_RE = re.compile(r"^[a-z][a-z0-9_]{1,59}$")
IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:+-]{0,350}@sha256:[a-fA-F0-9]{64}$")
PARAM_TYPES = {"string", "integer", "number", "boolean", "array", "object"}


class ParameterDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["string", "integer", "number", "boolean", "array", "object"]
    description: str = Field(default="", max_length=500)
    required: bool = False
    enum: list[Any] | None = None
    minimum: int | float | None = None
    maximum: int | float | None = None
    min_length: int | None = Field(default=None, ge=0, le=100000)
    max_length: int | None = Field(default=None, ge=0, le=100000)
    items: dict[str, Any] | None = None

    @model_validator(mode="after")
    def validate_bounds(self):
        if self.minimum is not None and self.maximum is not None and self.minimum > self.maximum:
            raise ValueError("minimum cannot exceed maximum")
        if self.min_length is not None and self.max_length is not None and self.min_length > self.max_length:
            raise ValueError("min_length cannot exceed max_length")
        if self.enum is not None and len(self.enum) == 0:
            raise ValueError("enum cannot be empty")
        return self


class OperationDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    description: str = Field(min_length=1, max_length=1000)
    parameters: dict[str, ParameterDefinition] = Field(default_factory=dict, max_length=40)


class RuntimeDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["container"]
    image: str = Field(min_length=1, max_length=500)
    entrypoint: list[str] = Field(min_length=1, max_length=16)
    timeout_seconds: int = Field(default=300, ge=1, le=1800)
    memory_mb: int = Field(default=512, ge=64, le=4096)
    cpus: float = Field(default=1.0, gt=0, le=4.0)
    read_only_rootfs: bool = True
    network_access: Literal["scoped_targets_only", "none"] = "scoped_targets_only"

    @field_validator("read_only_rootfs")
    @classmethod
    def require_read_only_rootfs(cls, value: bool):
        if value is not True:
            raise ValueError("read_only_rootfs must be true for user-supplied tools")
        return value

    @field_validator("image")
    @classmethod
    def require_immutable_digest(cls, value: str):
        if not IMAGE_RE.fullmatch(value):
            raise ValueError("Container image must be pinned by immutable @sha256:<64 hex> digest")
        return value

    @field_validator("entrypoint")
    @classmethod
    def validate_entrypoint(cls, value: list[str]):
        if any(not item or len(item) > 300 or "\\x00" in item for item in value):
            raise ValueError("Invalid entrypoint argument")
        return value


class ToolManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manifest_version: Literal["1.0"]
    tool_id: str
    name: str = Field(min_length=1, max_length=200)
    version: str = Field(min_length=1, max_length=40)
    description: str = Field(min_length=1, max_length=2000)
    runtime: RuntimeDefinition
    capabilities: list[str] = Field(min_length=1, max_length=30)
    operations: dict[str, OperationDefinition] = Field(min_length=1, max_length=30)
    output_format: Literal["json"] = "json"
    output_schema_version: str = Field(default="1.0", max_length=20)

    @field_validator("tool_id")
    @classmethod
    def validate_tool_id(cls, value: str):
        if not TOOL_ID_RE.fullmatch(value):
            raise ValueError("tool_id must be lowercase snake_case, 3-80 characters")
        return value

    @field_validator("capabilities")
    @classmethod
    def validate_capabilities(cls, values: list[str]):
        if len(set(values)) != len(values):
            raise ValueError("capabilities must be unique")
        for item in values:
            if not re.fullmatch(r"[a-z][a-z0-9_]{1,79}", item):
                raise ValueError(f"Invalid capability identifier: {item}")
        return values

    @model_validator(mode="after")
    def validate_operations(self):
        for operation in self.operations:
            if not OPERATION_RE.fullmatch(operation):
                raise ValueError(f"Invalid operation identifier: {operation}")
        return self


class IntegrationRegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manifest_yaml: str = Field(min_length=1, max_length=100000)
    created_by: str = Field(default="local-user", min_length=1, max_length=120)


class IntegrationEnableRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled_by: str = Field(default="local-user", min_length=1, max_length=120)
