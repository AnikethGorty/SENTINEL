from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from typing import Literal
from urllib.parse import urlparse
import re
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

TargetType = Literal["ip", "cidr", "domain", "hostname", "url"]


class Authorization(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["ACTIVE"] = "ACTIVE"
    authorized_by: str = Field(min_length=1, max_length=200)
    valid_from: datetime
    valid_until: datetime

    @model_validator(mode="after")
    def dates_ordered(self):
        if self.valid_from.tzinfo is None:
            self.valid_from = self.valid_from.replace(tzinfo=timezone.utc)
        if self.valid_until.tzinfo is None:
            self.valid_until = self.valid_until.replace(tzinfo=timezone.utc)
        if self.valid_until <= self.valid_from:
            raise ValueError("authorization.valid_until must be later than valid_from")
        return self


class Target(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: TargetType
    value: str = Field(min_length=1, max_length=2048)
    reason: str | None = Field(default=None, max_length=500)

    @field_validator("value")
    @classmethod
    def normalize_and_validate_value(cls, value: str, info):
        value = value.strip()
        if not value:
            raise ValueError("Target value cannot be empty")
        return value

    @model_validator(mode="after")
    def validate_target_syntax(self):
        value = self.value
        try:
            if self.type == "ip":
                ip_address(value)
            elif self.type == "cidr":
                ip_network(value, strict=False)
            elif self.type in ("domain", "hostname"):
                candidate = value.rstrip(".")
                if len(candidate) > 253 or not re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*", candidate):
                    raise ValueError("must be a valid domain/hostname")
            elif self.type == "url":
                parsed = urlparse(value)
                if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
                    raise ValueError("must be an http:// or https:// URL without embedded credentials")
        except ValueError as exc:
            raise ValueError(f"Invalid {self.type} target '{value}': {exc}") from exc
        return self


class TargetSet(BaseModel):
    model_config = ConfigDict(extra="forbid")
    allowed: list[Target] = Field(min_length=1)
    excluded: list[Target] = Field(default_factory=list)


class Operations(BaseModel):
    model_config = ConfigDict(extra="forbid")
    allowed: list[str] = Field(default_factory=list)
    prohibited: list[str] = Field(default_factory=list)

    @field_validator("allowed", "prohibited")
    @classmethod
    def operation_names_are_explicit(cls, values):
        cleaned = [v.strip() for v in values]
        if any(not re.fullmatch(r"[a-z][a-z0-9_.-]{1,99}", v) for v in cleaned):
            raise ValueError("Operation identifiers must use lowercase names such as nmap.service_discovery")
        if len(cleaned) != len(set(cleaned)):
            raise ValueError("Duplicate operation identifiers are not allowed")
        return cleaned

    @model_validator(mode="after")
    def no_conflicting_operations(self):
        overlap = set(self.allowed) & set(self.prohibited)
        if overlap:
            raise ValueError(f"Operations cannot be both allowed and prohibited: {', '.join(sorted(overlap))}")
        return self


class Constraints(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_scan_rate: int = Field(default=5, ge=1, le=1000)
    max_concurrent_scans: int = Field(default=2, ge=1, le=100)
    testing_hours: str | None = Field(default=None, max_length=100)
    allow_exploitation: bool = False
    allow_destructive_operations: bool = False
    allow_external_callbacks: bool = False
    allow_authentication_testing: bool = False


class ScopeDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scope_version: Literal["1.0"] = "1.0"
    engagement_name: str = Field(min_length=1, max_length=200)
    client_organization: str | None = Field(default=None, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    authorization: Authorization
    targets: TargetSet
    operations: Operations
    constraints: Constraints = Field(default_factory=Constraints)

    @model_validator(mode="after")
    def high_impact_operations_need_explicit_constraints(self):
        allowed = set(self.operations.allowed)
        if "metasploit.exploitation" in allowed and not self.constraints.allow_exploitation:
            raise ValueError("Allowing metasploit.exploitation also requires constraints.allow_exploitation=true")
        if "dos.attack" in allowed and not self.constraints.allow_destructive_operations:
            raise ValueError("Allowing dos.attack also requires constraints.allow_destructive_operations=true")
        if "data.exfiltration" in allowed and not self.constraints.allow_destructive_operations:
            raise ValueError("Allowing data.exfiltration also requires constraints.allow_destructive_operations=true")
        if "authentication.login_test" in allowed and not self.constraints.allow_authentication_testing:
            raise ValueError("Allowing authentication.login_test also requires constraints.allow_authentication_testing=true")
        return self


class ScopeDraftRequest(BaseModel):
    document: dict
    created_by: str = Field(default="human", min_length=1, max_length=120)


class ScopeValidateRequest(BaseModel):
    document: dict


class ScopeActivateRequest(BaseModel):
    revision_id: str
    confirmed: bool
