import os
import secrets
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from app.executor import execute_job, ExecutionError
from app.policy import (
    validate_target_ip,
    validate_ports,
    validate_web_url,
)
from app.registry import TOOL_REGISTRY, list_capabilities
from app.authorization import verify_and_consume


app = FastAPI(
    title="SENTINEL Scanner",
    version="0.3.0",
)


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    job_id: str = Field(min_length=1, max_length=128)
    tool: str = Field(min_length=1, max_length=40)
    action: str = Field(min_length=1, max_length=60)
    target: str = Field(min_length=1, max_length=2048)
    parameters: dict[str, Any]


def authenticate(api_key: str | None):
    expected = os.environ.get("SCANNER_API_KEY", "")

    if not expected or not api_key:
        raise HTTPException(status_code=401, detail="Unauthorized")

    if not secrets.compare_digest(api_key, expected):
        raise HTTPException(status_code=401, detail="Unauthorized")


def validate_job(request: ScanRequest):
    capability = TOOL_REGISTRY.get((request.tool, request.action))

    if capability is None:
        raise HTTPException(status_code=400, detail="Unsupported operation")

    parameters = request.parameters

    if request.tool == "nmap":
        allowed_keys = {"ports", "excluded_ports"}

        if set(parameters) - allowed_keys:
            raise HTTPException(status_code=400, detail="Unsupported Nmap parameter")

        try:
            validate_target_ip(request.target)
            validate_ports(
                parameters.get("ports", []),
                parameters.get("excluded_ports", []),
            )
        except ValueError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    elif request.tool in {"httpx", "nikto", "nuclei"}:
        if set(parameters) != {"url"}:
            raise HTTPException(
                status_code=400,
                detail="This operation accepts only the 'url' parameter",
            )

        if request.target != parameters["url"]:
            raise HTTPException(
                status_code=400,
                detail="Target must match the supplied URL",
            )

        try:
            validate_web_url(parameters["url"])
        except ValueError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    return capability


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "sentinel-scanner",
    }


@app.get("/capabilities")
def capabilities(x_scanner_key: str | None = Header(default=None)):
    authenticate(x_scanner_key)

    return {
        "service": "sentinel-scanner",
        "capabilities": list_capabilities(),
    }


@app.post("/jobs")
def submit_job(
    request: ScanRequest,
    x_scanner_key: str | None = Header(default=None),
    x_execution_authorization: str | None = Header(default=None),
):
    authenticate(x_scanner_key)
    validate_job(request)
    verify_and_consume(x_execution_authorization or "", request.model_dump())

    try:
        result = execute_job(
            tool=request.tool,
            action=request.action,
            target=request.target,
            parameters=request.parameters,
        )
    except ExecutionError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    failed = bool(result.get("error")) or result.get("exit_code", 0) != 0

    return {
        "job_id": request.job_id,
        "tool": request.tool,
        "action": request.action,
        "target": request.target,
        "status": "failed" if failed else "completed",
        "result": result,
    }
