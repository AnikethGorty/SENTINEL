from dataclasses import dataclass
from typing import Callable

from app.adapters.nmap import run_nmap
from app.adapters.httpx import run_httpx
from app.adapters.nikto import run_nikto
from app.adapters.nuclei import run_nuclei


@dataclass(frozen=True)
class ToolCapability:
    tool: str
    action: str
    description: str
    handler: Callable
    requires_approval: bool


_CAPABILITIES = [
    ToolCapability(
        tool="nmap",
        action="service_discovery",
        description="TCP port scanning and service version detection",
        handler=run_nmap,
        requires_approval=False,
    ),
    ToolCapability(
        tool="httpx",
        action="web_probe",
        description="HTTP probing, status, title, technologies and TLS metadata",
        handler=run_httpx,
        requires_approval=False,
    ),
    ToolCapability(
        tool="nikto",
        action="server_audit",
        description="Web server configuration and known-risk checks",
        handler=run_nikto,
        requires_approval=True,
    ),
    ToolCapability(
        tool="nuclei",
        action="template_scan",
        description="Restricted low-severity technology and misconfiguration templates",
        handler=run_nuclei,
        requires_approval=True,
    ),
]

TOOL_REGISTRY = {
    (capability.tool, capability.action): capability
    for capability in _CAPABILITIES
}


def list_capabilities() -> list[dict]:
    return [
        {
            "tool": capability.tool,
            "action": capability.action,
            "description": capability.description,
            "requires_approval": capability.requires_approval,
        }
        for capability in _CAPABILITIES
    ]
