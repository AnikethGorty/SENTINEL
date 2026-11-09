import ipaddress
import os
from urllib.parse import urlsplit


ALLOWED_TARGETS = {
    item.strip()
    for item in os.getenv(
        "SCANNER_ALLOWED_TARGETS",
        "192.168.56.101",
    ).split(",")
    if item.strip()
}


def validate_target_ip(target: str) -> None:
    try:
        parsed = ipaddress.ip_address(target)
    except ValueError as exc:
        raise ValueError("Target must be a valid IP address") from exc

    if str(parsed) not in ALLOWED_TARGETS:
        raise ValueError("Target is not assigned to this scanner")


def validate_ports(
    ports: list[int],
    excluded_ports: list[int],
) -> None:
    if not isinstance(ports, list) or not ports:
        raise ValueError("At least one port must be specified")

    if len(ports) != len(set(ports)):
        raise ValueError("Duplicate ports")

    if any(
        not isinstance(port, int)
        or isinstance(port, bool)
        or not 1 <= port <= 65535
        for port in ports
    ):
        raise ValueError("Invalid port")

    if not isinstance(excluded_ports, list):
        raise ValueError("Excluded ports must be a list")

    if len(excluded_ports) != len(set(excluded_ports)):
        raise ValueError("Duplicate excluded ports")

    if any(
        not isinstance(port, int)
        or isinstance(port, bool)
        or not 1 <= port <= 65535
        for port in excluded_ports
    ):
        raise ValueError("Invalid excluded port")

    if set(ports).intersection(excluded_ports):
        raise ValueError("A port cannot be both selected and excluded")


def validate_web_url(url: str) -> None:
    if not isinstance(url, str) or len(url) > 2048:
        raise ValueError("Invalid URL")

    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Malformed URL or port") from exc

    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are permitted")

    if not parsed.hostname:
        raise ValueError("URL must contain a hostname")

    if parsed.username or parsed.password:
        raise ValueError("Credentials in URLs are not permitted")

    if parsed.fragment:
        raise ValueError("URL fragments are not permitted")

    try:
        target_ip = str(ipaddress.ip_address(parsed.hostname))
    except ValueError as exc:
        raise ValueError(
            "Web scanner targets must use an authorized IP address"
        ) from exc

    validate_target_ip(target_ip)

    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Invalid target port")
