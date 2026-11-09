import json
import shutil
import subprocess


def run_httpx(target: str, parameters: dict) -> dict:
    url = parameters["url"]

    if not shutil.which("httpx"):
        return {"tool": "httpx", "target": url, "error": "HTTPX binary not installed"}

    command = [
        "httpx",
        "-u", url,
        "-json",
        "-title",
        "-status-code",
        "-tech-detect",
        "-web-server",
        "-tls-grab",
        "-timeout", "10",
        "-retries", "1",
        "-no-color",
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

        records = []

        for line in result.stdout.splitlines():
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        return {
            "tool": "httpx",
            "target": url,
            "exit_code": result.returncode,
            "records": records,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }

    except subprocess.TimeoutExpired:
        return {"tool": "httpx", "target": url, "error": "HTTPX timed out"}

    except OSError as exc:
        return {
            "tool": "httpx",
            "target": url,
            "error": f"HTTPX execution failed: {exc}",
        }
