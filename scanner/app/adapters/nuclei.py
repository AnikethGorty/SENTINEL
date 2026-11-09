import json
import shutil
import subprocess


def run_nuclei(target: str, parameters: dict) -> dict:
    """
    Execute a restricted Nuclei template scan.

    Only the URL is accepted from the caller.
    Template categories and execution limits are controlled here.
    """

    url = parameters["url"]

    if not shutil.which("nuclei"):
        return {
            "tool": "nuclei",
            "target": url,
            "error": "Nuclei binary not installed",
        }

    command = [
        "nuclei",
        "-u", url,
        "-jsonl",
        "-silent",
        "-severity", "info,low",
        "-tags", "tech,misconfig",
        "-rate-limit", "5",
        "-c", "2",
        "-timeout", "5",
        "-retries", "1",
        "-no-interactsh",
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
        )

        findings = []

        for line in result.stdout.splitlines():
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        return {
            "tool": "nuclei",
            "target": url,
            "exit_code": result.returncode,
            "findings": findings,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }

    except subprocess.TimeoutExpired:
        return {
            "tool": "nuclei",
            "target": url,
            "error": "Nuclei scan timed out",
        }

    except OSError as exc:
        return {
            "tool": "nuclei",
            "target": url,
            "error": f"Nuclei execution failed: {exc}",
        }
