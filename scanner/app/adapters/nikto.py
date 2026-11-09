import json
import os
import shutil
import subprocess
import tempfile


def run_nikto(target: str, parameters: dict) -> dict:
    url = parameters["url"]

    binary = shutil.which("nikto")

    if not binary:
        return {
            "tool": "nikto",
            "target": url,
            "error": "Nikto binary not installed",
        }

    output_path = None

    try:
        with tempfile.NamedTemporaryFile(
            suffix=".json",
            prefix="sentinel-nikto-",
            delete=False,
        ) as output_file:
            output_path = output_file.name

        command = [
            binary,
            "-host", url,
            "-Format", "json",
            "-output", output_path,
            "-ask", "no",
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
        )

        if result.returncode != 0:
            return {
                "tool": "nikto",
                "target": url,
                "exit_code": result.returncode,
                "error": "Nikto exited with a non-zero status",
                "stderr": result.stderr,
            }

        if not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
            return {
                "tool": "nikto",
                "target": url,
                "exit_code": result.returncode,
                "error": "Nikto produced no JSON report",
                "stderr": result.stderr,
            }

        with open(output_path, "r", encoding="utf-8") as file:
            raw_output = file.read()

        try:
            findings = json.loads(raw_output)
        except json.JSONDecodeError as exc:
            return {
                "tool": "nikto",
                "target": url,
                "exit_code": result.returncode,
                "error": f"Invalid Nikto JSON output: {exc}",
                "raw_output": raw_output,
                "stderr": result.stderr,
            }

        return {
            "tool": "nikto",
            "target": url,
            "exit_code": result.returncode,
            "output_format": "json",
            "findings": findings,
            "stderr": result.stderr,
        }

    except subprocess.TimeoutExpired:
        return {
            "tool": "nikto",
            "target": url,
            "error": "Nikto scan timed out",
        }

    except OSError as exc:
        return {
            "tool": "nikto",
            "target": url,
            "error": f"Nikto execution failed: {exc}",
        }

    finally:
        if output_path and os.path.exists(output_path):
            os.unlink(output_path)
