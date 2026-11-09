import subprocess


def run_nmap(
    target: str,
    ports: list[int],
    excluded_ports: list[int]
) -> dict:

    command = [
        "nmap",
        "-sT",
        "-sV",
        "--version-light",
        "-T3",
        "-p",
        ",".join(map(str, sorted(ports))),
    ]

    if excluded_ports:
        command.extend([
            "--exclude-ports",
            ",".join(map(str, sorted(excluded_ports)))
        ])

    command.extend([
        "-oX",
        "-",
        target
    ])

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
        )

        return {
            "tool": "nmap",
            "target": target,
            "ports_scanned": sorted(ports),
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }

    except subprocess.TimeoutExpired:
        return {
            "tool": "nmap",
            "target": target,
            "ports_scanned": sorted(ports),
            "error": "Scan timed out",
        }

    except OSError as exc:
        return {
            "tool": "nmap",
            "target": target,
            "ports_scanned": sorted(ports),
            "error": f"Nmap execution failed: {str(exc)}",
        }
