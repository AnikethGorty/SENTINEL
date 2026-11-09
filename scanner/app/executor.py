from app.registry import TOOL_REGISTRY


class ExecutionError(Exception):
    pass


def execute_job(
    tool: str,
    action: str,
    target: str,
    parameters: dict,
) -> dict:
    capability = TOOL_REGISTRY.get((tool, action))

    if capability is None:
        raise ExecutionError("Unsupported operation")

    try:
        if tool == "nmap":
            result = capability.handler(
                target=target,
                ports=parameters["ports"],
                excluded_ports=parameters.get("excluded_ports", []),
            )
        else:
            result = capability.handler(
                target=target,
                parameters=parameters,
            )

    except Exception as exc:
        raise ExecutionError(
            f"{tool} execution failed: {type(exc).__name__}: {exc}"
        ) from exc

    if not isinstance(result, dict):
        raise ExecutionError("Tool returned an invalid result")

    return result
