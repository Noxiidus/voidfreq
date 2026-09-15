"""Central subprocess runner — unified logging, timeout, and error handling."""

from __future__ import annotations

import subprocess
from typing import Any

from .logger import get_logger

log = get_logger("runner")


def run_cmd(
    cmd: list[str],
    *,
    timeout: int | None = 120,
    check: bool = False,
    capture: bool = True,
    text: bool = True,
    env: dict[str, str] | None = None,
    **kwargs: Any,
) -> subprocess.CompletedProcess[str]:
    cmd_str = " ".join(cmd)
    log.debug("Running: %s", cmd_str)

    try:
        result = subprocess.run(
            cmd,
            capture_output=capture,
            text=text,
            timeout=timeout,
            env=env,
            **kwargs,
        )
    except FileNotFoundError:
        log.error("Command not found: %s", cmd[0])
        raise
    except subprocess.TimeoutExpired:
        log.error("Command timed out after %ds: %s", timeout, cmd_str)
        raise

    if result.returncode != 0:
        log.warning(
            "Command exited %d: %s | stderr: %s",
            result.returncode,
            cmd_str,
            (result.stderr or "")[:500],
        )
    else:
        log.debug("Command OK (rc=0): %s", cmd_str)

    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode, cmd, result.stdout, result.stderr,
        )

    return result
