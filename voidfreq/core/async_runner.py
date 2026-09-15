"""Async subprocess runner — concurrent operations via asyncio."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

from .logger import get_logger

log = get_logger("async_runner")


@dataclass
class AsyncResult:
    command: list[str]
    returncode: int = -1
    stdout: str = ""
    stderr: str = ""
    duration: float = 0.0
    timed_out: bool = False


async def run_async(
    cmd: list[str],
    timeout: int = 120,
    env: dict | None = None,
) -> AsyncResult:
    start = time.monotonic()
    log.debug("async exec: %s", " ".join(cmd))

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=timeout,
        )
        duration = time.monotonic() - start

        result = AsyncResult(
            command=cmd,
            returncode=proc.returncode or 0,
            stdout=stdout_bytes.decode("utf-8", errors="replace"),
            stderr=stderr_bytes.decode("utf-8", errors="replace"),
            duration=duration,
        )
        log.debug("async done: %s (rc=%d, %.1fs)", cmd[0], result.returncode, duration)
        return result

    except TimeoutError:
        proc.kill()
        await proc.wait()
        duration = time.monotonic() - start
        log.warning("async timeout: %s after %ds", cmd[0], timeout)
        return AsyncResult(
            command=cmd,
            returncode=-1,
            duration=duration,
            timed_out=True,
        )
    except FileNotFoundError:
        log.error("async: command not found: %s", cmd[0])
        return AsyncResult(command=cmd, returncode=-1, stderr=f"{cmd[0]}: not found")


async def run_parallel(
    commands: list[list[str]],
    timeout: int = 120,
    max_concurrent: int = 4,
) -> list[AsyncResult]:
    semaphore = asyncio.Semaphore(max_concurrent)

    async def _limited(cmd: list[str]) -> AsyncResult:
        async with semaphore:
            return await run_async(cmd, timeout=timeout)

    tasks = [_limited(cmd) for cmd in commands]
    return await asyncio.gather(*tasks)


async def parallel_channel_scan(
    interface: str,
    channels: list[int],
    duration: int = 5,
) -> list[AsyncResult]:
    commands = [
        ["sudo", "airodump-ng", "--channel", str(ch),
         "--output-format", "csv", "-w", f"/tmp/vf_ch{ch}",
         interface]
        for ch in channels
    ]
    return await run_parallel(commands, timeout=duration + 10, max_concurrent=len(channels))


def lazy_import(module_name: str):
    import importlib
    return importlib.import_module(module_name)
