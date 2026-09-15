"""Tests for async subprocess runner."""

import asyncio

import pytest

from voidfreq.core.async_runner import AsyncResult, lazy_import, run_async, run_parallel


class TestAsyncResult:
    def test_defaults(self):
        r = AsyncResult(command=["echo", "hello"])
        assert r.returncode == -1
        assert r.stdout == ""
        assert r.timed_out is False
        assert r.duration == 0.0


class TestRunAsync:
    def test_successful_command(self):
        async def _test():
            result = await run_async(["echo", "hello"], timeout=10)
            assert result.returncode == 0
            assert "hello" in result.stdout
            assert result.timed_out is False
            assert result.duration > 0

        asyncio.run(_test())

    def test_command_not_found(self):
        async def _test():
            result = await run_async(["nonexistent_command_xyz"], timeout=5)
            assert result.returncode == -1
            assert "not found" in result.stderr

        asyncio.run(_test())

    def test_nonzero_exit(self):
        async def _test():
            result = await run_async(["python", "-c", "import sys; sys.exit(42)"], timeout=10)
            assert result.returncode == 42

        asyncio.run(_test())


class TestRunParallel:
    def test_multiple_commands(self):
        async def _test():
            commands = [
                ["echo", "one"],
                ["echo", "two"],
                ["echo", "three"],
            ]
            results = await run_parallel(commands, timeout=10)
            assert len(results) == 3
            for r in results:
                assert r.returncode == 0

        asyncio.run(_test())

    def test_mixed_success_failure(self):
        async def _test():
            commands = [
                ["echo", "ok"],
                ["python", "-c", "import sys; sys.exit(1)"],
            ]
            results = await run_parallel(commands, timeout=10)
            assert results[0].returncode == 0
            assert results[1].returncode == 1

        asyncio.run(_test())


class TestLazyImport:
    def test_import_json(self):
        mod = lazy_import("json")
        assert hasattr(mod, "dumps")

    def test_import_nonexistent(self):
        with pytest.raises(ModuleNotFoundError):
            lazy_import("nonexistent_module_xyz")
