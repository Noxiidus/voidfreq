"""Tests for central subprocess runner."""

import subprocess
from unittest.mock import patch

import pytest

from voidfreq.core.runner import run_cmd


class TestRunCmd:
    @patch("voidfreq.core.runner.subprocess.run")
    def test_success(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["echo", "hi"], returncode=0, stdout="hi\n", stderr="",
        )
        result = run_cmd(["echo", "hi"])
        assert result.returncode == 0
        assert result.stdout == "hi\n"
        mock_run.assert_called_once()

    @patch("voidfreq.core.runner.subprocess.run")
    def test_nonzero_exit(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["false"], returncode=1, stdout="", stderr="fail",
        )
        result = run_cmd(["false"])
        assert result.returncode == 1

    @patch("voidfreq.core.runner.subprocess.run")
    def test_check_raises(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["false"], returncode=1, stdout="", stderr="error",
        )
        with pytest.raises(subprocess.CalledProcessError):
            run_cmd(["false"], check=True)

    @patch("voidfreq.core.runner.subprocess.run", side_effect=FileNotFoundError)
    def test_command_not_found(self, mock_run):
        with pytest.raises(FileNotFoundError):
            run_cmd(["nonexistent_tool"])

    @patch("voidfreq.core.runner.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="slow", timeout=5))
    def test_timeout(self, mock_run):
        with pytest.raises(subprocess.TimeoutExpired):
            run_cmd(["slow"], timeout=5)

    @patch("voidfreq.core.runner.subprocess.run")
    def test_custom_timeout(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["cmd"], returncode=0, stdout="", stderr="",
        )
        run_cmd(["cmd"], timeout=60)
        call_kwargs = mock_run.call_args
        assert call_kwargs.kwargs.get("timeout") == 60 or call_kwargs[1].get("timeout") == 60

    @patch("voidfreq.core.runner.subprocess.run")
    def test_env_forwarded(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["cmd"], returncode=0, stdout="", stderr="",
        )
        env = {"FOO": "bar"}
        run_cmd(["cmd"], env=env)
        call_kwargs = mock_run.call_args
        assert call_kwargs.kwargs.get("env") == env or call_kwargs[1].get("env") == env
