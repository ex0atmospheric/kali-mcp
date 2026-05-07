import pytest
from unittest.mock import patch, MagicMock
from scope import Scope, ScopeViolation
from executor import Executor, ExecutionResult


@pytest.fixture
def open_scope():
    return Scope(targets=[], exclusions=[])  # CTF mode


@pytest.fixture
def narrow_scope():
    return Scope(targets=["10.10.10.0/24"], exclusions=[])


@pytest.fixture
def executor(open_scope):
    return Executor(scope=open_scope, timeout=10)


def test_run_returns_stdout(executor):
    with patch("executor.shutil.which", return_value="/usr/bin/echo"), \
         patch("executor.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="hello\n", stderr="", returncode=0)
        result = executor.run("echo", ["hello"])
    assert result.stdout == "hello\n"
    assert result.returncode == 0
    assert not result.timed_out


def test_run_raises_when_tool_missing(executor):
    with patch("executor.shutil.which", return_value=None):
        with pytest.raises(FileNotFoundError, match="not found in PATH"):
            executor.run("nonexistent_tool", [])


def test_run_blocks_out_of_scope_target(narrow_scope):
    exe = Executor(scope=narrow_scope, timeout=10)
    with pytest.raises(ScopeViolation, match="not in scope"):
        exe.run("nmap", ["-sV", "192.168.99.1"], target="192.168.99.1")


def test_run_passes_in_scope_target(narrow_scope):
    exe = Executor(scope=narrow_scope, timeout=10)
    with patch("executor.shutil.which", return_value="/usr/bin/nmap"), \
         patch("executor.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="scan done", stderr="", returncode=0)
        result = exe.run("nmap", ["-sV", "10.10.10.5"], target="10.10.10.5")
    assert result.stdout == "scan done"


def test_run_detects_timeout(executor):
    import subprocess
    with patch("executor.shutil.which", return_value="/usr/bin/nmap"), \
         patch("executor.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="nmap", timeout=10, output=b"partial", stderr=b"")):
        result = executor.run("nmap", ["-sV", "10.0.0.1"])
    assert result.timed_out


def test_extract_targets_finds_ips(executor):
    targets = executor._extract_targets_from_args(["-u", "http://10.10.10.5/page"])
    assert "10.10.10.5" in targets


def test_run_command_blocks_embedded_out_of_scope_ip(narrow_scope):
    exe = Executor(scope=narrow_scope, timeout=10)
    with patch("executor.shutil.which", return_value="/usr/bin/curl"):
        with pytest.raises(ScopeViolation):
            exe.run("curl", ["http://192.168.99.5/admin"])
