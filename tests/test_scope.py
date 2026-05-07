import pytest
from pathlib import Path
from unittest.mock import patch
from scope import Scope, ScopeViolation


def test_ip_in_cidr_passes():
    scope = Scope(targets=["10.10.10.0/24"], exclusions=[])
    scope.check("10.10.10.5")  # should not raise


def test_ip_outside_cidr_raises():
    scope = Scope(targets=["10.10.10.0/24"], exclusions=[])
    with pytest.raises(ScopeViolation, match="not in scope"):
        scope.check("10.10.11.5")


def test_excluded_ip_raises():
    scope = Scope(targets=["10.10.10.0/24"], exclusions=["10.10.10.1"])
    with pytest.raises(ScopeViolation, match="excluded"):
        scope.check("10.10.10.1")


def test_hostname_match_passes():
    scope = Scope(targets=["target.htb"], exclusions=[])
    scope.check("target.htb")  # should not raise


def test_hostname_not_in_scope_raises():
    scope = Scope(targets=["target.htb"], exclusions=[])
    with pytest.raises(ScopeViolation, match="not in scope"):
        scope.check("other.htb")


def test_empty_targets_ctf_mode_passes():
    scope = Scope(targets=[], exclusions=[])
    scope.check("10.10.10.5")  # CTF mode: no scope file → no block


def test_hostname_resolved_to_in_scope_ip_passes():
    scope = Scope(targets=["10.10.10.0/24"], exclusions=[])
    with patch("scope.socket.gethostbyname", return_value="10.10.10.5"):
        scope.check("target.htb")  # resolves to in-scope IP


def test_from_file_missing_returns_ctf_mode(tmp_path):
    scope = Scope.from_file(tmp_path / "scope.yaml")
    assert scope.targets == []
    scope.check("1.2.3.4")  # should not raise


def test_from_file_parses_targets(tmp_path):
    f = tmp_path / "scope.yaml"
    f.write_text("targets:\n  - 10.10.10.0/24\nexclude:\n  - 10.10.10.1\n")
    scope = Scope.from_file(f)
    assert "10.10.10.0/24" in scope.targets
    assert "10.10.10.1" in scope.exclusions
