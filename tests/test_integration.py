"""
Integration test: nmap scan → findings update → gobuster suggestion → gobuster → findings update.
No live network calls — all subprocess.run calls are mocked.
"""
import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def reset_context(tmp_path):
    """Give each test its own fresh findings store and open scope."""
    import context
    from scope import Scope
    from findings import FindingsStore
    from executor import Executor

    scope = Scope(targets=[], exclusions=[])
    findings = FindingsStore(persist_path=tmp_path / "findings.json")
    executor = Executor(scope=scope, timeout=10)

    context._scope = scope
    context._findings = findings
    context._executor = executor
    context._ctf_warned = False
    yield


def _mock_run(stdout: str, returncode: int = 0):
    m = MagicMock()
    m.stdout = stdout
    m.stderr = ""
    m.returncode = returncode
    return m


def test_nmap_updates_findings_and_suggests_web_tools():
    nmap_xml = (FIXTURES / "nmap_output.xml").read_text()

    with patch("executor.shutil.which", return_value="/usr/bin/nmap"), \
         patch("executor.subprocess.run", return_value=_mock_run(nmap_xml)):
        from tools.recon import nmap_scan
        output = nmap_scan("10.10.10.5")

    assert "FINDINGS UPDATE" in output
    assert "10.10.10.5" in output
    # HTTP port 80 found → should suggest web tools
    assert "SUGGESTED NEXT STEPS" in output
    assert any(kw in output for kw in ("web_fuzz_dirs", "ffuf", "gobuster", "web_scan", "nikto"))


def test_nmap_then_gobuster_updates_findings():
    nmap_xml = (FIXTURES / "nmap_output.xml").read_text()
    gobuster_txt = (FIXTURES / "gobuster_output.txt").read_text()

    with patch("executor.shutil.which", return_value="/usr/bin/nmap"), \
         patch("executor.subprocess.run", return_value=_mock_run(nmap_xml)):
        from tools.recon import nmap_scan
        nmap_scan("10.10.10.5")

    with patch("executor.shutil.which", return_value="/usr/bin/gobuster"), \
         patch("executor.subprocess.run", return_value=_mock_run(gobuster_txt)):
        from tools.web import web_fuzz_dirs
        output = web_fuzz_dirs("http://10.10.10.5")

    assert "FINDINGS UPDATE" in output

    import context
    urls = context.get_findings().get_all()["urls"]
    paths = [u["path"] for u in urls]
    assert "/admin/login.php" in paths


def test_hydra_hit_suggests_credential_stuffing():
    hydra_txt = (FIXTURES / "hydra_output.txt").read_text()

    with patch("executor.shutil.which", return_value="/usr/bin/hydra"), \
         patch("executor.subprocess.run", return_value=_mock_run(hydra_txt)):
        from tools.creds import brute_force
        with patch("tools.creds.Path.exists", return_value=True):
            output = brute_force("10.10.10.5", "ssh")

    assert "FINDINGS UPDATE" in output

    import context
    creds = context.get_findings().get_all()["credentials"]
    assert any(c["user"] == "admin" for c in creds)


def test_scope_violation_blocks_tool():
    from scope import Scope
    from executor import Executor
    import context

    context._scope = Scope(targets=["10.10.10.0/24"], exclusions=[])
    context._executor = Executor(context._scope, timeout=10)

    from tools.recon import nmap_scan
    output = nmap_scan("192.168.99.5")

    assert "SCOPE VIOLATION" in output


def test_clear_findings_resets_store():
    import context
    context.get_findings().add_note("test note")
    assert context.get_findings().get_all()["notes"]

    from tools.session import clear_findings
    clear_findings()

    assert context.get_findings().get_all()["notes"] == []
