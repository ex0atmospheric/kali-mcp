import json
import pytest
from pathlib import Path
from findings import FindingsStore


@pytest.fixture
def store(tmp_path):
    return FindingsStore(persist_path=tmp_path / "findings.json")


def test_update_ports_adds_new_ports(store):
    summary = store.update_ports("10.0.0.1", {
        "80": {"state": "open", "service": "http", "version": "Apache 2.4.49"},
    })
    assert "80" in summary
    assert store.get_all()["hosts"]["10.0.0.1"]["ports"]["80"]["service"] == "http"


def test_update_ports_persists(tmp_path):
    path = tmp_path / "findings.json"
    s = FindingsStore(persist_path=path)
    s.update_ports("10.0.0.1", {"80": {"state": "open", "service": "http", "version": ""}})
    data = json.loads(path.read_text())
    assert "10.0.0.1" in data["hosts"]


def test_update_urls(store):
    summary = store.update_urls("10.0.0.1", [{"host": "10.0.0.1", "path": "/admin", "status": 200}])
    assert "1" in summary
    assert store.get_all()["urls"][0]["path"] == "/admin"


def test_update_credentials(store):
    store.update_credentials([{"host": "10.0.0.1", "service": "ssh", "user": "admin", "pass": "pw"}])
    assert store.get_all()["credentials"][0]["user"] == "admin"


def test_update_hashes(store):
    store.update_hashes([{"user": "root", "hash": "$6$abc", "cracked": "toor"}])
    assert store.get_all()["hashes"][0]["cracked"] == "toor"


def test_add_note(store):
    store.add_note("SMB null session allowed")
    assert "SMB null session allowed" in store.get_all()["notes"]


def test_clear(store):
    store.update_ports("10.0.0.1", {"80": {"state": "open", "service": "http", "version": ""}})
    store.clear()
    assert store.get_all()["hosts"] == {}


def test_suggestions_http_port(store):
    store.update_ports("10.0.0.1", {"80": {"state": "open", "service": "http", "version": ""}})
    suggestions = store.get_suggestions()
    assert any("web_fuzz_dirs" in s or "gobuster" in s.lower() or "ffuf" in s.lower() or "web_scan" in s for s in suggestions)


def test_suggestions_mysql_port(store):
    store.update_ports("10.0.0.1", {"3306": {"state": "open", "service": "mysql", "version": ""}})
    suggestions = store.get_suggestions()
    assert any("hydra" in s.lower() or "brute" in s.lower() or "sql" in s.lower() for s in suggestions)


def test_suggestions_uncracked_hashes(store):
    store.update_hashes([{"user": "root", "hash": "$6$abc", "cracked": None}])
    suggestions = store.get_suggestions()
    assert any("crack_hash" in s or "john" in s.lower() or "hashcat" in s.lower() for s in suggestions)


def test_suggestions_login_page(store):
    store.update_urls("10.0.0.1", [{"host": "10.0.0.1", "path": "/admin/login.php", "status": 200}])
    suggestions = store.get_suggestions()
    assert any("brute_force" in s or "sql_inject" in s for s in suggestions)


def test_loads_existing_findings(tmp_path):
    path = tmp_path / "findings.json"
    path.write_text(json.dumps({
        "hosts": {"10.0.0.1": {"ports": {"22": {"state": "open", "service": "ssh", "version": ""}}, "os": None, "hostnames": []}},
        "urls": [], "credentials": [], "vulnerabilities": [], "hashes": [], "notes": []
    }))
    store = FindingsStore(persist_path=path)
    assert "10.0.0.1" in store.get_all()["hosts"]
