from pathlib import Path
import pytest

FIXTURES = Path(__file__).parent / "fixtures"


# ── nmap ──────────────────────────────────────────────────────────────────────

from parsers import nmap as nmap_parser


def test_nmap_parse_open_ports():
    xml = (FIXTURES / "nmap_output.xml").read_text()
    result = nmap_parser.parse(xml)
    host = result["hosts"]["10.10.10.5"]
    assert "80" in host["ports"]
    assert "3306" in host["ports"]


def test_nmap_skips_closed_ports():
    xml = (FIXTURES / "nmap_output.xml").read_text()
    result = nmap_parser.parse(xml)
    assert "443" not in result["hosts"]["10.10.10.5"]["ports"]


def test_nmap_parses_service_and_version():
    xml = (FIXTURES / "nmap_output.xml").read_text()
    result = nmap_parser.parse(xml)
    port80 = result["hosts"]["10.10.10.5"]["ports"]["80"]
    assert port80["service"] == "http"
    assert "Apache" in port80["version"]


def test_nmap_parses_os():
    xml = (FIXTURES / "nmap_output.xml").read_text()
    result = nmap_parser.parse(xml)
    assert "Linux" in result["hosts"]["10.10.10.5"]["os"]


def test_nmap_parses_hostname():
    xml = (FIXTURES / "nmap_output.xml").read_text()
    result = nmap_parser.parse(xml)
    assert "target.htb" in result["hosts"]["10.10.10.5"]["hostnames"]


def test_nmap_returns_empty_on_bad_xml():
    result = nmap_parser.parse("not xml at all")
    assert result == {"hosts": {}}


# ── gobuster ──────────────────────────────────────────────────────────────────

from parsers import gobuster as gobuster_parser


def test_gobuster_parses_paths():
    txt = (FIXTURES / "gobuster_output.txt").read_text()
    urls = gobuster_parser.parse(txt, "10.10.10.5")
    paths = [u["path"] for u in urls]
    assert "/admin" in paths
    assert "/admin/login.php" in paths


def test_gobuster_parses_status_codes():
    txt = (FIXTURES / "gobuster_output.txt").read_text()
    urls = gobuster_parser.parse(txt, "10.10.10.5")
    login = next(u for u in urls if u["path"] == "/admin/login.php")
    assert login["status"] == 200


def test_gobuster_sets_host():
    txt = (FIXTURES / "gobuster_output.txt").read_text()
    urls = gobuster_parser.parse(txt, "10.10.10.5")
    assert all(u["host"] == "10.10.10.5" for u in urls)


# ── ffuf ──────────────────────────────────────────────────────────────────────

from parsers import ffuf as ffuf_parser


def test_ffuf_parses_results():
    txt = (FIXTURES / "ffuf_output.json").read_text()
    urls = ffuf_parser.parse(txt, "10.10.10.5")
    paths = [u["path"] for u in urls]
    assert "/admin/" in paths
    assert "/api/" in paths


def test_ffuf_parses_status():
    txt = (FIXTURES / "ffuf_output.json").read_text()
    urls = ffuf_parser.parse(txt, "10.10.10.5")
    admin = next(u for u in urls if u["path"] == "/admin/")
    assert admin["status"] == 200


def test_ffuf_returns_empty_on_bad_json():
    urls = ffuf_parser.parse("not json", "10.10.10.5")
    assert urls == []


# ── hydra ──────────────────────────────────────────────────────────────────────

from parsers import hydra as hydra_parser


def test_hydra_parses_credentials():
    txt = (FIXTURES / "hydra_output.txt").read_text()
    creds = hydra_parser.parse(txt)
    assert len(creds) == 2


def test_hydra_credential_fields():
    txt = (FIXTURES / "hydra_output.txt").read_text()
    creds = hydra_parser.parse(txt)
    admin = next(c for c in creds if c["user"] == "admin")
    assert admin["pass"] == "password123"
    assert admin["host"] == "10.10.10.5"
    assert admin["service"] == "ssh"


def test_hydra_returns_empty_on_no_match():
    creds = hydra_parser.parse("no passwords found")
    assert creds == []


# ── john ──────────────────────────────────────────────────────────────────────

from parsers import john as john_parser


def test_john_parses_cracked():
    txt = (FIXTURES / "john_output.txt").read_text()
    hashes = john_parser.parse(txt)
    assert len(hashes) == 2


def test_john_hash_fields():
    txt = (FIXTURES / "john_output.txt").read_text()
    hashes = john_parser.parse(txt)
    admin = next(h for h in hashes if h["user"] == "admin")
    assert admin["cracked"] == "password123"


def test_john_returns_empty_on_no_match():
    hashes = john_parser.parse("Session completed.\n")
    assert hashes == []


# ── nikto ──────────────────────────────────────────────────────────────────────

from parsers import nikto as nikto_parser


def test_nikto_parses_cve():
    txt = (FIXTURES / "nikto_output.txt").read_text()
    vulns = nikto_parser.parse(txt, "10.10.10.5")
    cves = [v["cve"] for v in vulns if "cve" in v]
    assert "CVE-2021-41773" in cves


def test_nikto_parses_osvdb():
    txt = (FIXTURES / "nikto_output.txt").read_text()
    vulns = nikto_parser.parse(txt, "10.10.10.5")
    osvdb = [v for v in vulns if "path" in v]
    assert any("/admin/" in v["path"] for v in osvdb)


def test_nikto_sets_tool_field():
    txt = (FIXTURES / "nikto_output.txt").read_text()
    vulns = nikto_parser.parse(txt, "10.10.10.5")
    assert all(v["tool"] == "nikto" for v in vulns)


# ── sqlmap ──────────────────────────────────────────────────────────────────────

from parsers import sqlmap as sqlmap_parser


def test_sqlmap_parses_injectable_param():
    txt = (FIXTURES / "sqlmap_output.txt").read_text()
    findings = sqlmap_parser.parse(txt, "10.10.10.5")
    sqli = [f for f in findings if f.get("type") == "sqli"]
    assert any(f["parameter"] == "id" for f in sqli)


def test_sqlmap_parses_dbms():
    txt = (FIXTURES / "sqlmap_output.txt").read_text()
    findings = sqlmap_parser.parse(txt, "10.10.10.5")
    dbms = [f for f in findings if f.get("type") == "dbms-detected"]
    assert dbms[0]["dbms"] == "MySQL"


# ── enum4linux ──────────────────────────────────────────────────────────────────

from parsers import enum4linux as enum4linux_parser


def test_enum4linux_parses_users():
    txt = (FIXTURES / "enum4linux_output.txt").read_text()
    result = enum4linux_parser.parse(txt, "10.10.10.5")
    assert "administrator" in result["users"]
    assert "plague" in result["users"]


def test_enum4linux_parses_shares():
    txt = (FIXTURES / "enum4linux_output.txt").read_text()
    result = enum4linux_parser.parse(txt, "10.10.10.5")
    share_names = [s["name"] for s in result["shares"]]
    assert "backups" in share_names
    assert "ADMIN$" in share_names
