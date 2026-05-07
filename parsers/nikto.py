import re

_CVE_RE = re.compile(r"\+ (CVE-\d+-\d+):\s*(.+)")
_OSVDB_RE = re.compile(r"\+ OSVDB-\d+:\s*(/\S+):\s*(.+)")


def parse(output: str, host: str) -> list[dict]:
    vulns = []
    for m in _CVE_RE.finditer(output):
        vulns.append({
            "host": host,
            "cve": m.group(1),
            "description": m.group(2).strip(),
            "tool": "nikto",
        })
    for m in _OSVDB_RE.finditer(output):
        vulns.append({
            "host": host,
            "path": m.group(1),
            "description": m.group(2).strip(),
            "tool": "nikto",
        })
    return vulns
