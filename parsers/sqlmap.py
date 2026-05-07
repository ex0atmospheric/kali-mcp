import re

_INJECTABLE_RE = re.compile(r"Parameter '(\w+)' appears to be '(.+?)' injectable")
_DBMS_RE = re.compile(r"back-end DBMS is (\w+)")


def parse(output: str, host: str) -> list[dict]:
    findings = []
    for m in _INJECTABLE_RE.finditer(output):
        findings.append({
            "host": host,
            "type": "sqli",
            "parameter": m.group(1),
            "technique": m.group(2),
            "tool": "sqlmap",
        })
    m = _DBMS_RE.search(output)
    if m:
        findings.append({
            "host": host,
            "type": "dbms-detected",
            "dbms": m.group(1),
            "tool": "sqlmap",
        })
    return findings
