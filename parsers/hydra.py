import re

_CRED_RE = re.compile(
    r"\[(\d+)\]\[(\w+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)"
)


def parse(output: str) -> list[dict]:
    creds = []
    for m in _CRED_RE.finditer(output):
        creds.append({
            "host": m.group(3),
            "service": m.group(2),
            "port": m.group(1),
            "user": m.group(4),
            "pass": m.group(5),
        })
    return creds
