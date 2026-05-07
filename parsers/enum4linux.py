import re

_USER_RE = re.compile(r"user:\[(\w+)\]")
_SHARE_RE = re.compile(r"^(\S+)\s+(?:Disk|IPC|Printer)\s*(.*)", re.MULTILINE)


def parse(output: str, host: str) -> dict:
    users = _USER_RE.findall(output)
    shares = [
        {"name": m.group(1), "comment": m.group(2).strip()}
        for m in _SHARE_RE.finditer(output)
    ]
    return {"host": host, "users": users, "shares": shares}
