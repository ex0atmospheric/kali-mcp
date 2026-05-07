import re

_LINE_RE = re.compile(r"^(/\S*)\s+\(Status:\s*(\d+)\)", re.MULTILINE)


def parse(output: str, host: str) -> list[dict]:
    urls = []
    for match in _LINE_RE.finditer(output):
        urls.append({
            "host": host,
            "path": match.group(1),
            "status": int(match.group(2)),
        })
    return urls
