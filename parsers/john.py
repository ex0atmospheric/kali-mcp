import re

# John output format: "cracked_password         (username)"
_CRACK_RE = re.compile(r"^(\S+)\s+\((.+?)\)\s*$", re.MULTILINE)


def parse(output: str) -> list[dict]:
    results = []
    for m in _CRACK_RE.finditer(output):
        results.append({
            "cracked": m.group(1),
            "user": m.group(2),
        })
    return results
