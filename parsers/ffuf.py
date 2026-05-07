import json
from urllib.parse import urlparse


def parse(output: str, host: str) -> list[dict]:
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return []

    urls = []
    for item in data.get("results", []):
        parsed = urlparse(item.get("url", ""))
        urls.append({
            "host": host,
            "path": parsed.path,
            "status": item.get("status", 0),
        })
    return urls
