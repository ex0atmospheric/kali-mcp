import json
from pathlib import Path
from typing import Optional

_CORRELATION_RULES = [
    {
        "services": {"http", "https"},
        "suggestions": [
            "→ HTTP/HTTPS open — run web_fuzz_dirs (gobuster/ffuf) and web_scan (nikto)",
        ],
    },
    {
        "services": {"mysql", "postgresql", "ms-sql-s", "oracle"},
        "suggestions": [
            "→ Database port open — try brute_force, or sql_inject if a web app is found",
        ],
    },
    {
        "services": {"smb", "microsoft-ds", "netbios-ssn"},
        "suggestions": [
            "→ SMB open — run smb_enum (enum4linux)",
        ],
    },
    {
        "services": {"ssh"},
        "suggestions": [
            "→ SSH open — try brute_force with known usernames or common wordlists",
        ],
    },
    {
        "services": {"ftp"},
        "suggestions": [
            "→ FTP open — try anonymous login or brute_force",
        ],
    },
    {
        "services": {"rdp", "ms-wbt-server"},
        "suggestions": [
            "→ RDP open — try brute_force with hydra",
        ],
    },
]

_EMPTY_STORE = lambda: {
    "hosts": {},
    "urls": [],
    "credentials": [],
    "vulnerabilities": [],
    "hashes": [],
    "notes": [],
}


class FindingsStore:
    def __init__(self, persist_path: Path = Path("findings.json")):
        self.persist_path = persist_path
        self._data = _EMPTY_STORE()
        self._load()

    def _load(self) -> None:
        if self.persist_path.exists():
            try:
                self._data = json.loads(self.persist_path.read_text())
            except (json.JSONDecodeError, OSError):
                pass

    def _save(self) -> None:
        try:
            self.persist_path.write_text(json.dumps(self._data, indent=2))
        except OSError:
            pass

    def _ensure_host(self, host: str) -> None:
        if host not in self._data["hosts"]:
            self._data["hosts"][host] = {"ports": {}, "os": None, "hostnames": []}

    def update_ports(self, host: str, ports: dict) -> str:
        self._ensure_host(host)
        new = []
        for port, info in ports.items():
            if str(port) not in self._data["hosts"][host]["ports"]:
                new.append(f"{port}/{info.get('service', '?')}")
            self._data["hosts"][host]["ports"][str(port)] = info
        self._save()
        if new:
            return f"New ports on {host}: {', '.join(new)}"
        return f"Updated ports on {host} (no new ports)"

    def update_host_meta(self, host: str, os: Optional[str], hostnames: list[str]) -> None:
        self._ensure_host(host)
        if os:
            self._data["hosts"][host]["os"] = os
        for hn in hostnames:
            if hn not in self._data["hosts"][host]["hostnames"]:
                self._data["hosts"][host]["hostnames"].append(hn)
        self._save()

    def update_urls(self, host: str, urls: list[dict]) -> str:
        new = [u for u in urls if u not in self._data["urls"]]
        self._data["urls"].extend(new)
        self._save()
        return f"Added {len(new)} URL(s) for {host}"

    def update_credentials(self, creds: list[dict]) -> str:
        new = [c for c in creds if c not in self._data["credentials"]]
        self._data["credentials"].extend(new)
        self._save()
        return f"Found {len(new)} new credential(s)"

    def update_vulnerabilities(self, vulns: list[dict]) -> str:
        new = [v for v in vulns if v not in self._data["vulnerabilities"]]
        self._data["vulnerabilities"].extend(new)
        self._save()
        return f"Found {len(new)} new vulnerability/ies"

    def update_hashes(self, hashes: list[dict]) -> str:
        new = [h for h in hashes if h not in self._data["hashes"]]
        self._data["hashes"].extend(new)
        self._save()
        return f"Recorded {len(new)} hash(es)"

    def add_note(self, text: str) -> None:
        self._data["notes"].append(text)
        self._save()

    def get_all(self) -> dict:
        return self._data

    def clear(self) -> None:
        self._data = _EMPTY_STORE()
        self._save()

    def get_suggestions(self, host: Optional[str] = None) -> list[str]:
        suggestions: list[str] = []
        hosts = [host] if host else list(self._data["hosts"].keys())

        for h in hosts:
            port_data = self._data["hosts"].get(h, {}).get("ports", {})
            services = {info.get("service", "") for info in port_data.values()}

            for rule in _CORRELATION_RULES:
                if services & rule["services"]:
                    suggestions.extend(rule["suggestions"])

        if self._data["credentials"]:
            suggestions.append(
                "→ Credentials in findings — replay against other open services (credential stuffing)"
            )

        uncracked = [h for h in self._data["hashes"] if not h.get("cracked")]
        if uncracked:
            suggestions.append(f"→ {len(uncracked)} uncracked hash(es) — run crack_hash (john/hashcat)")

        login_urls = [
            u for u in self._data["urls"]
            if any(kw in u.get("path", "").lower() for kw in ("login", "admin", "signin"))
        ]
        if login_urls:
            paths = ", ".join(u["path"] for u in login_urls[:3])
            suggestions.append(
                f"→ Login/admin path(s) found ({paths}) — try brute_force or sql_inject"
            )

        return suggestions
