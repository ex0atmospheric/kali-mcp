import ipaddress
import socket
from pathlib import Path
import yaml


class ScopeViolation(Exception):
    pass


class Scope:
    def __init__(self, targets: list[str], exclusions: list[str]):
        self.targets = targets
        self.exclusions = exclusions
        self._networks: list = []
        self._hostnames: list[str] = []
        self._excluded_ips: set = set()

        for t in targets:
            try:
                self._networks.append(ipaddress.ip_network(t, strict=False))
            except ValueError:
                self._hostnames.append(t)

        for e in exclusions:
            try:
                self._excluded_ips.add(ipaddress.ip_address(e))
            except ValueError:
                pass

    def check(self, target: str) -> None:
        if not self.targets:
            return  # CTF mode

        ip = self._resolve(target)

        if ip and ip in self._excluded_ips:
            raise ScopeViolation(f"{target} is excluded from scope.")

        if target in self._hostnames:
            return

        if ip:
            for net in self._networks:
                if ip in net:
                    return

        scope_str = ", ".join(self.targets)
        raise ScopeViolation(
            f"{target} is not in scope. Current scope: {scope_str}"
        )

    def _resolve(self, target: str):
        try:
            return ipaddress.ip_address(target)
        except ValueError:
            pass
        try:
            return ipaddress.ip_address(socket.gethostbyname(target))
        except (socket.gaierror, ValueError):
            return None

    @classmethod
    def from_file(cls, path: Path) -> "Scope":
        if not path.exists():
            return cls(targets=[], exclusions=[])
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        return cls(
            targets=[str(t) for t in data.get("targets", [])],
            exclusions=[str(e) for e in data.get("exclude", [])],
        )
