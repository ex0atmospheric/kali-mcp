from pathlib import Path
from scope import Scope
from findings import FindingsStore
from executor import Executor

_scope = Scope.from_file(Path("scope.yaml"))
_findings = FindingsStore(Path("findings.json"))
_executor = Executor(_scope)

_ctf_warned = False


def get_scope() -> Scope:
    return _scope


def get_findings() -> FindingsStore:
    return _findings


def get_executor() -> Executor:
    return _executor


def reload_scope(targets: list[str], exclusions: list[str]) -> None:
    global _scope, _executor
    _scope = Scope(targets=targets, exclusions=exclusions)
    _executor = Executor(_scope)


def ctf_mode_warning() -> str:
    global _ctf_warned
    if not _scope.targets and not _ctf_warned:
        _ctf_warned = True
        return (
            "[CTF MODE] No scope.yaml found or targets list is empty. "
            "Scope enforcement is disabled. All targets are permitted."
        )
    return ""
