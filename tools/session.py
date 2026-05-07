import json
from context import get_findings, reload_scope


def get_findings_tool() -> str:
    data = get_findings().get_all()
    return json.dumps(data, indent=2)


def add_note(text: str) -> str:
    get_findings().add_note(text)
    return f"Note added: {text}"


def clear_findings() -> str:
    get_findings().clear()
    return "Findings cleared. Ready for new target."


def set_scope(targets: list[str], exclusions: list[str] = []) -> str:
    reload_scope(targets, exclusions)
    scope_str = ", ".join(targets) or "(none — CTF mode)"
    excl_str = ", ".join(exclusions) or "(none)"
    return f"Scope updated.\nTargets: {scope_str}\nExclusions: {excl_str}"
