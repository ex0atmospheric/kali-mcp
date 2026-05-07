def fmt_output(raw: str, timed_out: bool, timeout: int, update: str, suggestions: list[str]) -> str:
    out = raw
    if timed_out:
        out = f"[TIMEOUT after {timeout}s — partial output below]\n" + out
    out += f"\n\n[FINDINGS UPDATE]\n{update}"
    if suggestions:
        out += "\n\n[SUGGESTED NEXT STEPS]\n" + "\n".join(suggestions)
    return out
