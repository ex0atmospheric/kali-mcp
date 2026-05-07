from context import get_executor, get_findings, ctf_mode_warning
from scope import ScopeViolation
from parsers import nmap as nmap_parser
from parsers import enum4linux as enum4linux_parser


def _fmt(raw: str, timed_out: bool, timeout: int, update: str, suggestions: list[str]) -> str:
    out = raw
    if timed_out:
        out = f"[TIMEOUT after {timeout}s — partial output below]\n" + out
    out += f"\n\n[FINDINGS UPDATE]\n{update}"
    if suggestions:
        out += "\n\n[SUGGESTED NEXT STEPS]\n" + "\n".join(suggestions)
    return out


def nmap_scan(target: str, ports: str = "1-1000", flags: str = "") -> str:
    warn = ctf_mode_warning()
    exe = get_executor()
    findings = get_findings()

    try:
        exe.scope.check(target)
    except ScopeViolation as e:
        return f"[SCOPE VIOLATION] {e}"

    args = ["-oX", "-", "-p", ports]
    if flags:
        args.extend(flags.split())
    args.append(target)

    try:
        result = exe.run("nmap", args, target=target)
    except FileNotFoundError as e:
        return str(e)

    parsed = nmap_parser.parse(result.stdout)
    updates = []
    for host, hdata in parsed["hosts"].items():
        updates.append(findings.update_ports(host, hdata["ports"]))
        findings.update_host_meta(host, hdata.get("os"), hdata.get("hostnames", []))

    suggestions = findings.get_suggestions(target)
    update_str = "\n".join(updates) if updates else "No hosts parsed."

    return (warn + "\n" if warn else "") + _fmt(
        result.stdout + (f"\n[STDERR]\n{result.stderr}" if result.stderr else ""),
        result.timed_out, exe.timeout, update_str, suggestions,
    )


def dns_enum(target: str) -> str:
    warn = ctf_mode_warning()
    exe = get_executor()

    try:
        exe.scope.check(target)
    except ScopeViolation as e:
        return f"[SCOPE VIOLATION] {e}"

    output_parts = []
    for record_type in ("A", "MX", "NS", "TXT"):
        try:
            result = exe.run("dig", ["+short", target, record_type])
            if result.stdout.strip():
                output_parts.append(f"=== {record_type} ===\n{result.stdout.strip()}")
        except FileNotFoundError as e:
            return str(e)

    combined = "\n\n".join(output_parts) or "No DNS records found."
    return (warn + "\n" if warn else "") + combined + "\n\n[FINDINGS UPDATE]\nDNS enumeration complete."


def smb_enum(target: str) -> str:
    warn = ctf_mode_warning()
    exe = get_executor()
    findings = get_findings()

    try:
        exe.scope.check(target)
    except ScopeViolation as e:
        return f"[SCOPE VIOLATION] {e}"

    try:
        result = exe.run("enum4linux", ["-a", target], target=target)
    except FileNotFoundError as e:
        return str(e)

    parsed = enum4linux_parser.parse(result.stdout, target)
    if parsed["users"]:
        findings.add_note(f"SMB users on {target}: {', '.join(parsed['users'])}")
    if parsed["shares"]:
        names = [s["name"] for s in parsed["shares"]]
        findings.add_note(f"SMB shares on {target}: {', '.join(names)}")

    suggestions = findings.get_suggestions(target)
    update_str = (
        f"Users: {', '.join(parsed['users']) or 'none'} | "
        f"Shares: {', '.join(s['name'] for s in parsed['shares']) or 'none'}"
    )

    return (warn + "\n" if warn else "") + _fmt(
        result.stdout + (f"\n[STDERR]\n{result.stderr}" if result.stderr else ""),
        result.timed_out, exe.timeout, update_str, suggestions,
    )
