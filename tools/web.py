from context import get_executor, get_findings, ctf_mode_warning
from scope import ScopeViolation
from parsers import gobuster as gobuster_parser
from parsers import ffuf as ffuf_parser
from parsers import nikto as nikto_parser
from parsers import sqlmap as sqlmap_parser
from tools._utils import fmt_output

_SECLISTS = f"{__import__('os').path.expanduser('~')}/.local/share/wordlists"
_DEFAULT_WORDLIST = (
    "/usr/share/wordlists/dirb/common.txt"
    if __import__("os.path", fromlist=["exists"]).exists("/usr/share/wordlists/dirb/common.txt")
    else f"{_SECLISTS}/Discovery/Web-Content/common.txt"
)


def _extract_host(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).hostname or url


def web_fuzz_dirs(
    target_url: str,
    wordlist: str = _DEFAULT_WORDLIST,
    extensions: str = "",
    tool: str = "gobuster",
) -> str:
    warn = ctf_mode_warning()
    exe = get_executor()
    findings = get_findings()
    host = _extract_host(target_url)

    try:
        exe.scope.check(host)
    except ScopeViolation as e:
        return f"[SCOPE VIOLATION] {e}"

    if tool == "ffuf":
        args = ["-u", f"{target_url}/FUZZ", "-w", wordlist, "-o", "-", "-of", "json", "-s"]
        if extensions:
            args.extend(["-e", extensions])
        try:
            result = exe.run("ffuf", args)
        except FileNotFoundError as e:
            return str(e)
        urls = ffuf_parser.parse(result.stdout, host)
    else:
        args = ["dir", "-u", target_url, "-w", wordlist, "-q"]
        if extensions:
            args.extend(["-x", extensions])
        try:
            result = exe.run("gobuster", args)
        except FileNotFoundError as e:
            return str(e)
        urls = gobuster_parser.parse(result.stdout, host)

    update = findings.update_urls(host, urls)
    suggestions = findings.get_suggestions(host)

    return (warn + "\n" if warn else "") + fmt_output(
        result.stdout, result.timed_out, exe.timeout, update, suggestions,
    )


def web_scan(target: str, port: int = 80) -> str:
    warn = ctf_mode_warning()
    exe = get_executor()
    findings = get_findings()
    host = _extract_host(target)

    try:
        exe.scope.check(host)
    except ScopeViolation as e:
        return f"[SCOPE VIOLATION] {e}"

    try:
        result = exe.run("nikto", ["-h", target, "-p", str(port)])
    except FileNotFoundError as e:
        return str(e)

    vulns = nikto_parser.parse(result.stdout, host)
    update = findings.update_vulnerabilities(vulns)
    suggestions = findings.get_suggestions(host)

    return (warn + "\n" if warn else "") + fmt_output(
        result.stdout, result.timed_out, exe.timeout, update, suggestions,
    )


def sql_inject(url: str, params: str = "", level: int = 2) -> str:
    warn = ctf_mode_warning()
    exe = get_executor()
    findings = get_findings()
    host = _extract_host(url)

    try:
        exe.scope.check(host)
    except ScopeViolation as e:
        return f"[SCOPE VIOLATION] {e}"

    args = ["-u", url, "--batch", "--level", str(level)]
    if params:
        args.extend(["-p", params])

    try:
        result = exe.run("sqlmap", args)
    except FileNotFoundError as e:
        return str(e)

    vulns = sqlmap_parser.parse(result.stdout, host)
    update = findings.update_vulnerabilities(vulns)
    suggestions = findings.get_suggestions(host)

    return (warn + "\n" if warn else "") + fmt_output(
        result.stdout, result.timed_out, exe.timeout, update, suggestions,
    )


def wp_scan(url: str, enumerate: str = "vp,vt,u") -> str:
    warn = ctf_mode_warning()
    exe = get_executor()
    findings = get_findings()
    host = _extract_host(url)

    try:
        exe.scope.check(host)
    except ScopeViolation as e:
        return f"[SCOPE VIOLATION] {e}"

    args = ["--url", url, "--no-update", "--enumerate", enumerate]

    try:
        result = exe.run("wpscan", args)
    except FileNotFoundError as e:
        return str(e)

    if "WordPress" in result.stdout:
        findings.add_note(f"WordPress detected at {url}")

    import re
    users = re.findall(r"\|\s+Username:\s+(\S+)", result.stdout)
    if users:
        findings.add_note(f"WordPress users at {url}: {', '.join(users)}")

    suggestions = findings.get_suggestions(host)
    update = "wpscan complete — check output for vulnerabilities."

    return (warn + "\n" if warn else "") + fmt_output(
        result.stdout, result.timed_out, exe.timeout, update, suggestions,
    )
