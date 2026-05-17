from pathlib import Path
from context import get_executor, get_findings, ctf_mode_warning
from scope import ScopeViolation
from parsers import hydra as hydra_parser
from parsers import john as john_parser
from tools._utils import fmt_output

_SECLISTS = f"{__import__('os').path.expanduser('~')}/.local/share/wordlists"
_DEFAULT_PASSLIST = (
    "/usr/share/wordlists/rockyou.txt"
    if __import__("os.path", fromlist=["exists"]).exists("/usr/share/wordlists/rockyou.txt")
    else f"{_SECLISTS}/Passwords/Leaked-Databases/rockyou.txt"
)
_DEFAULT_USERLIST = (
    "/usr/share/wordlists/metasploit/unix_users.txt"
    if __import__("os.path", fromlist=["exists"]).exists("/usr/share/wordlists/metasploit/unix_users.txt")
    else f"{_SECLISTS}/Usernames/top-usernames-shortlist.txt"
)


def brute_force(
    target: str,
    service: str,
    port: int = 0,
    userlist: str = _DEFAULT_USERLIST,
    passlist: str = _DEFAULT_PASSLIST,
    username: str = "",
) -> str:
    warn = ctf_mode_warning()
    exe = get_executor()
    findings = get_findings()

    try:
        exe.scope.check(target)
    except ScopeViolation as e:
        return f"[SCOPE VIOLATION] {e}"

    if not Path(passlist).exists():
        return (
            f"[ERROR] Password list not found: {passlist}\n"
            "Tip: gunzip /usr/share/wordlists/rockyou.txt.gz to extract rockyou.txt"
        )

    if not username and not Path(userlist).exists():
        return (
            f"[ERROR] User list not found: {userlist}\n"
            "Tip: specify a custom userlist path or provide a username= argument"
        )

    args = []
    if username:
        args.extend(["-l", username])
    else:
        args.extend(["-L", userlist])
    args.extend(["-P", passlist])
    if port:
        args.extend(["-s", str(port)])
    args.append(target)
    args.append(service)

    try:
        result = exe.run("hydra", args, target=target)
    except FileNotFoundError as e:
        return str(e)

    creds = hydra_parser.parse(result.stdout)
    update = findings.update_credentials(creds)
    suggestions = findings.get_suggestions(target)

    return (warn + "\n" if warn else "") + fmt_output(
        result.stdout, result.timed_out, exe.timeout, update, suggestions,
    )


def crack_hash(
    hashfile: str,
    wordlist: str = _DEFAULT_PASSLIST,
    format: str = "",
) -> str:
    exe = get_executor()
    findings = get_findings()

    if not Path(hashfile).exists():
        return f"[ERROR] Hash file not found: {hashfile}"

    if not Path(wordlist).exists():
        return (
            f"[ERROR] Wordlist not found: {wordlist}\n"
            "Tip: gunzip /usr/share/wordlists/rockyou.txt.gz"
        )

    args = [f"--wordlist={wordlist}", hashfile]
    if format:
        args.insert(0, f"--format={format}")

    try:
        result = exe.run("john", args)
    except FileNotFoundError as e:
        return str(e)

    cracked = john_parser.parse(result.stdout)
    hashes = [{"user": h["user"], "hash": "", "cracked": h["cracked"]} for h in cracked]
    update = findings.update_hashes(hashes)
    suggestions = findings.get_suggestions()

    return fmt_output(result.stdout, result.timed_out, exe.timeout, update, suggestions)
