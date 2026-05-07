import os
import shutil
from context import get_executor, ctf_mode_warning
from scope import ScopeViolation

_KNOWN_TOOLS = {
    "nmap": "Network scanner",
    "gobuster": "Directory/DNS brute forcer",
    "ffuf": "Fast web fuzzer",
    "nikto": "Web server scanner",
    "sqlmap": "SQL injection tool",
    "hydra": "Password brute forcer",
    "john": "Password hash cracker",
    "hashcat": "GPU-accelerated hash cracker",
    "msfconsole": "Metasploit framework console",
    "searchsploit": "Exploit-DB search",
    "wpscan": "WordPress vulnerability scanner",
    "enum4linux": "SMB/Windows enumeration",
    "dnsenum": "DNS enumeration",
    "dig": "DNS lookup",
    "smbclient": "SMB client",
    "aircrack-ng": "WiFi security auditing",
    "wifite": "Automated wireless auditor",
    "netcat": "TCP/UDP networking",
    "nc": "Netcat",
    "curl": "HTTP client",
    "wget": "File downloader",
    "tcpdump": "Packet capture",
    "wireshark": "Packet analyser",
    "burpsuite": "Web proxy",
    "maltego": "OSINT tool",
    "crunch": "Wordlist generator",
    "dirb": "Web content scanner",
    "wfuzz": "Web fuzzer",
    "medusa": "Password brute forcer",
    "ncrack": "Network auth cracker",
    "masscan": "Fast port scanner",
    "whatweb": "Web technology fingerprinter",
    "wafw00f": "WAF detector",
    "sslscan": "SSL/TLS scanner",
    "testssl.sh": "SSL/TLS tester",
    "dnsrecon": "DNS recon",
    "sublist3r": "Subdomain enumerator",
    "amass": "Attack surface mapper",
    "theharvester": "OSINT email/domain harvester",
    "responder": "LLMNR/NBT-NS poisoner",
    "impacket-secretsdump": "Dump Windows secrets",
    "evil-winrm": "WinRM shell",
    "crackmapexec": "SMB/WinRM Swiss army knife",
    "bloodhound": "AD attack path finder",
    "neo4j": "Graph database (for BloodHound)",
    "mimikatz": "Windows credential tool",
    "powershell": "PowerShell",
    "python3": "Python interpreter",
    "perl": "Perl interpreter",
    "ruby": "Ruby interpreter",
}


def list_tools() -> str:
    installed = []
    for tool, desc in _KNOWN_TOOLS.items():
        if shutil.which(tool):
            installed.append(f"  {tool:<30} {desc}")

    unknown_dirs = ["/usr/bin", "/usr/local/bin", "/usr/sbin"]
    known_names = set(_KNOWN_TOOLS.keys())
    unknown = []
    for d in unknown_dirs:
        try:
            for entry in os.scandir(d):
                if entry.is_file() and os.access(entry.path, os.X_OK):
                    if entry.name not in known_names:
                        unknown.append(entry.name)
        except PermissionError:
            pass

    out = "=== Installed security tools ===\n"
    out += "\n".join(installed) or "  (none found)"
    if unknown:
        out += f"\n\n=== Other executables in PATH (first 50) ===\n"
        out += "  " + ", ".join(sorted(unknown)[:50])
    return out


def run_command(tool: str, args: str) -> str:
    warn = ctf_mode_warning()
    exe = get_executor()

    args_list = args.split() if args else []

    try:
        result = exe.run(tool, args_list)
    except FileNotFoundError as e:
        return str(e)
    except ScopeViolation as e:
        return f"[SCOPE VIOLATION] {e}"

    out = result.stdout
    if result.stderr:
        out += f"\n[STDERR]\n{result.stderr}"
    if result.timed_out:
        out = f"[TIMEOUT after {exe.timeout}s — partial output]\n" + out

    return (warn + "\n" if warn else "") + out
