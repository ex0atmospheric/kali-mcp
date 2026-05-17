import json
from mcp.server.fastmcp import FastMCP

import context
from tools.recon import nmap_scan as _nmap_scan, dns_enum as _dns_enum, smb_enum as _smb_enum
from tools.web import web_fuzz_dirs as _web_fuzz_dirs, web_scan as _web_scan, sql_inject as _sql_inject, wp_scan as _wp_scan
from tools.creds import brute_force as _brute_force, crack_hash as _crack_hash
from tools.exploit import find_exploits as _find_exploits, msf_exec as _msf_exec
from tools.generic import run_command as _run_command, list_tools as _list_tools
from tools.session import (
    get_findings_tool as _get_findings,
    add_note as _add_note,
    clear_findings as _clear_findings,
    set_scope as _set_scope,
)

mcp = FastMCP("kali-mcp")

# ── Recon ─────────────────────────────────────────────────────────────────────

@mcp.tool()
def nmap_scan(target: str, ports: str = "1-1000", flags: str = "") -> str:
    """Run nmap against target. Parses XML output into findings and suggests next tools."""
    return _nmap_scan(target, ports, flags)


@mcp.tool()
def dns_enum(target: str) -> str:
    """Enumerate DNS records (A, MX, NS, TXT) for a domain."""
    return _dns_enum(target)


@mcp.tool()
def smb_enum(target: str) -> str:
    """Run enum4linux against target to enumerate SMB users and shares."""
    return _smb_enum(target)


# ── Web ───────────────────────────────────────────────────────────────────────

@mcp.tool()
def web_fuzz_dirs(
    target_url: str,
    wordlist: str = "",
    extensions: str = "",
    tool: str = "gobuster",
) -> str:
    """Fuzz web directories/files. tool='gobuster' or 'ffuf'. extensions e.g. 'php,html'."""
    return _web_fuzz_dirs(target_url, wordlist or "", extensions, tool)


@mcp.tool()
def web_scan(target: str, port: int = 80) -> str:
    """Run nikto web vulnerability scan against target."""
    return _web_scan(target, port)


@mcp.tool()
def sql_inject(url: str, params: str = "", level: int = 2) -> str:
    """Run sqlmap against a URL. params: comma-separated param names to test."""
    return _sql_inject(url, params, level)


@mcp.tool()
def wp_scan(url: str, enumerate: str = "vp,vt,u") -> str:
    """Scan a WordPress site with wpscan. enumerate: vp=vuln plugins, vt=vuln themes, u=users."""
    return _wp_scan(url, enumerate)


# ── Creds ─────────────────────────────────────────────────────────────────────

@mcp.tool()
def brute_force(
    target: str,
    service: str,
    port: int = 0,
    userlist: str = "/usr/share/wordlists/metasploit/unix_users.txt",
    passlist: str = "/usr/share/wordlists/rockyou.txt",
    username: str = "",
) -> str:
    """Brute force a service with hydra. service e.g. ssh, ftp, http-get. username overrides userlist."""
    return _brute_force(target, service, port, userlist, passlist, username)


@mcp.tool()
def crack_hash(hashfile: str, wordlist: str = "/usr/share/wordlists/rockyou.txt", format: str = "") -> str:
    """Crack password hashes with john. hashfile: path to file containing hashes. format: e.g. 'sha512crypt'."""
    return _crack_hash(hashfile, wordlist, format)


# ── Exploit ───────────────────────────────────────────────────────────────────

@mcp.tool()
def find_exploits(query: str) -> str:
    """Search Exploit-DB via searchsploit. query: CVE, product name, or keyword."""
    return _find_exploits(query)


@mcp.tool()
def msf_exec(command: str, target: str = "") -> str:
    """Execute a msfconsole command. E.g. 'use exploit/multi/handler; set payload ...; run'. target for scope check."""
    return _msf_exec(command, target)


# ── Generic ───────────────────────────────────────────────────────────────────

@mcp.tool()
def run_command(tool: str, args: str) -> str:
    """Run any Kali tool not covered above. tool: binary name, args: argument string. Scope-gated."""
    return _run_command(tool, args)


@mcp.tool()
def list_tools() -> str:
    """List all installed security tools discovered in PATH, with descriptions."""
    return _list_tools()


# ── Session ───────────────────────────────────────────────────────────────────

@mcp.tool()
def get_findings() -> str:
    """Return full findings store as JSON: hosts/ports, URLs, credentials, vulns, hashes, notes."""
    return _get_findings()


@mcp.tool()
def add_note(text: str) -> str:
    """Add a free-form note to the findings store."""
    return _add_note(text)


@mcp.tool()
def clear_findings() -> str:
    """Clear all findings and reset the session for a new target."""
    return _clear_findings()


@mcp.tool()
def set_scope(targets: list[str], exclusions: list[str] = []) -> str:
    """Update scope at runtime. targets: list of IPs/CIDRs/hostnames. exclusions: list to block."""
    return _set_scope(targets, exclusions)


# ── Resources ─────────────────────────────────────────────────────────────────

@mcp.resource("findings://current")
def findings_resource() -> str:
    return json.dumps(context.get_findings().get_all(), indent=2)


@mcp.resource("scope://current")
def scope_resource() -> str:
    scope = context.get_scope()
    return f"Targets: {scope.targets}\nExclusions: {scope.exclusions}"


@mcp.resource("tools://available")
def tools_resource() -> str:
    return _list_tools()


if __name__ == "__main__":
    mcp.run()
