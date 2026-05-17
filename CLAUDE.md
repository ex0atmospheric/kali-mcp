# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`kali-mcp` is a Model Context Protocol (MCP) server that exposes Kali Linux security tools as structured MCP tools. It is designed to be consumed by Claude or another MCP client to drive autonomous penetration testing workflows against scoped lab targets.

## macOS PATH requirements

Tools installed by `install.sh` live in several non-standard locations. Ensure your shell (and the MCP server's environment) has all of these in `PATH`:

```
export PATH="/opt/homebrew/bin:/opt/homebrew/sbin:/opt/metasploit-framework/bin:/Library/Frameworks/Python.framework/Versions/3.13/bin:$HOME/.local/bin:$PATH"
```

Add this to your `~/.zshrc` (or `~/.bashrc`) so `server.py` and `msfconsole` are always reachable.

## Setup

1. Install all security tools and Python dependencies (macOS):
   ```
   bash install.sh
   ```
   This installs everything via brew, pip3, gem, and source. Safe to re-run — skips already-installed tools.

2. Edit `scope.yaml` to define your target IPs/CIDRs/hostnames before each engagement. Leave `targets` empty for CTF mode (no scope enforcement).

3. Update `.mcp.json` with the absolute paths for your environment:
   ```json
   { "mcpServers": { "kali-mcp": { "command": "python3", "args": ["/absolute/path/to/server.py"], "cwd": "/absolute/path/to/kali-mcp" } } }
   ```

4. Run the server directly (Claude Desktop / Claude Code picks it up via `.mcp.json`):
   ```
   python3 server.py
   ```

For fully autonomous mode (no permission prompts):
```
claude --dangerously-skip-permissions
```

## Running tests

```
pytest                        # all tests
pytest tests/test_parsers.py  # parser unit tests only
pytest tests/test_integration.py  # integration tests (all mocked, no live network)
pytest -k test_scope          # single test by name
```

Tests use `tmp_path` fixtures and mock `subprocess.run` — no live tool execution or network calls required.

## Architecture

The request flow is:

```
MCP client → server.py (tool definitions)
                → tools/*.py (business logic)
                    → executor.py (scope check + subprocess)
                    → parsers/*.py (structured output extraction)
                    → findings.py (persistent state)
                → context.py (module-level singletons)
```

### Key modules

- **`server.py`** — FastMCP tool registrations. Thin wrappers; all logic lives in `tools/`.
- **`context.py`** — Module-level singletons: `_scope`, `_findings`, `_executor`. Tests override these directly (e.g., `context._scope = Scope(...)`). `ctf_mode_warning()` emits a one-time banner when scope is empty.
- **`executor.py`** — Wraps `subprocess.run`. Checks scope before execution by extracting IPs/hostnames from args via regex. Raises `ScopeViolation` if a target is out of scope. Default timeout: 300s.
- **`scope.py`** — `Scope` loaded from `scope.yaml`. `check(target)` resolves hostnames to IPs and validates against CIDR networks/exclusion list. Empty `targets` list = CTF mode (everything allowed).
- **`findings.py`** — `FindingsStore` persists to `findings.json`. Tracks hosts/ports, URLs, credentials, vulnerabilities, hashes, and notes. `get_suggestions()` applies correlation rules (e.g., open port 80 → suggest `web_fuzz_dirs`) to drive the next-step recommendations appended to every tool output.
- **`tools/`** — One file per domain: `recon.py`, `web.py`, `creds.py`, `exploit.py`, `generic.py`, `session.py`. Each tool calls `get_executor()`, checks scope, runs the binary, parses output, updates findings, and returns `fmt_output(...)` with findings summary + suggestions appended.
- **`parsers/`** — One parser per tool (`nmap`, `gobuster`, `ffuf`, `hydra`, `john`, `nikto`, `sqlmap`, `enum4linux`). Each exposes a `parse(text, ...)` function returning structured dicts. nmap parses XML (`-oX -`); others parse plaintext.
- **`tools/_utils.py`** — Single helper `fmt_output()` that appends `[FINDINGS UPDATE]` and `[SUGGESTED NEXT STEPS]` sections to raw tool output.

### Findings store schema

```json
{
  "hosts": { "<ip>": { "ports": { "<port>": { "service": "", "version": "" } }, "os": null, "hostnames": [] } },
  "urls": [{ "host": "", "path": "", "status": 0 }],
  "credentials": [{ "host": "", "service": "", "user": "", "pass": "" }],
  "vulnerabilities": [{ "tool": "", "cve": "", ... }],
  "hashes": [{ "user": "", "hash": "", "cracked": null }],
  "notes": []
}
```

### Adding a new tool

1. Add a parser in `parsers/<toolname>.py` with a `parse()` function.
2. Add the tool logic in the appropriate `tools/*.py` — follow the existing pattern: scope check → `exe.run()` → parse → findings update → `fmt_output()`.
3. Register it in `server.py` with `@mcp.tool()`.
4. Add fixture output and parser tests in `tests/`.

### Wordlist paths

`tools/web.py` and `tools/creds.py` auto-detect the OS at import time. On Kali they use `/usr/share/wordlists/`; on macOS they fall back to `~/.local/share/wordlists/` (SecLists, installed by `install.sh`). The resolved paths are module-level constants (`_DEFAULT_WORDLIST`, `_DEFAULT_PASSLIST`, `_DEFAULT_USERLIST`) — callers that pass an explicit path override the defaults.

### Scope enforcement

Every `exe.run()` call checks scope twice: once on the explicit `target` parameter, and once by scanning all `args` for IP/hostname patterns. `ScopeViolation` is caught in each tool and returned as a `[SCOPE VIOLATION]` string rather than raised to the MCP layer.
