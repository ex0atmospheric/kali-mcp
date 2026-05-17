import re
import shutil
import subprocess
from typing import Optional

from scope import Scope, ScopeViolation


class ExecutionResult:
    def __init__(self, stdout: str, stderr: str, returncode: int, timed_out: bool = False):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.timed_out = timed_out


_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
_HOST_RE = re.compile(
    r"(?<!/)\b[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+\b"
)


class Executor:
    def __init__(self, scope: Scope, timeout: int = 300):
        self.scope = scope
        self.timeout = timeout

    def _extract_targets_from_args(self, args: list[str]) -> list[str]:
        targets: list[str] = []
        for arg in args:
            targets.extend(_IP_RE.findall(arg))
            targets.extend(_HOST_RE.findall(arg))
        return targets

    def run(
        self,
        tool: str,
        args: list[str],
        target: Optional[str] = None,
    ) -> ExecutionResult:
        if not shutil.which(tool):
            raise FileNotFoundError(
                f"Tool '{tool}' not found in PATH. Try: apt install {tool}"
            )

        if target:
            self.scope.check(target)

        for t in self._extract_targets_from_args(args):
            self.scope.check(t)

        try:
            proc = subprocess.run(
                [tool] + args,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            return ExecutionResult(proc.stdout, proc.stderr, proc.returncode)
        except subprocess.TimeoutExpired as exc:
            return ExecutionResult(
                stdout=exc.output.decode() if exc.output else "",
                stderr=exc.stderr.decode() if exc.stderr else "",
                returncode=-1,
                timed_out=True,
            )
