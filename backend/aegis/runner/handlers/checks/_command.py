"""Command check handler.

Handler for arbitrary shell command verification.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner._types import CheckResult

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _check_command(ssh: SSHSession, c: dict) -> CheckResult:
    """Run an arbitrary command and verify its output.

    Executes a shell command and checks the exit code and optionally
    stdout content. Use for complex checks not covered by other handlers.

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - run (str): Shell command to execute.
            - expected_exit (int, optional): Expected exit code. Defaults to 0.
            - expected_stdout (str, optional): String that must appear in stdout.

    Returns:
        CheckResult with passed=True if exit code matches and stdout
        contains expected string (if specified).

    """
    cmd = c["run"]
    result = ssh.run(cmd)

    expected_exit = c.get("expected_exit", 0)
    if result.exit_code != expected_exit:
        return CheckResult(
            passed=False,
            detail=f"exit {result.exit_code} (expected {expected_exit}): {result.stderr or result.stdout}",
        )

    if "expected_stdout" in c and c["expected_stdout"] not in result.stdout:
        return CheckResult(
            passed=False,
            detail=f"stdout mismatch: got {result.stdout!r}",
        )

    return CheckResult(passed=True, detail=result.stdout[:200] if result.stdout else "ok")
