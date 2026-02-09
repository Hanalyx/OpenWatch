"""SSH session wrapper around paramiko."""

from __future__ import annotations

import shlex
from dataclasses import dataclass

import paramiko


def _shell_quote(s: str) -> str:
    """Quote a string for use as a single shell argument."""
    return shlex.quote(s)


@dataclass
class Result:
    """Result of a remote command execution."""

    exit_code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        """Return True if command succeeded (exit code 0)."""
        return self.exit_code == 0


class SSHSession:
    """Single reusable SSH connection to a remote host."""

    def __init__(
        self,
        hostname: str,
        *,
        port: int = 22,
        user: str | None = None,
        key_path: str | None = None,
        password: str | None = None,
        timeout: int = 30,
        sudo: bool = False,
    ):
        self.hostname = hostname
        self.port = port
        self.user = user
        self.key_path = key_path
        self.password = password
        self.timeout = timeout
        self.sudo = sudo
        self._client: paramiko.SSHClient | None = None

    def connect(self) -> None:
        """Establish the SSH connection."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs: dict = {
            "hostname": self.hostname,
            "port": self.port,
            "timeout": self.timeout,
        }
        if self.user:
            connect_kwargs["username"] = self.user
        if self.key_path:
            connect_kwargs["key_filename"] = self.key_path
        if self.password:
            connect_kwargs["password"] = self.password

        # When explicit credentials are given, don't fall back to other methods.
        # When nothing is given, let paramiko try ~/.ssh keys and the agent.
        if self.key_path or self.password:
            connect_kwargs["look_for_keys"] = False
            connect_kwargs["allow_agent"] = False

        client.connect(**connect_kwargs)
        self._client = client

    def run(self, cmd: str, *, timeout: int | None = None) -> Result:
        """Execute a command and return the result."""
        if self._client is None:
            raise RuntimeError("Not connected — call connect() first")

        if self.sudo:
            cmd = f"sudo -n sh -c {_shell_quote(cmd)}"

        t = timeout if timeout is not None else self.timeout
        _, stdout_ch, stderr_ch = self._client.exec_command(cmd, timeout=t)

        stdout = stdout_ch.read().decode("utf-8", errors="replace")
        stderr = stderr_ch.read().decode("utf-8", errors="replace")
        exit_code = stdout_ch.channel.recv_exit_status()

        return Result(exit_code=exit_code, stdout=stdout.rstrip("\n"), stderr=stderr.rstrip("\n"))

    def close(self) -> None:
        """Close the SSH connection."""
        if self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> SSHSession:
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()
