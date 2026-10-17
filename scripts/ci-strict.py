#!/usr/bin/env python3
"""Strict local CI: the final local gate for one revision.

    python3 -S scripts/ci-strict.py [--commit] [--allow-not-run GATE ...]
    python3 -S scripts/ci-strict.py --check-result FILE [--expect-id ID] [--commit]

It reports what actually ran and makes no claim about whether to push.

Two modes, and every result says which one produced it (bugs/OW-124):

  development  (default) tests this checkout as it is: HEAD plus every
               uncommitted change, and any ignored source file on disk. The
               result names that state. It is not evidence about any commit.
  --commit     tests HEAD's committed files only. The gates run in a clean
               `git clone --shared` of HEAD outside the checkout, with the
               frontend dependencies installed there by `npm ci`, as hosted CI
               does. Uncommitted, untracked, staged-only and ignored files in
               the checkout cannot reach it. This is the readiness evidence for
               a pinned commit. The checkout's own state is not changed.

`--check-result FILE --commit` accepts only a commit-mode result for HEAD.

Exit codes, from this script (authoritative; `make ci-strict` is a wrapper,
and make turns every failure into exit 2):

  0  COMPLETE    every required gate ran and passed, and the only tests not
                 run are the opt-ins that hosted CI skips too
  1  FAILED      a gate or a test failed, or `npm ci` failed in a commit export
  3  INCOMPLETE  nothing failed, but a required gate or test did not run.
                 Accepting a gap with --allow-not-run records the acceptance;
                 the run is still INCOMPLETE and still exits 3
  4  REFUSED     another invocation holds the lock, or the arguments are
                 invalid; nothing ran

Order of work:

  1. Take the lock, or refuse. One invocation at a time: they would share
     the one local test database, and none may touch another's evidence.
  2. Preflight every prerequisite and report all that are missing at once.
     A missing prerequisite that was not accepted stops the run before any
     expensive work, as INCOMPLETE.
  3. Run the gates. Go tests run as hosted CI splits them (internal/server
     alone, then every other package), but one phase after the other and
     with -p 1, because a workstation has one test database. Hosted CI runs
     them at once, each against its own database.
  4. Summarize passed, failed and not-run tests from the result streams.
  5. Write the result atomically into this invocation's own directory, then
     point `latest.json` at it, also atomically.
  6. Remove the export and release the lock. Every command runs in a
     process group of its own, which is stopped and waited for before the
     command's call returns, so by this step nothing the run started is
     still running. SIGINT, SIGTERM and SIGHUP all reach this step, and are
     deferred while it runs; SIGKILL cannot. A descendant that deliberately
     leaves its group is out of reach. A group that survives SIGKILL is
     recorded in the lock, which then stays: no further command starts, the
     run is FAILED, and no run can take the lock while that group has
     members. A record that cannot be validated is never reclaimed
     automatically; remove that lock by hand.

Results live under `$(git rev-parse --git-dir)/ci-strict/`, outside the
working tree, so no test that walks the repository can see them. Each
invocation writes only `runs/<its id>/`; nothing deletes another's.

Standard library only.
"""

import argparse
import contextlib
import copy
import datetime
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import uuid
from pathlib import Path

EXIT_COMPLETE, EXIT_FAILED, EXIT_INCOMPLETE, EXIT_REFUSED = 0, 1, 3, 4
VERDICTS = {EXIT_COMPLETE: "complete", EXIT_FAILED: "failed", EXIT_INCOMPLETE: "incomplete"}

REPO = Path(__file__).resolve().parent.parent
SERVER_PKG = "github.com/Hanalyx/openwatch/internal/server"

# Tests that hosted CI skips too, by their exact t.Skip message, measured on
# Go CI run 37834313168 (the only five skips in a full hosted run). A local
# skip with any other message means a prerequisite was missing, so the run is
# not equivalent to hosted CI. Every entry must stay a literal in the tests
# (scripts/test_ci_strict.py checks that).
HOSTED_SKIPS = (
    "set OPENWATCH_LIVE_SCAN_{ADDR,USER,KEY} to run the live scan test",
    "generator; set OPENWATCH_WRITE_REPORT_FIXTURE=1 to rewrite the published example",
    "set OPENWATCH_LIVE_HOSTS (csv) and OPENWATCH_LIVE_KEY (private key) to run live-host SSH tests",
    "set OPENWATCH_ROLLBACK_IMAGE (for example postgres:16) to run the rollback blocks against PostgreSQL",
    "set OPENWATCH_KENSA_COMPAT_{IMAGE,KIND,OLD_DIR,NEW_DIR} to run the container pairing test",
)

LOGGED = re.compile(r"^\s*[\w./-]+_test\.go:\d+: (.*?)\s*$")


# ----------------------------------------------------------------- probes

class Probe:
    """Everything that touches the machine, so tests can replace it."""

    def __init__(self, repo=REPO, env=None):
        self.repo = Path(repo)
        self.env = dict(os.environ if env is None else env)

    def at(self, repo):
        """The same machine, working in another checkout."""
        other = copy.copy(self)
        other.repo = Path(repo)
        return other

    def which(self, name):
        return shutil.which(name, path=self.env.get("PATH"))

    def run(self, cmd, cwd=None, env=None, stdout=None, merge_stderr=False):
        """Run cmd; return its exit code. Output goes to the terminal unless
        stdout names a file; merge_stderr sends stderr to that file too."""
        e = dict(self.env)
        e.update(env or {})
        if stdout:
            with open(stdout, "wb") as out:
                return run_group(cmd, cwd=cwd or self.repo, env=e, stdout=out,
                                 stderr=subprocess.STDOUT if merge_stderr else None)
        return run_group(cmd, cwd=cwd or self.repo, env=e)

    def capture(self, cmd, cwd=None):
        # A file, not a pipe: a descendant holding a pipe open would keep a
        # reader waiting for EOF after the command itself had exited.
        with tempfile.TemporaryFile() as out:
            rc = run_group(cmd, cwd=cwd or self.repo, env=self.env, stdout=out, stderr=subprocess.STDOUT)
            out.seek(0)
            return rc, out.read().decode(errors="replace").strip()


    def tcp_open(self, host, port):
        try:
            with socket.create_connection((host, port), timeout=3):
                return True
        except OSError:
            return False

    def group_alive(self, pgid):
        """True while process group pgid has any member."""
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    def pid_alive(self, pid):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True


# ------------------------------------------------------- process groups

# How long a command's process group gets to exit after SIGTERM, and again
# after SIGKILL, before the run gives up on it.
GROUP_GRACE = 10.0

# Process groups that survived SIGKILL. Once any is listed, the run starts
# no further work, cannot be COMPLETE, and keeps its export and its lock.
UNSTOPPED = []

# Where to persist UNSTOPPED the moment it changes: the held lock's
# directory, set by strict(). The record outlives this process, and
# Lock.acquire refuses to reclaim the lock while a recorded group has
# members, whether or not the run that wrote it is still alive.
BLOCK_RECORD = None

# The signals cleanup must not be cut short by: every one that main() turns
# into an exception.
TERMINATING = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)


def run_group(cmd, **popen):
    """Run cmd in a session, and so a process group, of its own and return
    its exit code. Whatever way this returns, by exit, exception or signal,
    the whole group has been stopped and waited for first, so no descendant
    of the command outlives it: npm's lifecycle scripts, go test's test
    binaries, vitest's workers. Output must go to the terminal or a file,
    never a pipe: only the command itself is waited for, not EOF.

    A descendant that deliberately leaves the group (setsid, setpgid, a
    daemonizing double fork) is out of reach. Nothing the gates run does
    that today."""
    p = subprocess.Popen(cmd, start_new_session=True, **popen)
    finished = False
    try:
        p.wait()
        finished = True
    finally:
        with shielded(propagating=not finished):
            stop_group(p)
    return p.returncode


def stop_group(p):
    """SIGTERM p's process group, wait for it to empty, then SIGKILL and
    wait again. A group still present after that is recorded in UNSTOPPED
    and, at once, in BLOCK_RECORD."""
    for sig in (signal.SIGTERM, signal.SIGKILL):
        if group_empty(p):
            return
        try:
            os.killpg(p.pid, sig)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + GROUP_GRACE
        while time.monotonic() < deadline:
            if group_empty(p):
                return
            time.sleep(0.05)
    record_unstopped(p.pid)


def record_unstopped(pgid):
    """Note that process group pgid survived SIGKILL, in UNSTOPPED and at
    once in BLOCK_RECORD, which outlives this process."""
    UNSTOPPED.append(pgid)
    if BLOCK_RECORD is not None:
        write_atomic(BLOCK_RECORD, {"unstopped_groups": UNSTOPPED,
                                    "recorded": datetime.datetime.now(datetime.timezone.utc).isoformat()})


class StopRun(Exception):
    """A command was about to start after a process group survived SIGKILL."""


class Guarded:
    """The probe strict() runs every command through, gates and export
    preparation alike, whatever probe it was given. Once a process group has
    survived SIGKILL (UNSTOPPED is not empty), run and capture start nothing
    and raise StopRun. Everything else passes through."""

    def __init__(self, inner):
        self._inner = inner

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def _refuse_after_survivor(self, cmd):
        if UNSTOPPED:
            raise StopRun(f"process group(s) {UNSTOPPED} survived SIGKILL; "
                          f"not starting {' '.join(map(str, cmd[:3]))}")

    def run(self, cmd, *args, **kwargs):
        self._refuse_after_survivor(cmd)
        return self._inner.run(cmd, *args, **kwargs)

    def capture(self, cmd, *args, **kwargs):
        self._refuse_after_survivor(cmd)
        return self._inner.capture(cmd, *args, **kwargs)

    def at(self, repo):
        return Guarded(self._inner.at(repo))


def group_empty(p):
    p.poll()  # reap the leader, which would otherwise stay in the group as a zombie
    try:
        os.killpg(p.pid, 0)
    except ProcessLookupError:
        return True
    return False


class shielded:
    """Defer SIGINT, SIGTERM and SIGHUP while cleanup runs, so no signal can
    cut it short. A deferred signal is not lost: on the way out, if no
    exception is already propagating, the first one is delivered again to
    the restored handler, so a signal that arrived while a finished
    command's group was being stopped still stops the run. If an exception
    is propagating, the run is already on its way out, and that exception
    keeps its exit code. Only the main thread may change handlers; anywhere
    else this does nothing."""

    def __init__(self, propagating=False):
        # A `finally` cannot see the exception passing through it, so the
        # caller says whether one is.
        self.propagating = propagating

    def __enter__(self):
        self.pending, self.saved = [], {}
        try:
            for s in TERMINATING:
                self.saved[s] = signal.signal(s, lambda signum, _frame: self.pending.append(signum))
        except ValueError:
            pass  # not the main thread
        return self

    def __exit__(self, exc_type, exc, tb):
        for s, h in self.saved.items():
            signal.signal(s, h)
        if self.pending and exc_type is None and not self.propagating:
            signal.raise_signal(self.pending[0])
        return False


def makefile_pin(repo, name):
    m = re.search(rf"(?m)^{name}\s*:=\s*(\S+)", (Path(repo) / "Makefile").read_text())
    return m.group(1) if m else None


def preflight(probe):
    """Return {prerequisite: (ok, detail)} for every prerequisite, all checked."""
    out = {}
    env, repo = probe.env, probe.repo

    dsn = env.get("OPENWATCH_TEST_DSN", "")
    if not dsn:
        out["test-database"] = (False, "OPENWATCH_TEST_DSN is unset; start one with "
                                       "`make test-db && eval \"$(scripts/test-db.sh dsn)\"`")
    else:
        u = urllib.parse.urlparse(dsn)
        db = u.path.lstrip("/")
        if not db.endswith("_test"):
            out["test-database"] = (False, f"database {db!r} does not end in _test; tests truncate tables")
        elif not probe.tcp_open(u.hostname or "127.0.0.1", u.port or 5432):
            out["test-database"] = (False, f"nothing accepts connections at {u.hostname}:{u.port or 5432}")
        else:
            out["test-database"] = (True, f"{db} at {u.hostname}:{u.port or 5432}")

    want = (repo / ".specter-version").read_text().strip()
    if not probe.which("specter"):
        out["specter"] = (False, f"specter is not on PATH; the pin is {want}")
    else:
        rc, text = probe.capture(["specter", "--version"])
        m = re.search(r"\d+\.\d+\.\d+", text)
        have = m.group(0) if m else text
        out["specter"] = (have == want, f"specter {have}" + ("" if have == want else f", the pin is {want}"))

    pin = makefile_pin(repo, "GOLANGCI_VERSION")
    if not probe.which("golangci-lint"):
        out["golangci-lint"] = (False, f"golangci-lint is not on PATH; the pin is {pin}")
    else:
        rc, text = probe.capture(["golangci-lint", "version"])
        m = re.search(r"\d+\.\d+\.\d+", text)
        have = m.group(0) if m else text
        out["golangci-lint"] = (have == pin, f"golangci-lint {have}" + ("" if have == pin else f", the pin is {pin}"))

    out["govulncheck"] = ((True, "on PATH") if probe.which("govulncheck")
                          else (False, "govulncheck is not on PATH"))

    lock, installed = repo / "frontend" / "package-lock.json", repo / "frontend" / "node_modules" / ".package-lock.json"
    if not installed.is_file():
        out["frontend-dependencies"] = (False, "frontend/node_modules is not installed; run `cd frontend && npm ci`")
    else:
        try:
            want = {k: v for k, v in json.loads(lock.read_text())["packages"].items() if k}
            have_pkgs = {k: v.get("version") for k, v in json.loads(installed.read_text())["packages"].items() if k}
        except (OSError, ValueError, KeyError) as e:
            out["frontend-dependencies"] = (False, f"cannot compare node_modules with the lockfile: {e}")
        else:
            # npm leaves out optional packages for other platforms, and its
            # installed record omits them, so an absent OPTIONAL package is not
            # drift. A version mismatch, a missing required package, or an
            # installed package the lockfile does not list is.
            drift = sorted(
                [k for k, v in want.items()
                 if (k in have_pkgs and have_pkgs[k] != v.get("version"))
                 or (k not in have_pkgs and not v.get("optional"))]
                + [k for k in have_pkgs if k not in want])
            out["frontend-dependencies"] = ((True, f"{len(have_pkgs)} packages match the lockfile") if not drift
                                            else (False, f"node_modules differs from the lockfile ({len(drift)} "
                                                         f"packages, e.g. {drift[0]}); run `cd frontend && npm ci`"))

    missing = [t for t in ("rpmbuild", "rpm", "dpkg-deb", "dpkg") if not probe.which(t)]
    out["packaging-tools"] = ((True, "rpmbuild, rpm, dpkg-deb, dpkg") if not missing
                              else (False, "missing " + ", ".join(missing)))

    # The sshd container tests run in hosted CI, so they run here too.
    if not probe.which("docker"):
        out["container-runtime"] = (False, "docker is not on PATH; the sshd container tests need it")
    else:
        rc, _ = probe.capture(["docker", "info", "--format", "{{.ServerVersion}}"])
        out["container-runtime"] = ((True, "docker daemon answers") if rc == 0
                                    else (False, "docker is on PATH but its daemon does not answer"))

    missing = [t for t in ("go", "git", "node", "npx", "make") if not probe.which(t)]
    out["toolchain"] = ((True, "go, git, node, npx, make") if not missing
                        else (False, "missing " + ", ".join(missing)))
    return out


# ------------------------------------------------------------------ gates

# Each gate: the prerequisites it needs, and how it runs. Order matters.
GATES = [
    ("stage-embedded", ("toolchain",)),
    ("check-generated", ("toolchain", "frontend-dependencies")),
    ("vet", ("toolchain",)),
    ("lint", ("toolchain", "golangci-lint")),
    ("vuln", ("toolchain", "govulncheck")),
    ("spec-check", ("toolchain", "specter")),
    ("docs-style", ()),
    ("license-bundle", ("toolchain",)),
    ("go-tests", ("toolchain", "test-database", "packaging-tools", "container-runtime")),
    ("vitest", ("toolchain", "frontend-dependencies")),
    ("test-streams", ()),
    ("specter-coverage", ("specter",)),
]

MAKE_GATES = {
    "stage-embedded": ["make", "internal/server/openapi_embed.yaml", "internal/server/spa/index.html"],
    "check-generated": ["make", "check-generated"],
    "vet": ["make", "vet"],
    "lint": ["make", "lint"],
    "vuln": ["make", "vuln"],
    "spec-check": ["make", "spec-check"],
    "docs-style": ["make", "docs-style"],
    "license-bundle": ["make", "license-bundle"],
}


def run_go_tests(probe, rundir):
    """Hosted CI's split, run locally one phase after the other with -p 1."""
    rc, pkgs = probe.capture(["go", "list", "./..."])
    if rc != 0:
        return 1
    (rundir / "go-packages.txt").write_text(pkgs + "\n")
    others = [p for p in pkgs.splitlines() if p and p != SERVER_PKG]
    rc, kensa = probe.capture(["go", "list", "-m", "-f", "{{.Dir}}", "github.com/Hanalyx/kensa"])
    env = {"OPENWATCH_PACKAGING_BUILD": "1", "OPENWATCH_KENSA_RULES_DIR": kensa + "/rules",
           "OPENWATCH_SSH_CONTAINER_TESTS": "1"}
    a = probe.run(["go", "test", "-race", "-json", "-timeout", "1800s", "./internal/server/"],
                  env=env, stdout=rundir / "go-test-server.json")
    b = probe.run(["go", "test", "-race", "-json", "-timeout", "900s", "-p", "1"] + others,
                  env=env, stdout=rundir / "go-test.json")
    return 0 if a == 0 and b == 0 else 1


def run_gate(gate, probe, rundir):
    if gate in MAKE_GATES:
        return probe.run(MAKE_GATES[gate])
    if gate == "go-tests":
        return run_go_tests(probe, rundir)
    if gate == "vitest":
        return probe.run(["npx", "vitest", "run", "--reporter=junit",
                          f"--outputFile={rundir / 'vitest-junit.xml'}", "--reporter=default"],
                         cwd=probe.repo / "frontend")
    if gate == "test-streams":
        return probe.run([sys.executable, "-S", str(probe.repo / "scripts" / "check-test-streams.py"),
                          "--packages", str(rundir / "go-packages.txt"),
                          "--others", str(rundir / "go-test.json"),
                          "--server", str(rundir / "go-test-server.json"),
                          "--junit", str(rundir / "vitest-junit.xml")])
    if gate == "specter-coverage":
        for f in (probe.repo / ".specter-results.json",):
            if f.exists():
                f.unlink()
        rc = probe.run(["specter", "ingest", "--go-test", str(rundir / "go-test.json"),
                        "--go-test", str(rundir / "go-test-server.json"),
                        "--junit", str(rundir / "vitest-junit.xml")])
        return rc if rc != 0 else probe.run(["specter", "sync", "--tests", "**/*"])
    raise ValueError(gate)


# ---------------------------------------------------------------- summary

def summarize_streams(rundir):
    """Passed, failed and not-run tests from the go test streams, with each
    not-run test's reason, and whether that reason also skips on hosted CI."""
    passed = failed = 0
    not_run = {}
    for name in ("go-test-server.json", "go-test.json"):
        path = rundir / name
        if not path.is_file():
            continue
        out, final = {}, {}
        for line in path.read_text(errors="replace").splitlines():
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            t = ev.get("Test") if isinstance(ev, dict) else None
            if not t:
                continue
            key = (ev.get("Package"), t)
            if ev.get("Action") == "output":
                out.setdefault(key, []).append(ev.get("Output", ""))
            elif ev.get("Action") in ("pass", "fail", "skip"):
                final[key] = ev["Action"]
        for key, action in final.items():
            if action == "pass":
                passed += 1
            elif action == "fail":
                failed += 1
            else:
                msgs = [m.group(1) for chunk in out.get(key, []) for ln in chunk.splitlines()
                        for m in [LOGGED.match(ln)] if m]
                reason = msgs[-1] if msgs else "(no skip message)"
                not_run[reason] = not_run.get(reason, 0) + 1
    unexpected = {r: n for r, n in not_run.items() if r not in HOSTED_SKIPS}
    return {"passed": passed, "failed": failed, "not_run": not_run, "unexpected_not_run": unexpected}


def decide(gates, tests, coverage_ran):
    """The verdict from gate outcomes and the test summary."""
    if any(g["outcome"] == "failed" for g in gates) or tests["failed"]:
        return EXIT_FAILED
    if any(g["outcome"] != "passed" for g in gates) or tests["unexpected_not_run"] or not coverage_ran:
        return EXIT_INCOMPLETE
    return EXIT_COMPLETE


# --------------------------------------------------------- state and lock

def state_dir(probe):
    rc, gitdir = probe.capture(["git", "rev-parse", "--absolute-git-dir"])
    if rc != 0:
        raise SystemExit(f"ci-strict: not a git checkout: {gitdir}")
    return Path(gitdir) / "ci-strict"


# Ignored files that feed the checks: source a gate compiles, lints, tests or
# scans. Dependencies, build outputs and local evidence are ignored on purpose
# and are not inputs (bugs/OW-124).
CHECK_INPUT_ROOTS = ("internal/", "cmd/", "specs/", "api/", "auth/", "scripts/", "packaging/",
                     "release/", "frontend/src/", "frontend/tests/", ".github/")
CHECK_INPUT_SUFFIXES = (".go", ".py", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".yaml", ".yml", ".sql", ".md")
NOT_CHECK_INPUTS = ("internal/server/openapi_embed.yaml", "internal/server/spa/")


def git_list(probe, args):
    rc, text = probe.capture(["git", "ls-files", "-z"] + args)
    return [p for p in text.split("\0") if p] if rc == 0 else []


def ignored_check_inputs(probe):
    """Ignored files on disk that a gate would read as source. The roots and
    suffixes decide; excluding node_modules only keeps the listing small."""
    paths = git_list(probe, ["--others", "--ignored", "--exclude-standard", "--",
                             ":(exclude)frontend/node_modules", ":(exclude,glob)**/node_modules/**"])
    return sorted(p for p in paths
                  if p.startswith(CHECK_INPUT_ROOTS) and p.endswith(CHECK_INPUT_SUFFIXES)
                  and not p.startswith(NOT_CHECK_INPUTS))


def tree_identity(probe):
    """The commit and a digest of everything a development run can read
    beyond it: tracked changes, staged or not, the names AND contents of
    untracked files, and ignored source files on disk. A result can be
    matched to the state it describes."""
    _, head = probe.capture(["git", "rev-parse", "HEAD"])
    h = hashlib.sha256()
    _, diff = probe.capture(["git", "diff", "HEAD", "--binary", "--no-ext-diff"])
    h.update(diff.encode())
    h.update(b"\0")
    for p in git_list(probe, ["--others", "--exclude-standard"]) + ignored_check_inputs(probe):
        h.update(p.encode() + b"\0")
        try:
            h.update((probe.repo / p).read_bytes())
        except OSError:
            h.update(b"<unreadable>")
        h.update(b"\0")
    return head, h.hexdigest()


def working_tree_state(probe):
    """What a development run includes beyond HEAD, for the result."""
    _, changed = probe.capture(["git", "diff", "HEAD", "--name-only", "--no-ext-diff"])
    return {
        "changed_tracked": sorted(p for p in changed.splitlines() if p),
        "untracked": git_list(probe, ["--others", "--exclude-standard"]),
        "ignored_check_inputs": ignored_check_inputs(probe),
    }


def export_commit(probe, commit, owned):
    """A clean checkout of commit, outside the repository: `git clone
    --shared` (the objects are borrowed, the source's refs and worktrees are
    untouched), checked out detached. Returns the checkout, or raises
    RuntimeError.

    The temporary directory is appended to owned as soon as mkdtemp returns,
    before any git command runs. The caller removes everything in owned in
    its `finally`, so the directory goes on success, on a failed clone or
    checkout, and on an interrupt at any of those points."""
    owned.append(Path(tempfile.mkdtemp(prefix="ci-strict-commit-")))
    dest = owned[-1] / "checkout"
    rc, text = probe.capture(["git", "clone", "--quiet", "--shared", "--no-checkout", str(probe.repo), str(dest)])
    if rc != 0:
        raise RuntimeError(f"git clone of the checkout failed: {text}")
    rc, text = probe.capture(["git", "-C", str(dest), "checkout", "--quiet", "--detach", commit])
    if rc != 0:
        raise RuntimeError(f"git checkout {commit} in the export failed: {text}")
    return dest


class Lock:
    """An exclusive lock as a directory: mkdir is atomic. A lock whose owner
    is gone is reclaimed, and said so; a live one refuses the newcomer."""

    def __init__(self, state, probe, invocation):
        self.dir = state / "lock"
        self.probe = probe
        self.invocation = invocation
        self.held = False

    def acquire(self):
        self.dir.parent.mkdir(parents=True, exist_ok=True)
        for _ in range(2):
            try:
                self.dir.mkdir()
            except FileExistsError:
                owner = self.owner()
                groups, problem = self.blocking_record()
                if problem:
                    # A record exists but its groups cannot be determined.
                    # Unknown is not "none": refuse, and say why.
                    return False, dict(owner or {}, invalid_record=problem)
                alive = [g for g in groups if self.probe.group_alive(g)]
                if alive:
                    # A process group outlived SIGKILL in the run that holds
                    # this lock. Whether that run is alive does not matter.
                    return False, dict(owner or {}, unstopped=alive)
                if owner and self.probe.pid_alive(owner.get("pid", -1)):
                    return False, owner
                # Stale: its process is gone. Move it aside rather than delete,
                # so the record of what was interrupted survives.
                stale = self.dir.with_name(f"lock.stale-{uuid.uuid4().hex[:8]}")
                try:
                    self.dir.rename(stale)
                except FileNotFoundError:
                    pass
                print(f"ci-strict: reclaimed a stale lock from invocation "
                      f"{(owner or {}).get('id', '?')} (moved to {stale.name})"
                      + (f"; its recorded process group(s) {groups} have no members left" if groups else ""),
                      file=sys.stderr)
                continue
            (self.dir / "owner.json").write_text(json.dumps(
                {"pid": os.getpid(), "id": self.invocation,
                 "started": datetime.datetime.now(datetime.timezone.utc).isoformat()}))
            self.held = True
            return True, None
        return False, self.owner()

    def blocking_record(self):
        """(groups, problem). No record: ([], None). A valid record: its
        groups and None. A record whose groups cannot be determined
        (unreadable, not JSON, no non-empty list, an id that is not an
        integer above 1): (None, why). An id of 0, 1 or below would make
        killpg address this process's own group or every process."""
        path = self.dir / "unstopped.json"
        try:
            text = path.read_text()
        except FileNotFoundError:
            return [], None
        except OSError as e:
            return None, f"{path} cannot be read: {e}"
        try:
            data = json.loads(text)
        except ValueError as e:
            return None, f"{path} is not valid JSON: {e}"
        groups = data.get("unstopped_groups") if isinstance(data, dict) else None
        if not isinstance(groups, list) or not groups:
            return None, f"{path} has no non-empty unstopped_groups list"
        bad = [g for g in groups if type(g) is not int or g <= 1]
        if bad:
            return None, f"{path} names invalid process group id(s) {bad}"
        return groups, None

    def owner(self):
        try:
            return json.loads((self.dir / "owner.json").read_text())
        except (OSError, ValueError):
            return None

    def release(self):
        """Remove the lock, unless it records a process group that survived
        SIGKILL: then it stays, so the next run checks that group first."""
        if self.held and not (self.dir / "unstopped.json").exists():
            shutil.rmtree(self.dir, ignore_errors=True)
        self.held = False


def write_atomic(path, data):
    """Write data as JSON to path through a temporary file in the same
    directory and a rename, so a reader sees the old file or the whole new one."""
    tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def check_result(path, expect_id=None, probe=None, readiness=False):
    """Return (ok, message). ok only for a finished, well-formed, COMPLETE
    result, for the expected invocation and the current state. Anything
    missing, partial, mismatched or stale is not success.

    A commit-mode result is matched to HEAD alone: it tested committed files
    only, so the working tree cannot change what it proves. A development
    result is matched to the full working-tree identity. With readiness,
    only a commit-mode result is accepted (bugs/OW-124)."""
    try:
        r = json.loads(Path(path).read_text())
    except FileNotFoundError:
        return False, f"{path}: no result; the run did not finish"
    except (OSError, ValueError) as e:
        return False, f"{path}: unreadable result: {e}"
    for k in ("id", "verdict", "exit", "finished", "commit", "tree"):
        if k not in r:
            return False, f"{path}: result lacks {k!r}"
    if expect_id and r["id"] != expect_id:
        return False, f"{path}: result is from invocation {r['id']}, not {expect_id}"
    mode = r.get("mode", "development")
    if readiness and mode != "commit":
        return False, (f"{path}: a {mode} result tested working-tree changes; it is not readiness "
                       "evidence for a commit. Run scripts/ci-strict.py --commit")
    if probe is not None:
        if mode == "commit":
            _, head = probe.capture(["git", "rev-parse", "HEAD"])
            if r["commit"] != head:
                return False, f"{path}: result is for commit {r['commit'][:12]}, not HEAD {head[:12]}"
            _, tree = probe.capture(["git", "rev-parse", r["commit"] + "^{tree}"])
            if r["tree"] != tree:
                return False, (f"{path}: result records tree {str(r['tree'])[:12]}, but commit "
                               f"{r['commit'][:12]}'s tree is {tree[:12]}")
        else:
            commit, tree = tree_identity(probe)
            if (r["commit"], r["tree"]) != (commit, tree):
                return False, f"{path}: result describes a different tree than the one checked out"
    if r["verdict"] != "complete" or r["exit"] != EXIT_COMPLETE:
        return False, f"{path}: verdict {r['verdict'].upper()} (exit {r['exit']})"
    scope = (f"commit {r['commit'][:12]} only" if mode == "commit"
             else f"commit {r['commit'][:12]} plus working-tree changes")
    return True, f"{path}: COMPLETE ({mode}: {scope}), invocation {r['id']}, finished {r['finished']}"


# ------------------------------------------------------------------- main

def strict(probe, allow, out=print, mode="development"):
    invocation = uuid.uuid4().hex
    state = state_dir(probe)
    lock = Lock(state, probe, invocation)
    ok, owner = lock.acquire()
    if not ok and (owner or {}).get("invalid_record"):
        out(f"ci-strict: REFUSED. The lock ({lock.dir}) carries a blocking record whose process groups cannot "
            f"be determined: {owner['invalid_record']}. The lock is not reclaimed automatically. Check that no "
            "process from that run is still running, then remove the lock by hand. Nothing ran.")
        return EXIT_REFUSED
    if not ok and (owner or {}).get("unstopped"):
        out(f"ci-strict: REFUSED. Process group(s) {owner['unstopped']} from invocation {owner.get('id', '?')} "
            f"survived SIGKILL and still have members; the lock ({lock.dir}) and its unstopped.json stay "
            "until they are gone. Stop those processes. Nothing ran.")
        return EXIT_REFUSED
    if not ok:
        out(f"ci-strict: REFUSED. Invocation {(owner or {}).get('id', '?')} (pid "
            f"{(owner or {}).get('pid', '?')}) is running since {(owner or {}).get('started', '?')}. "
            "Wait for it; two runs would share one test database. Nothing ran.")
        return EXIT_REFUSED
    global BLOCK_RECORD
    owned = []  # temporary directories this run must remove, from the moment they exist
    UNSTOPPED.clear()
    BLOCK_RECORD = lock.dir / "unstopped.json"
    finished = False
    probe = Guarded(probe)
    try:
        started = datetime.datetime.now(datetime.timezone.utc).isoformat()
        rundir = state / "runs" / invocation
        rundir.mkdir(parents=True)
        # Defaults for a run that stops before it gets this far.
        working, tested, commit, tree, export = {}, "nothing: the run stopped first", "", "", None
        gates, tests, unaccepted, verdict = [], None, [], None
        try:
            working = working_tree_state(probe)
            uncommitted = sum(len(v) for v in working.values())
            gp = probe  # the checkout the gates run in
            export = None
            if mode == "commit":
                _, commit = probe.capture(["git", "rev-parse", "HEAD"])
                _, tree = probe.capture(["git", "rev-parse", "HEAD^{tree}"])
                tested = f"commit {commit}: committed files only, in a clean export"
                out(f"ci-strict: invocation {invocation}, COMMIT MODE: testing commit {commit[:12]}'s "
                    f"committed files only, in a clean export; results in {rundir}")
                if uncommitted:
                    out(f"  not tested: {uncommitted} uncommitted, untracked or ignored source file(s) in this "
                        "checkout")
                try:
                    dest = export_commit(probe, commit, owned)
                except RuntimeError as e:
                    export = {"method": "git clone --shared", "outcome": "failed", "detail": str(e)}
                    out(f"ci-strict: could not export commit {commit[:12]}: {e}")
                else:
                    gp = probe.at(dest)
                    out("== export: npm ci in the export's frontend")
                    npm_log = rundir / "npm-ci.log"
                    deps = gp.run(["npm", "ci", "--prefer-offline", "--no-audit", "--no-fund"], cwd=dest / "frontend",
                                  stdout=npm_log, merge_stderr=True)
                    export = {"method": "git clone --shared", "outcome": "exported",
                              "dependencies": "installed" if deps == 0 else f"failed: npm ci exited {deps}",
                              "dependencies_log": str(npm_log)}
                    if deps != 0:
                        out(f"ci-strict: npm ci exited {deps}; its output is in {npm_log}. The last lines:")
                        tail = npm_log.read_text(errors="replace").splitlines()[-20:] if npm_log.is_file() else []
                        for line in tail:
                            out(f"  | {line}")
            else:
                commit, tree = tree_identity(probe)
                tested = f"commit {commit} plus this checkout's working-tree changes"
                out(f"ci-strict: invocation {invocation}, DEVELOPMENT MODE: testing commit {commit[:12]} plus this "
                    f"checkout's working-tree changes; results in {rundir}")
                out(f"  includes {len(working['changed_tracked'])} changed tracked, {len(working['untracked'])} "
                    f"untracked and {len(working['ignored_check_inputs'])} ignored source file(s). Not readiness "
                    "evidence for any commit; for that run with --commit.")
                for p in working["ignored_check_inputs"]:
                    out(f"  ignored source on disk, read by the gates: {p}")

            # A commit run whose export or dependency install failed runs no gate,
            # and neither can be COMPLETE. A failed export is INCOMPLETE. A failed
            # `npm ci` is FAILED: the run tried to install and could not. Its exit
            # code alone does not say why (the lockfile, an install script, the
            # registry, the network, the disk), so the code and npm's output are
            # recorded and nothing is inferred from them.
            stop = None
            if export is not None and export["outcome"] == "failed":
                stop = (EXIT_INCOMPLETE, f"the export failed: {export['detail']}", ["export"])
            elif export is not None and export["dependencies"] != "installed":
                stop = (EXIT_FAILED, f"dependency installation in the export failed: {export['dependencies']}", [])
            if stop is not None:
                verdict, reason, unaccepted = stop
                gates = [{"gate": g, "outcome": "not run", "reason": reason} for g, _ in GATES]
                tests = summarize_streams(rundir)
                out(f"ci-strict: {reason}. No gate ran.")
            else:
                pre = preflight(gp)
                out("preflight:")
                for name, (good, detail) in pre.items():
                    out(f"  {'ok     ' if good else 'MISSING'} {name}: {detail}")
                missing = {n for n, (good, _) in pre.items() if not good}
                needs_of = dict(GATES)
                # A gate whose prerequisites are missing is blocked. It is an accepted
                # gap only if the gate, or every missing prerequisite it needs, was
                # named in --allow-not-run. Any unaccepted block stops the run here,
                # before expensive work.
                blocked = {g for g, needs in GATES if missing & set(needs)}
                accepted = {g for g in blocked if g in allow or (missing & set(needs_of[g])) <= allow}
                unaccepted_gates = sorted(blocked - accepted)
                unaccepted = sorted({n for g in unaccepted_gates for n in missing & set(needs_of[g])})
                gates = []
                if unaccepted_gates:
                    for g, _ in GATES:
                        gates.append({"gate": g, "outcome": "not run",
                                      "reason": "preflight failed" if g in blocked else "run stopped at preflight"})
                    tests = summarize_streams(rundir)
                    verdict = EXIT_INCOMPLETE
                    out(f"ci-strict: missing prerequisites block {', '.join(unaccepted_gates)}. Fix them, or accept "
                        "each gap by name with --allow-not-run (the run stays INCOMPLETE). Nothing else ran.")
                else:
                    ran = {}
                    for g, needs in GATES:
                        if missing & set(needs):
                            gates.append({"gate": g, "outcome": "not run", "accepted": True,
                                          "reason": "missing " + ", ".join(sorted(missing & set(needs)))})
                            continue
                        if g == "test-streams" and not (ran.get("go-tests") == 0 and ran.get("vitest") is not None):
                            gates.append({"gate": g, "outcome": "not run", "reason": "the test runs did not complete"})
                            continue
                        if g == "specter-coverage" and not all(ran.get(x) == 0 for x in ("go-tests", "vitest", "test-streams")):
                            gates.append({"gate": g, "outcome": "not run",
                                          "reason": "coverage is evaluated only over complete test results"})
                            continue
                        out(f"== {g}")
                        rc = run_gate(g, gp, rundir)
                        ran[g] = rc
                        gates.append({"gate": g, "outcome": "passed" if rc == 0 else "failed", "exit": rc})
                    tests = summarize_streams(rundir)
                    coverage_ran = any(x["gate"] == "specter-coverage" and x["outcome"] == "passed" for x in gates)
                    verdict = decide(gates, tests, coverage_ran)
        except StopRun as e:
            # A process group survived SIGKILL. The guard refused to start
            # the next command; nothing else starts either.
            out(f"ci-strict: {e}. No further command was started.")
            done = {g["gate"] for g in gates}
            gates += [{"gate": g, "outcome": "not run", "reason": str(e)} for g, _ in GATES if g not in done]
            tests = summarize_streams(rundir)

        if UNSTOPPED:
            # The one place this rule lives: a run beside which a process
            # group survived SIGKILL is FAILED, however far it got.
            verdict = EXIT_FAILED
        result = {
            "id": invocation, "mode": mode, "tested": tested, "working_tree": working,
            "commit": commit, "tree": tree, "started": started,
            "finished": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "verdict": VERDICTS[verdict], "exit": verdict, "gates": gates, "tests": tests,
            "accepted_gaps": sorted(allow), "unaccepted_missing": unaccepted,
        }
        if export is not None:
            result["export"] = export
        if UNSTOPPED:
            result["cleanup"] = {"unstopped_groups": list(UNSTOPPED), "record": str(BLOCK_RECORD)}
        write_atomic(rundir / "result.json", result)
        write_atomic(state / "latest.json", {"id": invocation, "result": str(rundir / "result.json")})

        out("")
        out(f"tests: {tests['passed']} passed, {tests['failed']} failed, {sum(tests['not_run'].values())} not run")
        for reason, n in sorted(tests["not_run"].items()):
            tag = "also skipped on hosted CI" if reason in HOSTED_SKIPS else "NOT skipped on hosted CI"
            out(f"  not run ({n}, {tag}): {reason}")
        for g in gates:
            if g["outcome"] != "passed":
                out(f"  gate {g['outcome']}: {g['gate']}" + (f" ({g['reason']})" if g.get("reason") else "")
                    + (" [accepted gap]" if g.get("accepted") else ""))
        out(f"result: {rundir / 'result.json'}")
        scope = (f"commit {commit[:12]}'s committed files only" if mode == "commit"
                 else f"commit {commit[:12]} plus working-tree changes; not readiness evidence")
        word = {EXIT_COMPLETE: f"LOCAL CI COMPLETE ({mode}: {scope}): every required gate ran and passed.",
                EXIT_FAILED: "LOCAL CI FAILED.",
                EXIT_INCOMPLETE: "LOCAL CI INCOMPLETE: nothing failed, but required gates or tests did not run. "
                                 "This run is not equivalent to hosted CI."}[verdict]
        out(f"{word} (exit {verdict})")
        finished = True
        return verdict
    finally:
        BLOCK_RECORD = None
        with shielded(propagating=not finished):
            if UNSTOPPED:
                # Normally written as each group was recorded; written again
                # here from UNSTOPPED itself, so the lock blocks the next run
                # however the list was filled.
                write_atomic(lock.dir / "unstopped.json", {
                    "unstopped_groups": list(UNSTOPPED),
                    "recorded": datetime.datetime.now(datetime.timezone.utc).isoformat()})
                # A command's process group survived SIGKILL. Its processes may
                # still use the export and the test database, so the export
                # stays, and the lock stays until those groups are empty.
                out(f"ci-strict: process group(s) {UNSTOPPED} did not exit after SIGKILL. The lock "
                    f"({lock.dir}, with unstopped.json) and the export(s) {[str(d) for d in owned]} are left "
                    "in place. No run can take the lock while those groups have members; stop those "
                    "processes, and remove the export(s).")
            else:
                for d in owned:
                    shutil.rmtree(d, ignore_errors=True)
                lock.release()


def cleanup_on_sigterm():
    """Turn SIGTERM and SIGHUP into SystemExit, so the running command's
    process group is stopped and strict()'s `finally` removes the export and
    releases the lock, as already happens for SIGINT's KeyboardInterrupt.
    SIGHUP is included because commands run in sessions of their own and no
    longer receive the terminal's hangup themselves. SIGKILL cannot be
    caught: it leaves the export, the lock (which the next run reclaims
    because its owner's pid is dead) and the running command's group."""
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda signum, _frame: sys.exit(128 + signum))


def main(argv=None):
    ap = argparse.ArgumentParser(description="Strict local CI. Exit 0 complete, 1 failed, "
                                             "3 incomplete, 4 refused.")
    ap.add_argument("--allow-not-run", action="append", default=[], metavar="GATE",
                    help="accept a named gate (or prerequisite) not running; the run stays INCOMPLETE")
    ap.add_argument("--commit", action="store_true",
                    help="test HEAD's committed files only, in a clean export (readiness evidence); with "
                         "--check-result, accept only such a result for HEAD")
    ap.add_argument("--check-result", metavar="FILE",
                    help="check a result file: exit 0 only for a finished COMPLETE result for this tree")
    ap.add_argument("--expect-id", help="with --check-result: the invocation the result must belong to")
    args = ap.parse_args(argv)
    probe = Probe()
    if args.check_result:
        ok, msg = check_result(args.check_result, args.expect_id, probe, readiness=args.commit)
        print(msg)
        return 0 if ok else 1
    known = {g for g, _ in GATES} | {n for _, needs in GATES for n in needs}
    bad = [a for a in args.allow_not_run if a not in known]
    if bad:
        print(f"ci-strict: unknown gate or prerequisite {bad}; known: {sorted(known)}", file=sys.stderr)
        return EXIT_REFUSED
    cleanup_on_sigterm()
    return strict(probe, set(args.allow_not_run), mode="commit" if args.commit else "development")


if __name__ == "__main__":
    sys.exit(main())
