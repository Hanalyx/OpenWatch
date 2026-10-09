#!/usr/bin/env python3
"""Strict local CI: the final local gate for one revision.

    python3 -S scripts/ci-strict.py [--allow-not-run GATE ...]
    python3 -S scripts/ci-strict.py --check-result FILE [--expect-id ID]

It reports what actually ran and makes no claim about whether to push.

Exit codes, from this script (authoritative; `make ci-strict` is a wrapper,
and make turns every failure into exit 2):

  0  COMPLETE    every required gate ran and passed, and the only tests not
                 run are the opt-ins that hosted CI skips too
  1  FAILED      a gate or a test failed
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

Results live under `$(git rev-parse --git-dir)/ci-strict/`, outside the
working tree, so no test that walks the repository can see them. Each
invocation writes only `runs/<its id>/`; nothing deletes another's.

Standard library only.
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
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

    def which(self, name):
        return shutil.which(name, path=self.env.get("PATH"))

    def run(self, cmd, cwd=None, env=None, stdout=None):
        """Run cmd; return its exit code. Output goes to the terminal unless
        stdout names a file."""
        e = dict(self.env)
        e.update(env or {})
        if stdout:
            with open(stdout, "wb") as out:
                return subprocess.run(cmd, cwd=cwd or self.repo, env=e, stdout=out).returncode
        return subprocess.run(cmd, cwd=cwd or self.repo, env=e).returncode

    def capture(self, cmd, cwd=None):
        p = subprocess.run(cmd, cwd=cwd or self.repo, env=self.env,
                           capture_output=True, text=True)
        return p.returncode, (p.stdout + p.stderr).strip()

    def tcp_open(self, host, port):
        try:
            with socket.create_connection((host, port), timeout=3):
                return True
        except OSError:
            return False

    def pid_alive(self, pid):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True


# -------------------------------------------------------------- preflight

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
    ("go-tests", ("toolchain", "test-database", "packaging-tools")),
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
    env = {"OPENWATCH_PACKAGING_BUILD": "1", "OPENWATCH_KENSA_RULES_DIR": kensa + "/rules"}
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


def tree_identity(probe):
    """The commit and a digest of every uncommitted change, so a result can
    be matched to the tree it describes."""
    _, head = probe.capture(["git", "rev-parse", "HEAD"])
    h = hashlib.sha256()
    for cmd in (["git", "diff", "HEAD", "--binary", "--no-ext-diff"],
                ["git", "ls-files", "--others", "--exclude-standard"]):
        _, text = probe.capture(cmd)
        h.update(text.encode())
        h.update(b"\0")
    return head, h.hexdigest()


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
                      f"{(owner or {}).get('id', '?')} (moved to {stale.name})", file=sys.stderr)
                continue
            (self.dir / "owner.json").write_text(json.dumps(
                {"pid": os.getpid(), "id": self.invocation,
                 "started": datetime.datetime.now(datetime.timezone.utc).isoformat()}))
            self.held = True
            return True, None
        return False, self.owner()

    def owner(self):
        try:
            return json.loads((self.dir / "owner.json").read_text())
        except (OSError, ValueError):
            return None

    def release(self):
        if self.held:
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


def check_result(path, expect_id=None, probe=None):
    """Return (ok, message). ok only for a finished, well-formed, COMPLETE
    result, for the expected invocation and the current tree. Anything
    missing, partial, mismatched or stale is not success."""
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
    if probe is not None:
        commit, tree = tree_identity(probe)
        if (r["commit"], r["tree"]) != (commit, tree):
            return False, f"{path}: result describes a different tree than the one checked out"
    if r["verdict"] != "complete" or r["exit"] != EXIT_COMPLETE:
        return False, f"{path}: verdict {r['verdict'].upper()} (exit {r['exit']})"
    return True, f"{path}: COMPLETE, invocation {r['id']}, finished {r['finished']}"


# ------------------------------------------------------------------- main

def strict(probe, allow, out=print):
    invocation = uuid.uuid4().hex
    state = state_dir(probe)
    lock = Lock(state, probe, invocation)
    ok, owner = lock.acquire()
    if not ok:
        out(f"ci-strict: REFUSED. Invocation {(owner or {}).get('id', '?')} (pid "
            f"{(owner or {}).get('pid', '?')}) is running since {(owner or {}).get('started', '?')}. "
            "Wait for it; two runs would share one test database. Nothing ran.")
        return EXIT_REFUSED
    try:
        started = datetime.datetime.now(datetime.timezone.utc).isoformat()
        commit, tree = tree_identity(probe)
        rundir = state / "runs" / invocation
        rundir.mkdir(parents=True)
        out(f"ci-strict: invocation {invocation} on {commit[:12]}; results in {rundir}")

        pre = preflight(probe)
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
                rc = run_gate(g, probe, rundir)
                ran[g] = rc
                gates.append({"gate": g, "outcome": "passed" if rc == 0 else "failed", "exit": rc})
            tests = summarize_streams(rundir)
            coverage_ran = any(x["gate"] == "specter-coverage" and x["outcome"] == "passed" for x in gates)
            verdict = decide(gates, tests, coverage_ran)

        result = {
            "id": invocation, "commit": commit, "tree": tree, "started": started,
            "finished": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "verdict": VERDICTS[verdict], "exit": verdict, "gates": gates, "tests": tests,
            "accepted_gaps": sorted(allow), "unaccepted_missing": unaccepted,
        }
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
        word = {EXIT_COMPLETE: "LOCAL CI COMPLETE: every required gate ran and passed.",
                EXIT_FAILED: "LOCAL CI FAILED.",
                EXIT_INCOMPLETE: "LOCAL CI INCOMPLETE: nothing failed, but required gates or tests did not run. "
                                 "This run is not equivalent to hosted CI."}[verdict]
        out(f"{word} (exit {verdict})")
        return verdict
    finally:
        lock.release()


def main(argv=None):
    ap = argparse.ArgumentParser(description="Strict local CI. Exit 0 complete, 1 failed, "
                                             "3 incomplete, 4 refused.")
    ap.add_argument("--allow-not-run", action="append", default=[], metavar="GATE",
                    help="accept a named gate (or prerequisite) not running; the run stays INCOMPLETE")
    ap.add_argument("--check-result", metavar="FILE",
                    help="check a result file: exit 0 only for a finished COMPLETE result for this tree")
    ap.add_argument("--expect-id", help="with --check-result: the invocation the result must belong to")
    args = ap.parse_args(argv)
    probe = Probe()
    if args.check_result:
        ok, msg = check_result(args.check_result, args.expect_id, probe)
        print(msg)
        return 0 if ok else 1
    known = {g for g, _ in GATES} | {n for _, needs in GATES for n in needs}
    bad = [a for a in args.allow_not_run if a not in known]
    if bad:
        print(f"ci-strict: unknown gate or prerequisite {bad}; known: {sorted(known)}", file=sys.stderr)
        return EXIT_REFUSED
    return strict(probe, set(args.allow_not_run))


if __name__ == "__main__":
    sys.exit(main())
