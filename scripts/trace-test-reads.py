#!/usr/bin/env python3
"""Trace which tracked files the test suites read, and report documentation-path gaps.

    python3 -S scripts/trace-test-reads.py run --out DIR [--go-packages PATTERN ...]
        [--go-flags="-p 4 -timeout 1800s"]   (the = form: the value starts with -)
    python3 -S scripts/trace-test-reads.py report --out DIR

A diagnostic, never a gate. It runs weekly and on demand (.github/workflows/
trace-test-reads.yml), outside the required checks and the release gates.

The question it answers: Go CI's documentation path (release-ci-gates C-18)
runs only packaging/tests and the Python checks when a change touches nothing
in go-ci.yml's code, spec, tooling and CI pattern. If a test outside that
selection reads a file the pattern treats as documentation, a change to that
file alone would skip the test that reads it. Those files are the gaps.

run executes, with test-result caching off (go test -count=1):
  - every Go test binary under strace, through go test -exec;
  - every scripts/test_*.py, and the frontend's Vitest suite, under strace.
strace -f follows subprocesses (bash, git, make, python), and -y prints the
path behind each file descriptor, so a successful open is recorded with the
path the kernel resolved. Each suite's raw trace, the go test -json stream
and every exit status are kept.

report reads go-ci.yml's pattern at run time (there is one copy, the
workflow's), lists the tracked files, and writes report.md and report.json:
  - Gaps: tracked documentation files opened by a suite the documentation
    path does not run. A gap makes report exit 1, so the run shows failed and
    is triaged; it never blocks a pull request.
  - Not exercised: every skipped Go test with its reason, packages with no
    test files, packages and suites that failed, and suites that did not run.
  - Informational: tracked files nothing opened.
  - Completeness: go test's own result apart from each package's. The trace is
    incomplete when go test timed out or stopped without a failed package to
    account for it, a started package has no result, or a package or suite
    failed or did not run. report exits 1 for gaps, else 3 when incomplete.

Limits it cannot overcome, stated in every report:
  - It sees only reads that happened. Skipped tests, branches that did not
    run, and reads through git (git show, ls-tree, cat-file) never open the
    working-tree path, so they are invisible.
  - A read of a copy (a test that clones or copies the tree to a temporary
    directory first) is recorded under the copy's path, not the tracked file.
  - A change to a helper, configuration or dependency can change what tests
    read without any test changing; a weekly run sees that drift late.
  - The result is evidence of observed reads, not proof of every dependency.

Spec: ci-test-read-trace.
"""

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
WORKFLOW = REPO / ".github" / "workflows" / "go-ci.yml"
STRACE = ["strace", "-f", "-qq", "-y", "-e", "trace=open,openat,openat2,execve"]

# The suites the documentation path runs (go-ci.yml, docs-tests). A read by
# any other suite is outside its selection.
DOCS_PATH_SUITES = ("go:./packaging/tests", "python:")

LIMITS = [
    "It sees only reads that happened. Skipped tests, branches that did not run, and reads "
    "through git (git show, ls-tree, cat-file) never open the working-tree path, so they are "
    "invisible.",
    "A read of a copy (a test that clones or copies the tree to a temporary directory first) "
    "is recorded under the copy's path, not the tracked file.",
    "A change to a helper, configuration or dependency can change what tests read without any "
    "test changing; a weekly run sees that drift late.",
    "The result is evidence of observed reads, not proof of every dependency.",
]


class TraceError(Exception):
    pass


# ----------------------------------------------------------------- parsing

# A successful open, with -y: `= 3</abs/path>`. A resumed call carries the
# result on its own line. execve returns 0 and names its program as the first
# argument.
_OPEN_OK = re.compile(r'\b(?:open|openat|openat2)\(.*?\)\s+=\s+\d+<(.+)>\s*$')
_RESUMED_OK = re.compile(r'<\.\.\. (?:open|openat|openat2) resumed>.*?\)\s+=\s+\d+<(.+)>\s*$')
_EXEC_OK = re.compile(r'\bexecve\("((?:[^"\\]|\\.)*)",.*\)\s+=\s+0\s*$')


def _unescape(s):
    # strace escapes non-printing bytes as \xNN and quotes as \"; -y paths
    # are printed the same way.
    return re.sub(r'\\x([0-9a-fA-F]{2})|\\(.)',
                  lambda m: chr(int(m.group(1), 16)) if m.group(1) else m.group(2), s)


def opened_paths(lines):
    """Absolute paths successfully opened or executed, from strace -f -y output."""
    out = set()
    for line in lines:
        line = line.rstrip("\n")
        m = _OPEN_OK.search(line) or _RESUMED_OK.search(line)
        if m:
            out.add(_unescape(m.group(1)))
            continue
        m = _EXEC_OK.search(line)
        if m and m.group(1).startswith("/"):
            out.add(_unescape(m.group(1)))
    return out


def code_pattern(workflow_text):
    """go-ci.yml's code, spec, tooling and CI pattern, from its selector step."""
    found = re.findall(r"grep -qE '([^']+)' <<<\"\$changed\"", workflow_text)
    if len(found) != 1:
        raise TraceError("go-ci.yml has %d selector patterns, not one; the documentation path "
                         "cannot be classified" % len(found))
    return re.compile(found[0])


def go_events(stream_lines):
    """(skipped [(pkg, test, reason)], no-test packages, failed packages, incomplete
    packages) from go test -json. A package is incomplete when it has events but no
    package-level pass, fail or skip: it started and never finished."""
    skipped, notests, failed = [], set(), set()
    started, finished = set(), set()
    output = {}
    for line in stream_lines:
        try:
            e = json.loads(line)
        except ValueError:
            continue
        pkg, test, action = e.get("Package", ""), e.get("Test"), e.get("Action")
        if pkg:
            started.add(pkg)
            if test is None and action in ("pass", "fail", "skip"):
                finished.add(pkg)
        if action == "output":
            text = e.get("Output", "")
            output.setdefault((pkg, test), []).append(text)
            if test is None and "[no test files]" in text:
                notests.add(pkg)
        elif action == "skip" and test:
            lines = [l.strip() for l in output.get((pkg, test), [])
                     if l.strip() and not l.strip().startswith(("=== ", "--- SKIP"))]
            skipped.append((pkg, test, lines[-1] if lines else "(no reason printed)"))
        elif action == "fail" and test is None:
            failed.add(pkg)
    return skipped, sorted(notests), sorted(failed), sorted(started - finished)


# ------------------------------------------------------------------ report

def suite_of(name):
    return name[:-len(".trace")] if name.endswith(".trace") else name


def in_docs_path(suite):
    return any(suite == p or (p.endswith(":") and suite.startswith(p)) for p in DOCS_PATH_SUITES)


def build_report(out_dir, repo=None):
    repo = repo or REPO
    out = Path(out_dir)
    manifest_path = out / "manifest.json"
    if not manifest_path.is_file():
        raise TraceError("%s has no manifest.json; run `run` first" % out)
    manifest = json.loads(manifest_path.read_text())
    pattern = code_pattern((Path(repo) / ".github" / "workflows" / "go-ci.yml").read_text())
    tracked = [p for p in subprocess.run(["git", "-C", str(repo), "ls-files", "-z"],
                                         capture_output=True, check=True).stdout.decode()
               .split("\0") if p]
    root = str(Path(repo).resolve()) + "/"
    readers = {}  # tracked path -> sorted suites that opened it
    for suite in manifest["suites"]:
        for trace in suite["traces"]:
            with open(out / trace, encoding="utf-8", errors="replace") as f:
                for path in opened_paths(f):
                    if path.startswith(root):
                        readers.setdefault(path[len(root):], set()).add(suite["name"])
    tracked_set = set(tracked)
    docs = {p for p in tracked if not pattern.search(p)}
    gaps = []
    for path in sorted(docs):
        outside = sorted(s for s in readers.get(path, ()) if not in_docs_path(s))
        if outside:
            gaps.append({"path": path, "read_by": outside})
    unread = sorted(p for p in tracked if p not in readers)
    skipped, notests, failed, unfinished = [], [], [], []
    stream = out / "go-test.json"
    if stream.is_file():
        with open(stream, encoding="utf-8", errors="replace") as f:
            skipped, notests, failed, unfinished = go_events(f)
    other = [s for s in manifest["suites"] if s.get("kind") != "go"]
    not_run = [s["name"] for s in other if s.get("exit") is None]
    failed_suites = [s["name"] for s in other if s.get("exit") not in (None, 0)]
    # The overall go test result, apart from each package's. A nonzero exit
    # that no failed package accounts for (a build or module error before any
    # package ran) or a timeout means Go coverage is missing, not failed.
    go_exit = manifest.get("go_exit")
    incomplete = []
    if go_exit == "timeout":
        incomplete.append("go test timed out")
    elif go_exit is None:
        incomplete.append("go test did not run")
    elif go_exit != 0 and not failed:
        incomplete.append("go test exited %s and no package failed: it stopped before or "
                          "outside the packages" % go_exit)
    if unfinished:
        incomplete.append("%d package(s) started without a result: %s" % (
            len(unfinished), ", ".join(unfinished)))
    if failed:
        incomplete.append("%d package(s) failed, so their reads may be cut short" % len(failed))
    if failed_suites:
        incomplete.append("suite(s) failed: %s" % ", ".join(failed_suites))
    if not_run:
        incomplete.append("suite(s) did not run: %s" % ", ".join(not_run))
    report = {
        "commit": manifest.get("commit"), "pattern": pattern.pattern,
        "tracked": len(tracked), "documentation_files": len(docs),
        "read": len([p for p in readers if p in tracked_set]),
        "gaps": gaps,
        "go_test": {"exit": go_exit},
        "incomplete": incomplete,
        "not_exercised": {"skipped_tests": [{"package": p, "test": t, "reason": r}
                                            for p, t, r in skipped],
                          "no_test_files": notests, "failed_packages": failed,
                          "unfinished_packages": unfinished,
                          "failed_suites": failed_suites, "suites_not_run": not_run},
        "unread": unread, "limits": LIMITS,
    }
    (out / "report.json").write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    # The opened tracked files per suite: a small, derived index of the raw
    # traces, which stay authoritative.
    index = {}
    for path, suites in readers.items():
        if path in tracked_set:
            for name in suites:
                index.setdefault(name, []).append(path)
    (out / "index.json").write_text(json.dumps({k: sorted(v) for k, v in sorted(index.items())},
                                               indent=1) + "\n")
    (out / "report.md").write_text(render(report))
    return report


def render(r):
    ne = r["not_exercised"]
    md = ["# Test read trace", "",
          "A diagnostic, not a gate. Commit `%s`." % r["commit"], "",
          "%d tracked files; %d are documentation by go-ci.yml's pattern; %d were read." % (
              r["tracked"], r["documentation_files"], r["read"]), "",
          "## Completeness", "",
          "go test exit: %s." % r["go_test"]["exit"], ""]
    md += (["**Incomplete trace.** Coverage is missing, so an absence of gaps proves less:", ""]
           + ["- %s" % i for i in r["incomplete"]]) if r["incomplete"] else [
        "Complete: every suite ran and every started package finished."]
    md += ["", "## Gaps (%d)" % len(r["gaps"]), "",
          "A documentation file read by a suite the documentation path does not run. A change "
          "to it alone would skip that suite.", ""]
    md += ["- `%s`: %s" % (g["path"], ", ".join(g["read_by"])) for g in r["gaps"]] or ["None."]
    md += ["", "## Not exercised", "",
           "- Skipped Go tests: %d" % len(ne["skipped_tests"])]
    md += ["  - `%s` %s: %s" % (s["package"], s["test"], s["reason"]) for s in ne["skipped_tests"]]
    md += ["- Packages with no test files: %d" % len(ne["no_test_files"]),
           "- Failed packages: %s" % (", ".join(ne["failed_packages"]) or "none"),
           "- Packages started without a result: %s" % (
               ", ".join(ne["unfinished_packages"]) or "none"),
           "- Failed suites: %s" % (", ".join(ne["failed_suites"]) or "none"),
           "- Suites that did not run: %s" % (", ".join(ne["suites_not_run"]) or "none"),
           "", "## Informational", "",
           "%d tracked files were not opened by any suite (listed in report.json)." % len(
               r["unread"]), "", "## Limits", ""]
    md += ["- %s" % l for l in r["limits"]]
    return "\n".join(md) + "\n"


# --------------------------------------------------------------------- run

def run(out_dir, go_packages, go_flags=(), repo=None, timeout=5400):
    repo = repo or REPO
    out = Path(out_dir)
    if out.exists() and any(out.iterdir()):
        raise TraceError("%s is not empty; a trace is never mixed with another" % out)
    out.mkdir(parents=True, exist_ok=True)
    traces = out / "traces"
    traces.mkdir()
    commit = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True,
                            text=True, check=True).stdout.strip()
    suites = []

    def traced(name, argv, cwd, env=None):
        trace = "traces/%s.trace" % re.sub(r"[^A-Za-z0-9_.-]", "_", name)
        cmd = STRACE + ["-o", str(out / trace), "--"] + argv
        with open(out / ("traces/%s.out" % os.path.basename(trace)[:-6]), "wb") as log:
            try:
                rc = subprocess.run(cmd, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT,
                                    timeout=timeout).returncode
            except subprocess.TimeoutExpired:
                rc = "timeout"
        suites.append({"name": name, "argv": argv, "exit": rc, "traces": [trace]})

    # Go: each test binary under strace, through -exec. The wrapper names its
    # trace after the binary's working directory, which go test sets to the
    # package directory, and records that directory beside it.
    wrapper = out / "go-exec-strace.sh"
    wrapper.write_text("#!/bin/sh\nset -u\nt=\"%s/go.$(printf %%s \"$PWD\" | tr -c 'A-Za-z0-9' _)"
                       ".$$\"\nprintf '%%s\\n' \"$PWD\" > \"$t.pwd\"\nexec %s -o \"$t.trace\" -- "
                       "\"$@\"\n" % (traces, " ".join(shlex.quote(a) for a in STRACE)))
    wrapper.chmod(0o755)
    with open(out / "go-test.json", "wb") as stream:
        try:
            go_rc = subprocess.run(["go", "test", "-count=1", "-json", "-exec", str(wrapper)]
                                   + list(go_flags) + go_packages, cwd=repo, stdout=stream,
                                   stderr=subprocess.STDOUT, timeout=timeout).returncode
        except subprocess.TimeoutExpired:
            go_rc = "timeout"
    for pwd_file in sorted(traces.glob("go.*.pwd")):
        pkg_dir = pwd_file.read_text().strip()
        rel = os.path.relpath(pkg_dir, repo)
        # A Go package's pass or failure is read from go-test.json, never
        # from go test's overall exit status, which one package decides.
        suites.append({"name": "go:./" + rel, "kind": "go",
                       "traces": ["traces/" + pwd_file.name[:-4] + ".trace"]})
    for script in sorted((Path(repo) / "scripts").glob("test_*.py")):
        traced("python:" + script.name, [sys.executable, "-S", str(script)], repo)
    if (Path(repo) / "frontend" / "node_modules").is_dir():
        traced("vitest", ["npx", "vitest", "run"], Path(repo) / "frontend")
    else:
        suites.append({"name": "vitest", "exit": None, "traces": [],
                       "reason": "frontend/node_modules is absent; run npm ci first"})
    (out / "manifest.json").write_text(json.dumps(
        {"commit": commit, "go_exit": go_rc, "suites": suites}, indent=1, sort_keys=True) + "\n")
    return suites


def main(argv=None, out=sys.stdout):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="step")
    r = sub.add_parser("run")
    r.add_argument("--out", required=True)
    r.add_argument("--go-packages", nargs="+", default=["./..."])
    r.add_argument("--go-flags", default="", help="more go test flags, such as -p 4 -timeout 1800s")
    s = sub.add_parser("report")
    s.add_argument("--out", required=True)
    a = p.parse_args(argv)
    if a.step is None:
        p.print_help(sys.stderr)
        return 2
    try:
        if a.step == "run":
            if "-count" in a.go_flags or "-exec" in a.go_flags:
                raise TraceError("--go-flags may not set -count or -exec; caching stays off and "
                                 "every binary stays traced")
            suites = run(a.out, a.go_packages, shlex.split(a.go_flags))
            out.write("traced %d suites into %s\n" % (len(suites), a.out))
            return 0
        rep = build_report(a.out)
        out.write("%d gaps; %s; report in %s\n" % (
            len(rep["gaps"]), "INCOMPLETE" if rep["incomplete"] else "complete",
            os.path.join(a.out, "report.md")))
        # Both fail the diagnostic run visibly; neither is a required check.
        if rep["gaps"]:
            return 1
        return 3 if rep["incomplete"] else 0
    except (TraceError, OSError, subprocess.CalledProcessError) as e:
        out.write("trace-test-reads: %s\n" % e)
        return 2


if __name__ == "__main__":
    sys.exit(main())
