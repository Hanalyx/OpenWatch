#!/usr/bin/env python3
"""Tests for the upgrade Steps 1 to 8 tool.

    python3 -S scripts/test_release_upgrade.py

The OpenWatch server is simulated: the transport is `sh -c` instead of ssh,
the file paths sit under a fake root (OW_ROOT), and openwatch, systemctl,
dnf, apt-get, rpm, pg_dump, pg_restore, psql, curl, journalctl, sudo,
hostname and stat are one fake dispatcher that keeps the server's state
(version, schema, service) in files and logs every call. The maintained phase
scripts, the capture library, the fetch and the verification are all real,
and so is the served-versus-installed comparison (python3 with a small YAML
shim). Every call is logged, so a test can show what was never run.

One class per criterion of spec release-upgrade-steps. No network.
"""

import contextlib
import io
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

_here = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("release_upgrade", _here / "release_upgrade.py")
ru = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ru)
ec = ru.ec

TAG = "v0.9.0"
COMMIT = "474d9af26e457fc6a47b5475fab87394433a687b"  # pragma: allowlist secret
TOKEN = "owk_test_token_value_never_printed_0001"  # pragma: allowlist secret
RULES = ("audit-sudo-log", "ssh-root-login", "shell-timeout")

FAKEBIN = r'''
import json, os, sys
F = os.environ["OW_FAKE"]
R = os.environ.get("OW_ROOT", "")
cmd = os.path.basename(sys.argv[0])
args = sys.argv[1:]


def st(name, default=""):
    p = os.path.join(F, name)
    return open(p).read().strip() if os.path.exists(p) else default


def put(name, value):
    with open(os.path.join(F, name), "w") as f:
        f.write(value)


def flag(name):
    return os.path.exists(os.path.join(F, name))


with open(os.path.join(F, "calls.log"), "a") as f:
    f.write(cmd + " " + " ".join(args) + "\n")

if cmd == "sudo":
    a = list(args)
    while a and a[0] == "-n":
        a.pop(0)
    if a[:1] == ["-u"]:
        a = a[2:]
    os.execvp(a[0], a)
if cmd == "hostname":
    print(st("hostname", "owas-rhn01.hanalyx.local")); sys.exit(0)
if cmd == "openwatch":
    if args == ["--version"]:
        print("openwatch " + st("version")); sys.exit(0)
    if "check-config" in args:
        if flag("check-config-fail"):
            print("config: [scan] missing key", file=sys.stderr); sys.exit(1)
        print("config valid"); sys.exit(0)
    if args[-2:] == ["migrate", "--status"]:
        print("current version " + st("schema")); sys.exit(0)
    if args[-1:] == ["migrate"]:
        if flag("migrate-pending"):
            print("applied 2 migrations; version " + st("schema")); sys.exit(0)
        print("version %s\nno migrations to run" % st("schema")); sys.exit(0)
    sys.exit(2)
if cmd == "systemctl":
    verb = args[0]
    if verb == "stop":
        put("service", "inactive"); sys.exit(0)
    if verb in ("start", "restart"):
        if flag(verb + "-fail"):
            sys.exit(1)
        put("service", "active"); sys.exit(0)
    if verb in ("is-active", "status"):
        s = st("service", "active")
        print(s); sys.exit(0 if s == "active" else 3)
    sys.exit(2)
if cmd in ("dnf", "apt-get"):
    if flag("install-fail"):
        print("Error: Transaction check error", file=sys.stderr); sys.exit(1)
    put("version", st("new-version")); put("schema", st("new-schema"))
    put("service", "inactive" if flag("scriptlet-leaves-stopped") else "active")
    open(os.path.join(R, "var/lib/openwatch/backups/openwatch-pre-upgrade.sql"), "w").close()
    print("Complete!"); sys.exit(0)
if cmd == "rpm":
    if args[:1] == ["-q"]:
        print("openwatch-%s-1.x86_64\nkensa-rules-0.10.0-1.noarch" % st("version")); sys.exit(0)
    if args[:1] == ["-V"]:
        v = st("rpm-V")
        if v:
            print(v); sys.exit(1)
        sys.exit(0)
if cmd == "pg_dump":
    if flag("pg_dump-fail"):
        print("pg_dump: error: connection refused", file=sys.stderr); sys.exit(1)
    path = [a for a in args if a.startswith("--file=")][0][len("--file="):]
    with open(path, "w") as f:
        f.write("PGDMP fake")
    sys.exit(0)
if cmd == "pg_restore":
    if not os.path.exists(args[-1]):
        sys.exit(1)
    print(";\n; Archive created\n2001; 1259 16400 TABLE public hosts"); sys.exit(0)
if cmd == "psql":
    print(" ?column?\n----------\n        1\n(1 row)"); sys.exit(0)
if cmd == "journalctl":
    print(st("journal", "openwatch: listening on :8443")); sys.exit(0)
if cmd == "curl":
    # Bodies as the server writes them (internal/server/handlers.go): GetHealth
    # answers 200 with a HealthResponse or 503 with an ErrorEnvelope, and
    # GetVersion a VersionResponse, which has no "version" field. A state file
    # health-body or version-body replaces the body verbatim.
    out = conf = wfmt = None
    fail = False
    i = 0
    while i < len(args):
        if args[i] in ("-o", "-K", "--max-time", "--connect-timeout", "-w"):
            if args[i] == "-o":
                out = args[i + 1]
            if args[i] == "-K":
                conf = args[i + 1]
            if args[i] == "-w":
                wfmt = args[i + 1]
            i += 2
            continue
        if args[i].startswith("-") and not args[i].startswith("--") and "f" in args[i]:
            fail = True
        i += 1
    url = args[-1]
    if flag("health-down"):
        sys.exit(7)
    code = 200
    if url.endswith("/api/v1/health"):
        if flag("db-down"):
            code, body = 503, {"error": {"code": "server.unavailable", "fault": "server",
                                         "retryable": True,
                                         "human_message": "database is not reachable"}}
        else:
            body = {"status": "healthy", "db_connected": True, "version": st("version")}
        body = st("health-body") or json.dumps(body, separators=(",", ":"))
        code = int(st("health-code", str(code)))
    elif url.endswith("/api/v1/version"):
        body = {"openwatch": st("version"), "kensa": "0.10.0", "go": "go1.26.5",
                "commit": "474d9af26e45", "build_time": "2026-10-01T00:00:00Z"}  # pragma: allowlist secret
        body = st("version-body") or json.dumps(body, separators=(",", ":"))
    elif url.endswith("/api/v1/rules"):
        if "Bearer " + st("token") not in (open(conf).read() if conf else ""):
            code, body = 401, '{"error":{"code":"auth.required"}}'
        else:
            body = json.dumps({"rules": [{"id": x} for x in st("served").split()]})
    else:
        code, body = 404, "{}"
    if fail and code >= 400:
        sys.exit(22)
    if out and out != "/dev/null":
        with open(out, "w") as f:
            f.write(body)
    elif not out:
        sys.stdout.write(body)
    if wfmt == "%{http_code}":
        sys.stdout.write(str(code))
    sys.exit(0)
if cmd == "stat":
    print("%s %s" % (st("token-owner", "root"), oct(os.stat(args[-1]).st_mode & 0o777)[2:]))
    sys.exit(0)
if cmd == "python3":
    env = dict(os.environ, PYTHONPATH=os.path.join(F, "shim"))
    os.execve(REAL_PYTHON, [REAL_PYTHON] + args, env)
sys.exit(99)
'''

YAML_SHIM = '''
def safe_load(f):
    out = {}
    for line in (f.read() if hasattr(f, "read") else f).splitlines():
        if ":" in line and not line.startswith((" ", "#")):
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out
'''

COMMANDS = ("sudo", "hostname", "openwatch", "systemctl", "dnf", "apt-get", "rpm", "pg_dump",
            "pg_restore", "psql", "journalctl", "curl", "stat", "python3")


def read_text(path):
    with open(path) as f:
        return f.read()


class Case(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="relupg-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.fake = os.path.join(self.dir, "fake")
        self.root = os.path.join(self.dir, "root")
        bin_ = os.path.join(self.dir, "bin")
        for d in (self.fake, bin_, os.path.join(self.fake, "shim")):
            os.makedirs(d)
        with open(os.path.join(self.fake, "shim", "yaml.py"), "w") as f:
            f.write(YAML_SHIM)
        dispatcher = os.path.join(self.dir, "fakebin.py")
        with open(dispatcher, "w") as f:
            f.write("#!%s\nREAL_PYTHON = %r\n%s" % (sys.executable, sys.executable, FAKEBIN))
        os.chmod(dispatcher, 0o755)
        for c in COMMANDS:
            os.symlink(dispatcher, os.path.join(bin_, c))
        for rel in ("etc/openwatch", "var/lib/openwatch/backups", "var/backups/openwatch",
                    "usr/share/kensa/rules/linux", "proc/sys/kernel/random", "root"):
            os.makedirs(os.path.join(self.root, rel))
        self.write("etc/openwatch/secrets.env", "OPENWATCH_DATABASE_DSN=postgres://db/x\n")
        self.write("etc/openwatch/openwatch.toml", "[server]\n")
        self.write("etc/machine-id", "35a9c078635e4d12ab707298cd170ae2\n")
        self.write("proc/sys/kernel/random/boot_id", "9f46fbda-0000\n")
        for rid in RULES:
            self.write("usr/share/kensa/rules/linux/%s.yml" % rid, "id: %s\ntitle: x\n" % rid)
        self.token_file = os.path.join(self.root, "root", "owk-token")
        self.write("root/owk-token", TOKEN + "\n", mode=0o600)
        for name, value in (("version", "0.8.4"), ("schema", "65"), ("service", "active"),
                            ("new-version", "0.9.0"), ("new-schema", "67"), ("token", TOKEN),
                            ("served", " ".join(RULES))):
            self.state(name, value)
        self.packages = []
        for name in ("openwatch-0.9.0-1.x86_64.rpm", "kensa-rules-0.10.0-1.noarch.rpm"):
            p = os.path.join(self.dir, name)
            with open(p, "wb") as f:
                f.write(("package %s\n" % name).encode())
            self.packages.append(p)
        self.old_env = dict(os.environ)
        self.addCleanup(lambda: (os.environ.clear(), os.environ.update(self.old_env)))
        os.environ.update(OW_FAKE=self.fake, OW_HEALTH_TRIES="2",
                          PATH=bin_ + os.pathsep + os.environ.get("PATH", ""))
        self.evidence = os.path.join(self.dir, "evidence")
        self.remote = os.path.join(self.dir, "remote")
        self.args = ["--host", "owas-rhn01", "--tag", TAG, "--commit", COMMIT, "--kind", "rpm",
                     "--evidence", self.evidence, "--sudo", "", "--remote-python",
                     sys.executable, "--remote-dir", self.remote, "--root", self.root,
                     "--transport", json.dumps(["sh", "-c"])]
        self.host_dir = os.path.join(self.evidence, "upgrade", "owas-rhn01")

    def write(self, rel, text, mode=0o644):
        p = os.path.join(self.root, rel)
        with open(p, "w") as f:
            f.write(text)
        os.chmod(p, mode)

    def state(self, name, value=""):
        with open(os.path.join(self.fake, name), "w") as f:
            f.write(value)

    def calls(self):
        p = os.path.join(self.fake, "calls.log")
        return read_text(p).splitlines() if os.path.exists(p) else []

    def run_phase(self, phase, *extra, execute=True):
        argv = [phase] + self.args + list(extra)
        if phase == "install":
            for p in self.packages:
                argv += ["--package", p]
        if phase == "rules":
            argv += ["--token-file", self.token_file]
        if execute and phase not in ("plan", "status"):
            argv.append("--execute")
        out = io.StringIO()
        code = ru.main(argv, out=out)
        return code, out.getvalue()

    def ok(self, phase, **kw):
        code, out = self.run_phase(phase, **kw)
        self.assertEqual(code, 0, out)
        return out

    def through(self, last):
        for p in ("plan", "backup", "install", "verify", "rules"):
            self.ok(p)
            if p == last:
                return

    def capture(self, phase):
        return os.path.join(self.host_dir, "upgrade-" + phase)

    def stdout(self, phase):
        with open(os.path.join(self.capture(phase), "stdout")) as f:
            return f.read()


class UpgradePhasesInOrder(Case):
    """AC-01: the five phases run in order, each a verified capture."""

    def test_a_full_upgrade_reaches_match(self):
        self.through("rules")
        for p in ("plan", "backup", "install", "verify", "rules"):
            rec = ec.verify_capture(self.capture(p), tag=TAG, commit=COMMIT)
            self.assertEqual(rec["exit"]["code"], 0, p)
        self.assertIn("STEP 8 DONE: MATCH", self.stdout("rules"))
        self.assertIn("served: 3 installed: 3", self.stdout("rules"))
        self.assertIn("no migrations to run", self.stdout("verify"))
        code, out = self.run_phase("status")
        self.assertIn("next: none; Step 8 reached MATCH", out)

    def test_packages_are_staged_and_checked_on_the_host(self):
        self.through("install")
        out = self.stdout("install")
        for p in self.packages:
            self.assertIn("%s/%s/upgrade/packages/%s: OK" % (self.remote, TAG,
                                                            os.path.basename(p)), out)
        installs = [c for c in self.calls() if c.startswith("dnf ")]
        self.assertEqual(len(installs), 1)
        for p in self.packages:
            self.assertIn(os.path.basename(p), installs[0])

    def test_a_dry_run_changes_nothing_and_shows_the_commands(self):
        self.ok("plan")
        before = self.calls()
        for phase in ("backup",):
            code, out = self.run_phase(phase, execute=False)
            self.assertEqual(code, 0, out)
            self.assertIn("DRY RUN", out)
            self.assertIn("pg_dump", out)
        self.assertEqual(self.calls(), before, "a dry run contacted the host")
        self.assertFalse(os.path.exists(self.capture("backup")))

    def test_the_backup_is_proven_readable(self):
        self.through("backup")
        out = self.stdout("backup")
        self.assertIn("== pg_restore --list", out)
        self.assertIn("TABLE public hosts", out)
        dumps = os.listdir(os.path.join(self.root, "var/backups/openwatch"))
        self.assertEqual(len(dumps), 1)
        self.assertRegex(dumps[0], r"^openwatch_\d{8}T\d{6}Z\.dump$")


class UpgradeGates(Case):
    """AC-02: a phase needs the previous phases verified, from the same host."""

    def assert_refused(self, phase, reason):
        before = self.calls()
        code, out = self.run_phase(phase)
        self.assertEqual(code, 1, out)
        self.assertIn(reason, out)
        self.assertEqual(self.calls(), before, "the host was contacted")

    def test_each_phase_needs_the_ones_before_it(self):
        self.assert_refused("backup", "no verified plan capture")
        self.ok("plan")
        self.assert_refused("install", "no verified backup capture")
        self.ok("backup")
        self.assert_refused("rules", "no verified install capture")

    def test_a_failed_preflight_blocks_the_backup(self):
        self.state("service", "inactive")
        code, out = self.run_phase("plan")
        self.assertEqual(code, 1)
        self.assertIn("service (exit 3)", out)
        # The preflight script fails itself, not only through the tool's reading.
        with open(os.path.join(self.capture("plan"), "exit")) as f:
            self.assertEqual(f.read(), "exit=1\n")
        self.assert_refused("backup", "plan phase on owas-rhn01 did not pass")

    def test_an_altered_backup_capture_blocks_the_install(self):
        self.through("backup")
        p = os.path.join(self.capture("backup"), "stdout")
        os.chmod(p, 0o600)
        with open(p, "a") as f:
            f.write("edited\n")
        self.assert_refused("install", "does not verify")

    def planted(self, phase, script):
        """A capture of `phase` that the host script did not write: exit 0 regardless."""
        os.makedirs(self.host_dir, exist_ok=True)
        ec.capture(["sh", "-c", script], self.host_dir, "upgrade-" + phase, TAG, COMMIT,
                   timeout=30, host=dict(ec.host_identity()))

    def test_a_capture_reporting_a_failed_step_is_refused_even_at_exit_0(self):
        self.ok("plan")
        self.planted("backup", 'echo "== pg_dump"; echo "== exit 1"; echo "BACKUP DONE"')
        self.assert_refused("install", "failed: pg_dump (exit 1)")

    def test_a_capture_without_its_done_line_is_refused(self):
        self.ok("plan")
        self.planted("backup", 'echo "== pg_dump"; echo "== exit 0"')
        self.assert_refused("install", "did not print 'BACKUP DONE'")

    def test_execute_needs_the_preflight_to_show_this_host(self):
        self.state("hostname", "owas-rhn02.hanalyx.local")
        self.ok("plan")
        self.assert_refused("backup", "not owas-rhn01")


class UpgradeStopsSafely(Case):
    """AC-03: a failed step stops the phase, and nothing starts the service by hand."""

    def assert_never_started(self):
        self.assertFalse([c for c in self.calls() if c.startswith("systemctl start")],
                         "the service was started by hand")

    def test_a_package_that_does_not_match_stops_before_the_service_is_touched(self):
        self.through("backup")
        # The digest taken here no longer matches what reaches the host, as if
        # the copy had been corrupted in transit.
        real = ec._sha256_file
        target = os.path.basename(self.packages[0])
        ec._sha256_file = lambda p: "0" * 64 if os.path.basename(p) == target else real(p)
        self.addCleanup(setattr, ec, "_sha256_file", real)
        calls_before = len(self.calls())
        code, out = self.run_phase("install")
        ec._sha256_file = real
        self.assertEqual(code, 1, out)
        with open(os.path.join(self.capture("install"), "stderr")) as f:
            self.assertIn("STOPPED at: staged packages match their digests", f.read())
        later = self.calls()[calls_before:]
        self.assertFalse([c for c in later if c.startswith(("systemctl stop", "dnf"))], later)
        self.assertEqual(read_text(os.path.join(self.fake, "service")), "active")

    def test_a_failed_install_leaves_the_service_stopped_and_blocks_verify(self):
        self.through("backup")
        self.state("install-fail")
        code, out = self.run_phase("install")
        self.assertEqual(code, 1, out)
        with open(os.path.join(self.capture("install"), "stderr")) as f:
            err = f.read()
        self.assertIn("Do not start the service by hand", err)
        self.assertEqual(read_text(os.path.join(self.fake, "service")), "inactive")
        self.assert_never_started()
        code, out = self.run_phase("verify")
        self.assertEqual(code, 1)
        self.assertIn("install phase on owas-rhn01 did not pass", out)

    def test_a_stopped_service_after_install_fails_verify_without_starting_it(self):
        self.through("backup")
        self.state("scriptlet-leaves-stopped")
        self.ok("install")
        code, out = self.run_phase("verify")
        self.assertEqual(code, 1)
        with open(os.path.join(self.capture("verify"), "stderr")) as f:
            err = f.read()
        self.assertIn("STOPPED at: Step 6: service active (exit 3)", err)
        self.assertIn("Do not start it by hand; go to Rollback", err)
        self.assert_never_started()

    def test_each_failed_verify_step_stops_verify(self):
        for flag, step in (("check-config-fail", "Step 4"), ("migrate-pending", "Step 5")):
            with self.subTest(flag=flag):
                shutil.rmtree(self.evidence, True)
                shutil.rmtree(self.remote, True)
                for f in ("check-config-fail", "migrate-pending"):
                    if os.path.exists(os.path.join(self.fake, f)):
                        os.unlink(os.path.join(self.fake, f))
                for name, value in (("version", "0.8.4"), ("schema", "65"), ("service", "active")):
                    self.state(name, value)
                self.through("install")
                self.state(flag)
                code, out = self.run_phase("verify")
                self.assertEqual(code, 1, out)
                with open(os.path.join(self.capture("verify"), "stderr")) as f:
                    self.assertIn("STOPPED at: " + step, f.read())

    def test_a_server_reporting_another_version_fails_verify(self):
        self.through("backup")
        self.state("new-version", "0.8.9")
        self.ok("install")
        code, out = self.run_phase("verify")
        self.assertEqual(code, 1)
        with open(os.path.join(self.capture("verify"), "stderr")) as f:
            err = f.read()
        self.assertIn("STOPPED at: " + HEALTH_STEP, err)
        self.assertIn("health: wrong or missing version", err)

    def test_a_failed_dump_stops_the_backup(self):
        self.ok("plan")
        self.state("pg_dump-fail")
        code, out = self.run_phase("backup")
        self.assertEqual(code, 1)
        self.assertFalse([c for c in self.calls() if c.startswith("systemctl stop")])


HEALTH_STEP = "Step 7: health is healthy, database connected, version 0.9.0"
VERSION_STEP = "Step 7: version endpoint reports openwatch 0.9.0"
GEN = _here.parent / "internal" / "server" / "api" / "server.gen.go"


def generated_fields(struct):
    """The JSON names of a response type generated from api/openapi.yaml."""
    import re
    text = read_text(GEN)
    body = re.search(r"^type %s struct \{\n(.*?)^\}" % struct, text, re.S | re.M).group(1)
    return set(re.findall(r'json:"([^",]+)', body))


class UpgradeStep7(Case):
    """AC-06: Step 7 reads each endpoint by its schema, and refuses anything else."""

    def verify_fails(self, at, why, **state):
        self.through("install")
        for k, v in state.items():
            self.state(k.replace("_", "-"), v)
        code, out = self.run_phase("verify")
        self.assertEqual(code, 1, out)
        with open(os.path.join(self.capture("verify"), "stderr")) as f:
            err = f.read()
        self.assertIn("STOPPED at: " + at, err)
        self.assertIn(why, err)
        self.assertNotIn("VERIFY DONE", self.stdout("verify"))

    def test_the_fixtures_are_the_servers_schemas(self):
        # The defect this class exists for: a fake with an invented "version"
        # field on /api/v1/version hid a check that the real server fails.
        self.through("verify")
        out = self.stdout("verify")
        self.assertEqual(generated_fields("VersionResponse"),
                         {"openwatch", "kensa", "go", "commit", "build_time"})
        self.assertEqual(generated_fields("HealthResponse"), {"status", "db_connected", "version"})
        bodies = [json.loads(l) for l in out.splitlines() if l.startswith("{")]
        self.assertEqual([set(b) for b in bodies],
                         [generated_fields("HealthResponse"), generated_fields("VersionResponse")])
        self.assertIn("openwatch='0.9.0' (want '0.9.0')", out)
        self.assertIn("http 200", out)

    def test_a_version_body_with_only_a_version_field_fails(self):
        self.verify_fails(VERSION_STEP, "version: wrong or missing openwatch",
                          version_body='{"version":"0.9.0"}')

    def test_another_openwatch_version_fails(self):
        self.verify_fails(VERSION_STEP, "version: wrong or missing openwatch",
                          version_body=json.dumps({"openwatch": "0.8.4", "kensa": "0.10.0",
                                                   "go": "go1.26.5", "commit": "x",
                                                   "build_time": "y"}))

    def test_degraded_health_fails(self):
        self.verify_fails(HEALTH_STEP, "health: wrong or missing status", health_body=json.dumps(
            {"status": "degraded", "db_connected": True, "version": "0.9.0"}))

    def test_a_disconnected_database_fails(self):
        for body in ({"status": "healthy", "db_connected": False, "version": "0.9.0"},
                     {"status": "healthy", "db_connected": 1, "version": "0.9.0"},
                     {"status": "healthy", "version": "0.9.0"}):
            with self.subTest(body=body):
                shutil.rmtree(self.evidence, True)
                shutil.rmtree(self.remote, True)
                for name, value in (("version", "0.8.4"), ("schema", "65"), ("service", "active")):
                    self.state(name, value)
                if os.path.exists(os.path.join(self.fake, "health-body")):
                    os.unlink(os.path.join(self.fake, "health-body"))
                self.verify_fails(HEALTH_STEP, "health: wrong or missing db_connected",
                                  health_body=json.dumps(body))

    def test_a_503_with_an_error_envelope_fails(self):
        self.verify_fails(HEALTH_STEP, "", db_down="")
        out = self.stdout("verify")
        self.assertIn("http 503", out)
        self.assertIn('"code":"server.unavailable"', out)

    def test_a_status_other_than_200_fails_even_with_a_healthy_body(self):
        self.verify_fails(HEALTH_STEP, "", health_code="500")
        self.assertIn("http 500", self.stdout("verify"))
        self.assertIn('"status":"healthy"', self.stdout("verify"))

    def test_a_body_that_is_not_json_fails(self):
        self.verify_fails(HEALTH_STEP, "health: the body is not JSON",
                          health_body="<html>502 Bad Gateway</html>")

    def test_step_8_needs_a_healthy_body_too(self):
        self.through("verify")
        self.state("health-body", json.dumps(
            {"status": "degraded", "db_connected": True, "version": "0.9.0"}))
        code, out = self.run_phase("rules")
        self.assertEqual(code, 1, out)
        with open(os.path.join(self.capture("rules"), "stderr")) as f:
            self.assertIn("STOPPED at: Step 8.1: healthy", f.read())
        self.assertNotIn("STEP 8 DONE", self.stdout("rules"))


# Every command that changes an OpenWatch server, as the fakes log it.
MUTATING = ("pg_dump", "pg_restore", "systemctl stop", "systemctl start", "systemctl restart",
            "dnf", "apt-get", "openwatch --config")


class UpgradeIdentity(Case):
    """AC-07: a changed target causes no staging, dump, stop, install, migration or restart."""

    def changed_target_changes_nothing(self, phase, change, staged_by_phase=False):
        prior = ("plan", "backup", "install", "verify", "rules")
        self.through(prior[prior.index(phase) - 1])
        dumps = sorted(os.listdir(os.path.join(self.root, "var/backups/openwatch")))
        service = read_text(os.path.join(self.fake, "service"))
        version = read_text(os.path.join(self.fake, "version"))
        stage = os.path.join(self.remote, TAG, "upgrade", "packages")
        staged = sorted(os.listdir(stage)) if os.path.isdir(stage) else None
        change()
        before = len(self.calls())
        code, out = self.run_phase(phase)
        self.assertEqual(code, 1, out)
        later = self.calls()[before:]
        self.assertEqual([c for c in later if c.startswith(MUTATING)], [], later)
        self.assertNotIn(phase.upper() + " DONE", out)
        self.assertEqual(sorted(os.listdir(os.path.join(self.root, "var/backups/openwatch"))),
                         dumps)
        self.assertEqual(read_text(os.path.join(self.fake, "service")), service)
        self.assertEqual(read_text(os.path.join(self.fake, "version")), version)
        if not staged_by_phase:
            self.assertEqual(sorted(os.listdir(stage)) if os.path.isdir(stage) else None,
                             staged, "a package was staged on a changed host")
        if phase == "install":
            self.assertIsNone(staged)
        return out

    def test_another_machine_id_changes_nothing_in_any_phase(self):
        for phase in ("backup", "install", "verify", "rules"):
            with self.subTest(phase=phase):
                self.setUp()
                out = self.changed_target_changes_nothing(phase, lambda: self.write(
                    "etc/machine-id", "0000000000000000000000000000beef\n"))
                if phase == "install":
                    self.assertIn("staging", out)
                else:
                    with open(os.path.join(self.capture(phase), "stderr")) as f:
                        err = f.read()
                    self.assertIn("STOPPED at: identity matches the verified preflight", err)
                    self.assertIn("not the host the preflight examined", err)

    def test_another_hostname_changes_nothing_in_any_phase(self):
        for phase in ("backup", "install", "verify", "rules"):
            with self.subTest(phase=phase):
                self.setUp()
                self.changed_target_changes_nothing(
                    phase, lambda: self.state("hostname", "owas-rhn02.hanalyx.local"))

    def test_the_staging_checks_identity_before_it_creates_anything(self):
        self.through("backup")
        self.write("etc/machine-id", "0000000000000000000000000000beef\n")
        code, out = self.run_phase("install")
        self.assertEqual(code, 1, out)
        self.assertIn("staging %s on owas-rhn01 ended with exit=1" %
                      os.path.basename(self.packages[0]), out)
        with open(os.path.join(self.host_dir, "stage-" + os.path.basename(self.packages[0]),
                               "stderr")) as f:
            self.assertIn("not the host the preflight examined", f.read())
        self.assertFalse(os.path.exists(self.capture("install")), "the install phase ran")

    def test_a_host_changed_after_staging_is_not_stopped_or_installed(self):
        # Staging and the install run are separate connections: the install
        # script checks again, on its own connection, before Step 2.
        real = ru.stage_packages

        def stage_then_change(*a, **kw):
            result = real(*a, **kw)
            self.write("etc/machine-id", "0000000000000000000000000000beef\n")
            return result
        ru.stage_packages = stage_then_change
        self.addCleanup(setattr, ru, "stage_packages", real)
        out = self.changed_target_changes_nothing("install", lambda: None, staged_by_phase=True)
        with open(os.path.join(self.capture("install"), "stderr")) as f:
            self.assertIn("STOPPED at: identity matches the verified preflight", f.read())

    def test_the_expected_identity_is_the_preflights(self):
        self.ok("plan")
        code, out = self.run_phase("backup", execute=False)
        self.assertIn("export OW_EXPECT_MACHINE_ID=35a9c078635e4d12ab707298cd170ae2", out)
        self.assertIn("export OW_EXPECT_HOSTNAME=owas-rhn01.hanalyx.local", out)
        self.assertLess(out.index("identity matches the verified preflight"),
                        out.index("pg_dump"))

    def test_a_preflight_without_one_identity_line_blocks_every_change(self):
        os.makedirs(self.host_dir)
        ec.capture(["sh", "-c", 'echo "== hostname"; echo a; echo b; echo "== exit 0"; '
                    'echo "== machine-id"; echo 35a9c078635e4d12ab707298cd170ae2; '
                    'echo "== exit 0"'], self.host_dir, "upgrade-plan", TAG, COMMIT,
                   timeout=30, host=dict(ec.host_identity()))
        before = self.calls()
        code, out = self.run_phase("backup")
        self.assertEqual(code, 1, out)
        self.assertIn("reported 2 hostname lines, not one", out)
        self.assertEqual(self.calls(), before)


class UpgradeStep8(Case):
    """AC-04: Step 8 reaches MATCH only when the served rules are the installed rules."""

    def step8(self):
        self.through("verify")
        return self.run_phase("rules")

    def assert_step8_fails(self, at):
        code, out = self.step8()
        self.assertEqual(code, 1, out)
        with open(os.path.join(self.capture("rules"), "stderr")) as f:
            err = f.read()
        self.assertIn("STOPPED at: " + at, err)
        self.assertIn("Do not scan", err)
        self.assertNotIn("STEP 8 DONE", self.stdout("rules"))

    def test_a_stale_served_rule_is_a_mismatch(self):
        self.state("served", " ".join(RULES + ("shell-idle-timeout-tmout",)))
        self.assert_step8_fails("Step 8.3")
        self.assertIn("served but not installed: ['shell-idle-timeout-tmout']",
                      self.stdout("rules"))
        self.assertIn("MISMATCH", self.stdout("rules"))

    def test_no_rules_at_all_is_not_a_match(self):
        self.state("served", "")
        for name in os.listdir(os.path.join(self.root, "usr/share/kensa/rules/linux")):
            os.unlink(os.path.join(self.root, "usr/share/kensa/rules/linux", name))
        self.assert_step8_fails("Step 8.3")

    def test_changed_package_files_fail(self):
        self.state("rpm-V", "S.5....T.  /usr/share/kensa/rules/linux/ssh-root-login.yml")
        self.assert_step8_fails("Step 8.2")

    def test_a_rule_load_failure_in_the_journal_fails(self):
        self.state("journal", "level=ERROR msg=\"kensa rule library unavailable\"")
        self.assert_step8_fails("Step 8.1: no rule-load failure in the journal")

    def test_a_service_that_does_not_come_back_fails(self):
        self.through("verify")
        self.state("health-down")
        code, out = self.run_phase("rules")
        self.assertEqual(code, 1)
        with open(os.path.join(self.capture("rules"), "stderr")) as f:
            self.assertIn("STOPPED at: Step 8.1: healthy", f.read())

    def test_the_token_file_must_be_root_only_and_hold_an_owk_token(self):
        for setup, at in ((lambda: os.chmod(self.token_file, 0o644), "token file is root-only"),
                          (lambda: self.state("token-owner", "owadmin"), "token file is root-only"),
                          (lambda: self.write("root/owk-token", "not-a-token\n", mode=0o600),
                           "token")):
            with self.subTest(at=at):
                shutil.rmtree(self.evidence, True)
                shutil.rmtree(self.remote, True)
                for name, value in (("version", "0.8.4"), ("schema", "65"),
                                    ("service", "active"), ("token-owner", "root")):
                    self.state(name, value)
                self.write("root/owk-token", TOKEN + "\n", mode=0o600)
                self.through("verify")
                setup()
                code, out = self.run_phase("rules")
                self.assertEqual(code, 1, out)
                with open(os.path.join(self.capture("rules"), "stderr")) as f:
                    self.assertIn("STOPPED at: " + at, f.read())
        restarts = [c for c in self.calls() if c.startswith("systemctl restart")]
        self.assertEqual(restarts, [], "a bad token file must stop Step 8 before the restart")

    def test_the_token_never_appears_in_any_evidence(self):
        self.through("rules")
        for root, _dirs, files in os.walk(self.dir):
            if root.startswith(os.path.join(self.root, "root")) or root.startswith(self.fake):
                continue
            for n in files:
                with open(os.path.join(root, n), "rb") as f:
                    self.assertNotIn(TOKEN.encode(), f.read(), os.path.join(root, n))


class UpgradeBoundaries(Case):
    """AC-05: explicit timeouts, and nothing in the scripts starts, rolls back or reboots."""

    def test_every_capture_has_its_declared_timeout(self):
        self.through("rules")
        allowed = {p.timeout + ru.rp.SSH_MARGIN for p in ru.PHASES} | {
            p.timeout for p in ru.PHASES} | {ru.TRANSFER_TIMEOUT, ru.STAGE_TIMEOUT}
        for n in sorted(os.listdir(self.host_dir)):
            rec = ec.verify_capture(os.path.join(self.host_dir, n), tag=TAG, commit=COMMIT,
                                    allow_incomplete=True)
            self.assertIn(rec["invocation"]["timeout_seconds"], allowed, n)
        for p in ru.PHASES:
            with open(os.path.join(self.remote, TAG, "upgrade", "upgrade-" + p.name,
                                   "record.json")) as f:
                self.assertEqual(json.load(f)["invocation"]["timeout_seconds"], p.timeout)

    def test_a_phase_without_a_timeout_cannot_run(self):
        p = ru.phase("plan")
        old = p.timeout
        p.timeout = None
        try:
            code, out = self.run_phase("plan")
        finally:
            p.timeout = old
        self.assertEqual(code, 1)
        self.assertIn("explicit positive timeout", out)
        self.assertEqual(self.calls(), [])

    def test_the_scripts_never_start_roll_back_or_reboot(self):
        import re
        for script in sorted(os.listdir(ru.SCRIPTS)):
            with open(ru.SCRIPTS / script) as f:
                text = f.read()
            body = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
            for pattern in (r"systemctl\s+start", r"\breboot\b", r"shutdown", r"downgrade",
                            r"pg_restore\s+(?!--list)", r"dnf\s+(remove|downgrade|history)",
                            r"apt-get\s+(remove|purge)", r"(?<!\|)\|(?!\|)"):
                self.assertIsNone(re.search(pattern, body), "%s: %s" % (script, pattern))
            if script != "rules.sh":
                self.assertNotIn("systemctl restart", body, script)


if __name__ == "__main__":
    unittest.main(verbosity=2)
