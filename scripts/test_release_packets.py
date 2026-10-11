#!/usr/bin/env python3
"""Tests for the F1, F3 and D1 packet tool.

    python3 -S scripts/test_release_packets.py

The OpenWatch server is simulated: the transport is `sh -c` instead of ssh,
file paths sit under a fake root (OW_ROOT), and sudo, hostname, openwatch,
psql, curl and stat are one fake dispatcher that logs every call with its
arguments and, for psql, the SQL it was given. The reading scripts, the
capture library, the fetch and the verification are real. The SQL itself is
tested against the migrated schema in internal/scanruns (AC-07); here psql
answers by recognizing which reading asked.

D1 runs the real scripts/doc-review-skeleton.py in a throwaway git
repository, so the checker commit and its cleanliness are real too.

One class per criterion of spec release-packets. No network.
"""

import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

_here = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("release_packets", _here / "release_packets.py")
rk = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rk)
ec = rk.ec

TAG = "v0.9.0"
COMMIT = "474d9af26e457fc6a47b5475fab87394433a687b"  # pragma: allowlist secret
SCAN = "01a12357-fb3b-7763-8c0e-2932b5ddd7d8"
TOKEN = "owk_test_token_value_never_printed_0002"  # pragma: allowlist secret
ARTIFACT = "openwatch-0.9.0-1.x86_64.rpm"

FAKEBIN = r'''
import json, os, sys
F = os.environ["OW_FAKE"]
cmd = os.path.basename(sys.argv[0])
args = sys.argv[1:]


def st(name, default=""):
    p = os.path.join(F, name)
    return open(p).read().strip() if os.path.exists(p) else default


stdin = ""
if cmd == "psql" and args[-2:] == ["-f", "-"]:
    stdin = sys.stdin.read()
with open(os.path.join(F, "calls.log"), "a") as f:
    f.write(json.dumps([cmd] + args + ([stdin] if stdin else [])) + "\n")

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
    # printVersion in cmd/openwatch/main.go.
    out = st("binary-version-out")
    if not out:
        out = "openwatch %s\n  commit:    %s\n  built:     2026-10-01T00:00:00Z\n  fips:      false" % (
            st("binary-version", "0.9.0"), st("binary-commit", "474d9af2"))
    print(out); sys.exit(0)
if cmd == "psql":
    sql = stdin
    if flag := st("psql-fail"):
        print("psql: error: " + flag, file=sys.stderr); sys.exit(2)
    if "WITH r AS" in sql:
        print(st("consistency", "consistent"))
    elif "FROM scan_runs WHERE id" in sql:
        print("id | host_id | trigger_source | requested_by | status | queued_at | started_at | "
              "finished_at | rules_pass | rules_fail | rules_skipped | rules_error | "
              "engine_version | corpus_version | corpus_digest | correlation_id")
        print("%s | 01a0ed4c-c03a-752b-8600-a15fff968665 | on_demand | "
              "01a0ed4a-b968-7a0b-8fc6-87c440a90d9b | completed | %s | "
              "2026-10-11 15:00:01.000000+00 | 2026-10-11 15:00:41.000000+00 | 500 | 110 | 169 | 0 | "
              "v0.10.0 | 0.10.0 | sha256:abc | req-1" % (
                  st("scan-id-echo", SCAN_ID), st("queued-at", "2026-10-11 15:00:00.000000+00")))
    elif "GROUP BY status" in sql:
        print("status | count\nfail | 110\npass | 500\nskipped | 169")
    elif "GROUP BY skip_reason" in sql:
        print("count | coalesce\n134 | not applicable\n27 | no applicable implementation")
    elif "FROM audit_events e, scan_runs r" in sql:
        print("occurred_at | action | actor_type | coalesce | coalesce | correlation_id")
        print("2026-10-11 15:00:00+00 | scan.queued | user | u | admin | req-1")
        print("2026-10-11 15:00:41+00 | scan.completed | system |  |  | req-1")
    else:
        print("unrecognized SQL", file=sys.stderr); sys.exit(3)
    sys.exit(0)
if cmd == "curl":
    out = conf = wfmt = None
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
        i += 1
    url = args[-1]
    code = 200
    if url.endswith("/api/v1/version"):
        # GetVersion's VersionResponse; "version-body" replaces it verbatim.
        code = int(st("version-code", "200"))
        body = st("version-body") or json.dumps({
            "openwatch": st("api-version", "0.9.0"), "kensa": "0.10.0", "go": "go1.26.9",
            "commit": st("api-commit", "474d9af2"), "build_time": "2026-10-01T00:00:00Z"})
    elif url.endswith("/api/v1/system/scan/variables"):
        if "Bearer " + st("token") not in (open(conf).read() if conf else ""):
            code, body = 401, '{"error":{"code":"auth.required"}}'
        else:
            code = int(st("variables-code", "200"))
            body = st("variables-body") or json.dumps({"variables": [
                {"name": n, "default": "", "value": "", "overridden": n == "ntp_server",
                 "affects_rules": 1, "rule_ids": ["r-" + n], "configure_me": n != "banner_text"}
                for n in ("allowed_users", "banner_text", "ntp_server")]})
    else:
        code, body = 404, "{}"
    with open(out, "w") as f:
        f.write(body)
    if wfmt == "%{http_code}":
        sys.stdout.write(str(code))
    sys.exit(0)
if cmd == "stat":
    print("%s %s" % (st("token-owner", "root"), oct(os.stat(args[-1]).st_mode & 0o777)[2:]))
    sys.exit(0)
sys.exit(99)
'''

COMMANDS = ("sudo", "hostname", "openwatch", "psql", "curl", "stat")


def read_text(path):
    with open(path) as f:
        return f.read()


def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


class Case(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="relpkt-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.fake = os.path.join(self.dir, "fake")
        self.root = os.path.join(self.dir, "root")
        bin_ = os.path.join(self.dir, "bin")
        for d in (self.fake, bin_):
            os.makedirs(d)
        dispatcher = os.path.join(self.dir, "fakebin.py")
        with open(dispatcher, "w") as f:
            f.write("#!%s\nSCAN_ID = %r\n%s" % (sys.executable, SCAN, FAKEBIN))
        os.chmod(dispatcher, 0o755)
        for c in COMMANDS:
            os.symlink(dispatcher, os.path.join(bin_, c))
        for rel in ("etc/openwatch", "root"):
            os.makedirs(os.path.join(self.root, rel))
        self.write("etc/openwatch/secrets.env", "OPENWATCH_DATABASE_DSN=postgres://db/x\n")
        self.write("etc/machine-id", "35a9c078635e4d12ab707298cd170ae2\n")
        self.token_file = os.path.join(self.root, "root", "owk-token")
        self.write("root/owk-token", TOKEN + "\n", mode=0o600)
        self.state("token", TOKEN)
        self.sums = os.path.join(self.dir, "SHA256SUMS")
        self.digest = hashlib.sha256(b"rpm").hexdigest()
        with open(self.sums, "w") as f:
            f.write("%s  %s\n%s  kensa-rules-0.10.0-1.noarch.rpm\n" % (
                self.digest, ARTIFACT, "1" * 64))
        old_env = dict(os.environ)
        self.addCleanup(lambda: (os.environ.clear(), os.environ.update(old_env)))
        os.environ.update(OW_FAKE=self.fake, PATH=bin_ + os.pathsep + os.environ.get("PATH", ""))
        self.evidence = os.path.join(self.dir, "evidence")
        self.remote = os.path.join(self.dir, "remote")
        self.host_dir = os.path.join(self.evidence, "packets", "owas-rhn01")

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
        return [json.loads(l) for l in read_text(p).splitlines()] if os.path.exists(p) else []

    def host_args(self):
        return ["--host", "owas-rhn01", "--tag", TAG, "--commit", COMMIT, "--evidence",
                self.evidence, "--sums", self.sums, "--artifact", ARTIFACT, "--sudo", "",
                "--remote-python", sys.executable, "--remote-dir", self.remote,
                "--root", self.root, "--transport", json.dumps(["sh", "-c"])]

    def run_tool(self, argv):
        out = io.StringIO()
        code = rk.main(argv, out=out)
        return code, out.getvalue()

    def f1(self, *extra):
        return self.run_tool(["f1"] + self.host_args() + ["--scan-id", SCAN] + list(extra))

    def f3(self, *extra):
        return self.run_tool(["f3"] + self.host_args() + ["--token-file", self.token_file]
                             + list(extra))

    def skeleton(self, gate, kind):
        return os.path.join(self.host_dir, "attest-%s-%s-%s.skeleton.toml" % (gate, kind, TAG))

    def plant_step8(self, text="STEP 8 DONE: MATCH"):
        """A release_upgrade.py Step 8 capture for this server, finished now."""
        d = os.path.join(self.evidence, "upgrade", "owas-rhn01")
        os.makedirs(d)
        ec.capture(["sh", "-c", "echo '%s'" % text], d, "upgrade-rules", TAG, COMMIT,
                   timeout=30, host=dict(ec.host_identity()))

    def assert_human_fields_blank(self, doc):
        for k in ("performed_by", "performed_at", "captain_confirmation", "observed"):
            self.assertEqual(doc[k], "", k)


class F1Packet(Case):
    """AC-01: F1 reads the captain's scan, read-only, into a packet and a blank skeleton."""

    def test_a_scan_becomes_a_packet_and_a_skeleton_with_blank_human_fields(self):
        code, out = self.f1()
        self.assertEqual(code, 0, out)
        doc = tomllib.loads(read_text(self.skeleton("F1", "fleet-scan")))
        self.assertEqual((doc["kind"], doc["tag"], doc["commit"], doc["artifact"]),
                         ("fleet-scan", TAG, COMMIT, ARTIFACT))
        self.assertEqual(doc["artifact_sha256"], self.digest)
        self.assertEqual(doc["sums_sha256"], hashlib.sha256(read_bytes(self.sums)).hexdigest())
        self.assert_human_fields_blank(doc)
        cap = os.path.join(self.host_dir, "f1-readings")
        rec = ec.verify_capture(cap, tag=TAG, commit=COMMIT)
        self.assertIn(rec["streams"]["stdout"]["sha256"], doc["server_records"])
        self.assertIn("500 pass, 110 fail, 169 skipped, 0 error", doc["server_records"])
        self.assertIn("fail | 110; pass | 500; skipped | 169", doc["server_records"])
        self.assertIn("no release_upgrade.py Step 8 capture", doc["server_records"])
        packet = read_text(os.path.join(self.host_dir, "F1-PACKET.md"))
        self.assertIn("It records no verdict.", packet)
        self.assertIn("- Observed by: ______", packet)
        self.assertIn("the scan was started by the captain from the UI after Step 8 MATCH: ______",
                      packet)

    def test_every_query_is_read_only_and_binds_the_scan_id(self):
        self.f1()
        psql = [c for c in self.calls() if c[0] == "psql"]
        self.assertEqual(len(psql), 5)
        for c in psql:
            self.assertIn("SET default_transaction_read_only = on", c)
            self.assertIn("ON_ERROR_STOP=1", c)
            self.assertIn("scan=" + SCAN, c)
            sql = c[-1]
            self.assertNotIn(SCAN, sql, "the scan id was pasted into the SQL")
            self.assertIn(":'scan'", sql)
            for word in ("INSERT", "UPDATE", "DELETE", "TRUNCATE", "ALTER", "DROP", "CREATE"):
                self.assertNotIn(word, sql.upper().replace("CREATED", ""), word)

    def test_a_step_8_match_before_the_scan_is_recorded(self):
        self.state("queued-at", "2099-01-01 00:00:00.000000+00")
        self.plant_step8()
        code, out = self.f1()
        self.assertEqual(code, 0, out)
        doc = tomllib.loads(read_text(self.skeleton("F1", "fleet-scan")))
        self.assertIn("MATCH in %s" % os.path.join(self.evidence, "upgrade", "owas-rhn01",
                                                  "upgrade-rules"), doc["server_records"])



class F1Refusals(Case):
    """AC-02: F1 writes no packet for a bad scan id, artifact, reading or ordering."""

    def assert_no_packet(self):
        self.assertFalse(os.path.exists(os.path.join(self.host_dir, "F1-PACKET.md")))
        self.assertFalse(os.path.exists(self.skeleton("F1", "fleet-scan")))

    def test_a_malformed_scan_id_is_refused_before_contact(self):
        for bad in ("", "01A12357-FB3B-7763-8C0E-2932B5DDD7D8", SCAN + "'; DROP TABLE x; --",
                    "not-a-uuid"):
            with self.subTest(bad=bad):
                code, out = self.run_tool(["f1"] + self.host_args() + ["--scan-id", bad])
                self.assertEqual(code, 1, out)
                self.assertIn("--scan-id must be the scan's UUID", out)
        self.assertEqual(self.calls(), [])
        self.assertFalse(os.path.exists(self.evidence))

    def test_an_artifact_not_listed_once_is_refused_before_contact(self):
        for name, why in (("openwatch-9.9.9-1.x86_64.rpm", "0 times"), ("bad name/x", "file name")):
            with self.subTest(name=name):
                code, out = self.run_tool(["f1"] + self.host_args()[:-12] + [
                    "--artifact", name, "--sudo", "", "--remote-python", sys.executable,
                    "--remote-dir", self.remote, "--root", self.root, "--transport",
                    json.dumps(["sh", "-c"]), "--sums", self.sums, "--scan-id", SCAN])
                self.assertEqual(code, 1, out)
                self.assertIn(why, out)
        with open(self.sums, "a") as f:
            f.write("%s  %s\n" % ("2" * 64, ARTIFACT))
        code, out = self.f1()
        self.assertIn("2 times", out)
        self.assertEqual(self.calls(), [])

    def test_inconsistent_records_write_no_packet_and_keep_the_capture(self):
        for fault in ("run counts differ from result rows", "scan is running",
                      "scan.completed events: 0", "no such scan"):
            with self.subTest(fault=fault):
                shutil.rmtree(self.evidence, True)
                shutil.rmtree(self.remote, True)
                self.state("consistency", fault)
                code, out = self.f1()
                self.assertEqual(code, 1, out)
                self.assertIn("failed: consistency (exit 1)", out)
                self.assertIn("No packet was written", out)
                self.assert_no_packet()
                self.assertIn(fault, read_text(os.path.join(self.host_dir, "f1-readings",
                                                            "stdout")))

    def test_a_failed_query_fails_its_section_and_every_section_still_runs(self):
        self.state("psql-fail", "connection refused")
        code, out = self.f1()
        self.assertEqual(code, 1, out)
        for s in ("scan run", "result counts", "skip reasons", "audit trail", "consistency"):
            self.assertIn("%s (exit" % s, out)
        # The readings script fails itself, not only through the tool's reading.
        self.assertEqual(read_text(os.path.join(self.host_dir, "f1-readings", "exit")), "exit=1\n")
        self.assertIn("F1 readings: required sections failed",
                      read_text(os.path.join(self.host_dir, "f1-readings", "stderr")))
        self.assert_no_packet()

    def test_a_scan_queued_before_step_8_finished_is_refused(self):
        self.plant_step8()
        code, out = self.f1()
        self.assertEqual(code, 1, out)
        self.assertIn("before the Step 8 capture finished", out)
        self.assert_no_packet()

    def test_a_step_8_capture_without_match_is_refused(self):
        self.state("queued-at", "2099-01-01 00:00:00.000000+00")
        self.plant_step8("MISMATCH")
        code, out = self.f1()
        self.assertEqual(code, 1, out)
        self.assertIn("did not end in MATCH", out)
        self.assert_no_packet()

    def test_a_second_run_and_an_existing_packet_are_refused(self):
        self.assertEqual(self.f1()[0], 0)
        code, out = self.f1()
        self.assertEqual(code, 1, out)
        self.assertIn("never taken twice", out)
        before = read_text(os.path.join(self.host_dir, "F1-PACKET.md"))
        os.rename(os.path.join(self.host_dir, "f1-readings"),
                  os.path.join(self.host_dir, "f1-readings.moved-aside"))
        shutil.rmtree(self.remote, True)
        code, out = self.f1()
        self.assertEqual(code, 1, out)
        self.assertIn("never overwritten", out)
        self.assertEqual(read_text(os.path.join(self.host_dir, "F1-PACKET.md")), before)


class F3Packet(Case):
    """AC-03: F3 reads the scan variables by schema, with the token kept on the server."""

    def test_the_variables_become_a_packet_and_a_skeleton_with_blank_human_fields(self):
        code, out = self.f3()
        self.assertEqual(code, 0, out)
        doc = tomllib.loads(read_text(self.skeleton("F3", "fleet-scan-variables")))
        self.assertEqual(doc["kind"], "fleet-scan-variables")
        self.assert_human_fields_blank(doc)
        self.assertIn("answered 200 with 3 variables, 2 needing organization settings "
                      "(configure_me) and 1 overridden", doc["server_records"])
        self.assertIn("Settings > Compliance policies lists these scan variables",
                      read_text(os.path.join(self.host_dir, "F3-PACKET.md")))

    def test_names_are_compared_with_the_previous_release(self):
        prior = os.path.join(self.dir, "prior-names")
        with open(prior, "w") as f:
            f.write("allowed_users\nbanner_text\nold_variable\n")
        code, out = self.f3("--prior-names", prior)
        self.assertEqual(code, 0, out)
        doc = tomllib.loads(read_text(self.skeleton("F3", "fleet-scan-variables")))
        self.assertIn("added ['ntp_server']; removed ['old_variable']", doc["server_records"])

    def test_an_empty_list_is_the_blank_panel_and_fails(self):
        self.state("variables-body", '{"variables":[]}')
        code, out = self.f3()
        self.assertEqual(code, 1, out)
        self.assertIn("summary (exit 1)", out)
        self.assertIn("the rule corpus did not resolve",
                      read_text(os.path.join(self.host_dir, "f3-readings", "stderr")))

    def test_a_body_off_the_schema_or_a_non_200_fails(self):
        for name, value in (("variables-body", '{"variables":[{"name":"x"}]}'),
                            ("variables-body", "<html>502</html>"),
                            ("variables-body", '{"vars":[]}'),
                            ("variables-code", "500")):
            with self.subTest(body=value):
                shutil.rmtree(self.evidence, True)
                shutil.rmtree(self.remote, True)
                for f in ("variables-body", "variables-code"):
                    if os.path.exists(os.path.join(self.fake, f)):
                        os.unlink(os.path.join(self.fake, f))
                self.state(name, value)
                code, out = self.f3()
                self.assertEqual(code, 1, out)
                self.assertFalse(os.path.exists(os.path.join(self.host_dir, "F3-PACKET.md")))

    def test_a_field_of_the_wrong_type_fails_the_schema_check(self):
        for field, value, why in (("affects_rules", "1", "affects_rules as int"),
                                  ("configure_me", "yes", "configure_me as bool"),
                                  ("rule_ids", "r-1", "rule_ids as list")):
            with self.subTest(field=field):
                shutil.rmtree(self.evidence, True)
                shutil.rmtree(self.remote, True)
                v = {"name": "x", "default": "", "value": "", "overridden": False,
                     "affects_rules": 1, "rule_ids": [], "configure_me": True}
                v[field] = value
                self.state("variables-body", json.dumps({"variables": [v]}))
                code, out = self.f3()
                self.assertEqual(code, 1, out)
                # The schema check's own message, not a crash further on.
                self.assertIn("a variable lacks %s" % why,
                              read_text(os.path.join(self.host_dir, "f3-readings", "stderr")))

    def test_a_token_file_that_is_not_root_only_never_reaches_curl(self):
        for setup in (lambda: os.chmod(self.token_file, 0o644),
                      lambda: self.state("token-owner", "owadmin")):
            with self.subTest():
                shutil.rmtree(self.evidence, True)
                shutil.rmtree(self.remote, True)
                os.chmod(self.token_file, 0o600)
                self.state("token-owner", "root")
                setup()
                before = len(self.calls())
                code, out = self.f3()
                self.assertEqual(code, 1, out)
                self.assertIn("token file is root-only (exit 1)", out)
                self.assertFalse([c for c in self.calls()[before:] if c[0] == "curl"
                                  and c[-1].endswith("/scan/variables")])

    def test_the_token_never_appears_in_any_evidence(self):
        self.assertEqual(self.f3()[0], 0)
        for root, _dirs, files in os.walk(self.dir):
            if root.startswith((os.path.join(self.root, "root"), self.fake)):
                continue
            for n in files:
                with open(os.path.join(root, n), "rb") as f:
                    self.assertNotIn(TOKEN.encode(), f.read(), os.path.join(root, n))

    def test_a_relative_token_path_is_refused_before_contact(self):
        code, out = self.run_tool(["f3"] + self.host_args() + ["--token-file", "owk-token"])
        self.assertEqual(code, 1, out)
        self.assertEqual(self.calls(), [])


class D1Packet(unittest.TestCase):
    """AC-04: D1 runs the skeleton generator from a clean checker commit, and adds no verdict."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="relpkt-d1-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.repo = os.path.join(self.dir, "repo")
        os.makedirs(os.path.join(self.repo, "scripts"))
        shutil.copy(_here / "doc-review-skeleton.py", os.path.join(self.repo, "scripts"))
        for name, text in (("README.md", "# readme\n"), ("docs/guide.md", "# guide\n")):
            os.makedirs(os.path.dirname(os.path.join(self.repo, name)), exist_ok=True)
            with open(os.path.join(self.repo, name), "w") as f:
                f.write(text)
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com",
                   GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.com",
                   GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
        for cmd in (["init", "-q", "-b", "main"], ["add", "-A"], ["commit", "-q", "-m", "c"]):
            subprocess.run(["git", "-C", self.repo] + cmd, check=True, env=env)
        self.commit = subprocess.run(["git", "-C", self.repo, "rev-parse", "HEAD"], check=True,
                                     capture_output=True, text=True).stdout.strip()
        self.evidence = os.path.join(self.dir, "evidence")
        self.local = os.path.join(self.evidence, "d1")

    def d1(self, *extra):
        out = io.StringIO()
        code = rk.main(["d1", "--tag", TAG, "--commit", self.commit, "--evidence", self.evidence,
                        "--repo", self.repo] + list(extra), out=out)
        return code, out.getvalue()

    def generator(self, body):
        p = os.path.join(self.dir, "gen.py")
        with open(p, "w") as f:
            f.write("print(%r)\n" % body)
        return p

    def test_the_skeleton_is_the_capture_and_every_verdict_stays_pending(self):
        code, out = self.d1()
        self.assertEqual(code, 0, out)
        cap = os.path.join(self.local, "d1-skeleton")
        rec = ec.verify_capture(cap, tag=TAG, commit=self.commit)
        with open(os.path.join(cap, "stdout"), "rb") as f:
            raw = f.read()
        skel = os.path.join(self.local, "doc-review-%s.skeleton.toml" % TAG)
        with open(skel, "rb") as f:
            self.assertEqual(f.read(), raw, "the skeleton must be the capture's exact stdout")
        doc = tomllib.loads(raw.decode())
        self.assertEqual(doc["performed_by"], "")
        self.assertEqual(sorted(r["path"] for r in doc["reviewed"]), ["README.md", "docs/guide.md"])
        self.assertEqual({r["verdict"] for r in doc["reviewed"]}, {"pending"})
        packet = read_text(os.path.join(self.local, "D1-PACKET.md"))
        self.assertIn("at `%s` (clean tree)" % self.commit, packet)
        self.assertIn(rec["streams"]["stdout"]["sha256"], packet)
        self.assertIn("2 to review (verdict pending), 0 inherited", packet)
        self.assertIn("It records no verdict.", packet)

    def test_a_checker_with_tracked_changes_is_refused(self):
        with open(os.path.join(self.repo, "README.md"), "a") as f:
            f.write("edited\n")
        code, out = self.d1()
        self.assertEqual(code, 1, out)
        self.assertIn("tracked changes", out)
        self.assertFalse(os.path.exists(self.local))

    def test_a_generator_that_fills_a_verdict_or_a_signature_is_refused(self):
        for body, why in (
                ('kind = "documentation-review"\nperformed_by = ""\n\n[[reviewed]]\n'
                 'path = "README.md"\nblob = "x"\nverdict = "accurate"', "verdict other than pending"),
                ('kind = "documentation-review"\nperformed_by = "someone"\n\n[[reviewed]]\n'
                 'path = "README.md"\nblob = "x"\nverdict = "pending"', "performed_by"),
                ('kind = "documentation-review"\nperformed_by = ""', "lists no documents")):
            with self.subTest(why=why):
                shutil.rmtree(self.evidence, True)
                code, out = self.d1("--skeleton", self.generator(body))
                self.assertEqual(code, 1, out)
                self.assertIn(why, out)
                self.assertFalse(os.path.exists(os.path.join(self.local, "D1-PACKET.md")))
                self.assertFalse(os.path.exists(
                    os.path.join(self.local, "doc-review-%s.skeleton.toml" % TAG)))
                self.assertTrue(os.path.isdir(os.path.join(self.local, "d1-skeleton")),
                                "the raw capture is kept")

    def test_a_failed_generator_writes_no_packet(self):
        code, out = self.d1("--inherit-from", os.path.join(self.dir, "no-such-review.toml"))
        self.assertEqual(code, 1, out)
        self.assertIn("the skeleton generator ended with", out)
        self.assertFalse(os.path.exists(os.path.join(self.local, "D1-PACKET.md")))

    def test_a_second_run_is_refused(self):
        self.assertEqual(self.d1()[0], 0)
        code, out = self.d1()
        self.assertEqual(code, 1, out)
        self.assertIn("never taken twice", out)


class ServerIdentity(Case):
    """AC-07: F1 and F3 write a packet only for a server running the candidate."""

    def refused(self, gate, why, **state):
        for k, v in state.items():
            self.state(k.replace("_", "-"), v)
        code, out = (self.f1 if gate == "f1" else self.f3)()
        self.assertEqual(code, 1, out)
        self.assertIn("does not run the candidate %s at %s" % (TAG, COMMIT[:12]), out)
        self.assertIn(why, out)
        self.assertIn("No packet was written", out)
        name = gate.upper()
        self.assertFalse(os.path.exists(os.path.join(self.host_dir, "%s-PACKET.md" % name)))
        self.assertFalse([n for n in os.listdir(self.host_dir) if n.endswith(".skeleton.toml")])
        cap = os.path.join(self.host_dir, gate + "-readings")
        ec.verify_capture(cap, tag=TAG, commit=COMMIT)  # the raw capture is kept, intact
        return out

    def each_gate(self, why, **state):
        for gate in ("f1", "f3"):
            with self.subTest(gate=gate):
                shutil.rmtree(self.evidence, True)
                shutil.rmtree(self.remote, True)
                for f in os.listdir(self.fake):
                    if f.startswith(("binary-", "api-", "version-")):
                        os.unlink(os.path.join(self.fake, f))
                self.refused(gate, why, **state)

    def test_an_older_release_is_refused(self):
        # The reviewer's reproduction: 0.8.3 at 79f18f78, packets asked for v0.9.0.
        self.each_gate("reports version 0.8.3, not the candidate's 0.9.0",
                       binary_version="0.8.3", binary_commit="79f18f78",
                       api_version="0.8.3", api_commit="79f18f78")

    def test_the_same_version_from_another_commit_is_refused(self):
        self.each_gate("reports commit 79f18f78, not the candidate's 474d9af26e45",
                       binary_commit="79f18f78", api_commit="79f18f78")

    def test_a_service_not_restarted_onto_the_candidate_is_refused(self):
        self.each_gate("the running service (0.8.3, 79f18f78) differ; was the service restarted",
                       api_version="0.8.3", api_commit="79f18f78")

    def test_missing_or_malformed_identity_is_refused(self):
        for why, state in (
                ("reports commit 'unknown', not a commit id",
                 {"binary_commit": "unknown", "api_commit": "unknown"}),
                ("reports commit '474d', not a commit id",
                 {"binary_commit": "474d", "api_commit": "474d"}),
                ("has no openwatch and commit strings",
                 {"version_body": '{"openwatch":"0.9.0","kensa":"0.10.0"}'}),
                ("has no openwatch and commit strings", {"version_body": '{"version":"0.9.0"}'}),
                ("Expecting value", {"version_body": "<html>502</html>"}),
                ("does not report one version and one commit",
                 {"binary_version_out": "openwatch 0.9.0"})):
            with self.subTest(why=why):
                self.each_gate(why, **state)

    def test_a_version_endpoint_that_does_not_answer_200_fails_its_section(self):
        # Refused one step earlier, as a failed section, with the raw capture kept.
        self.state("version-code", "503")
        for gate in ("f1", "f3"):
            with self.subTest(gate=gate):
                shutil.rmtree(self.evidence, True)
                shutil.rmtree(self.remote, True)
                code, out = (self.f1 if gate == "f1" else self.f3)()
                self.assertEqual(code, 1, out)
                self.assertIn("failed: version endpoint (exit 1)", out)
                self.assertFalse(os.path.exists(
                    os.path.join(self.host_dir, "%s-PACKET.md" % gate.upper())))
                self.assertIn("http 503", read_text(os.path.join(
                    self.host_dir, gate + "-readings", "stdout")))

    def test_a_full_commit_and_the_candidate_are_accepted(self):
        self.state("binary-commit", COMMIT)
        self.state("api-commit", COMMIT)
        for gate in (self.f1, self.f3):
            code, out = gate()
            self.assertEqual(code, 0, out)
        doc = tomllib.loads(read_text(self.skeleton("F3", "fleet-scan-variables")))
        self.assertIn("The server runs openwatch 0.9.0, commit %s" % COMMIT, doc["server_records"])


class PacketBoundaries(Case):
    """AC-05: explicit timeouts, and the server scripts change nothing."""

    def test_every_capture_carries_its_declared_timeout(self):
        self.assertEqual(self.f1()[0], 0)
        self.assertEqual(self.f3()[0], 0)
        allowed = {rk.READ_TIMEOUT, rk.READ_TIMEOUT + rk.rp.SSH_MARGIN, rk.TRANSFER_TIMEOUT}
        for n in sorted(os.listdir(self.host_dir)):
            p = os.path.join(self.host_dir, n)
            if os.path.isdir(p):
                rec = ec.verify_capture(p, tag=TAG, commit=COMMIT, allow_incomplete=True)
                self.assertIn(rec["invocation"]["timeout_seconds"], allowed, n)
        for gate in ("f1", "f3"):
            with open(os.path.join(self.remote, TAG, "packets", gate + "-readings",
                                   "record.json")) as f:
                self.assertEqual(json.load(f)["invocation"]["timeout_seconds"], rk.READ_TIMEOUT)

    def test_a_missing_timeout_is_refused_before_contact(self):
        for name in ("READ_TIMEOUT", "TRANSFER_TIMEOUT", "D1_TIMEOUT"):
            with self.subTest(name=name):
                old = getattr(rk, name)
                setattr(rk, name, 0)
                try:
                    code, out = self.f1()
                finally:
                    setattr(rk, name, old)
                self.assertEqual(code, 1, out)
                self.assertIn("%s is not an explicit positive timeout" % name, out)
        self.assertEqual(self.calls(), [])

    def test_the_server_scripts_change_nothing(self):
        import re
        for script in sorted(os.listdir(rk.SCRIPTS)):
            text = read_text(rk.SCRIPTS / script)
            body = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
            for pattern in (r"systemctl", r"\breboot\b", r"\bdnf\b", r"apt-get", r"\brpm\b",
                            r"\b(INSERT|UPDATE|DELETE|TRUNCATE|ALTER|DROP|CREATE|GRANT)\b",
                            r"pg_dump|pg_restore"):
                self.assertIsNone(re.search(pattern, body), "%s: %s" % (script, pattern))
            # No pipeline: a pipe hides the first command's status. Quoted
            # strings (psql's " | " column separator) and || are not pipes.
            unquoted = re.sub(r'"[^"\n]*"|\'[^\'\n]*\'', "", body)
            self.assertIsNone(re.search(r"(?<!\|)\|(?!\|)", unquoted), "%s: a pipe" % script)
            if re.search(r"\bpsql\b", body):
                self.assertEqual(script, "common.sh", "psql outside read_sql in %s" % script)
            for m in re.finditer(r"\brm\b[^\n]*", body):
                self.assertIn("$WORK", m.group(0), "%s: %s" % (script, m.group(0)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
