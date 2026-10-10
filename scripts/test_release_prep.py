#!/usr/bin/env python3
"""Tests for the release-preparation F2 workflow.

    python3 -S scripts/test_release_prep.py

The fleet host is simulated: the transport is `sh -c` instead of ssh and the
snapshot is a fake script reading state the test controls. Everything else is
real: the capture library runs as it would on a host, the capture is fetched
with tar and verified. One class per criterion of spec release-preparation;
packaging/tests/release_prep_test.go counts the passing cases. No network.
"""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

_here = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("release_prep", _here / "release_prep.py")
rp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rp)
ec = rp.ec

TAG = "v0.8.5"
COMMIT = "474d9af26e457fc6a47b5475fab87394433a687b"  # pragma: allowlist secret
OTHER_COMMIT = "92ea8fc534981208dd9b25624aeee6079df9b59c"  # pragma: allowlist secret

FAKE_SNAPSHOT = """\
echo "== auditctl -s"; cat "$F2_FAKE_DIR/status"; echo "== exit 0"
echo "== rules.d contents"; cat "$F2_FAKE_DIR/rules"; echo "== exit 0"
if [ -f "$F2_FAKE_DIR/hang" ]; then exec sleep 60; fi
if [ -f "$F2_FAKE_DIR/fail" ]; then echo "snapshot failed" >&2; exit 3; fi
exit 0
"""

# Truncates the tar stream when the test asks, to simulate a broken transfer.
TRANSPORT = """\
case "$1" in
  "tar "*|*" tar "*) if [ -f "$F2_FAKE_DIR/corrupt" ]; then sh -c "$1" | head -c 1500; exit 0; fi ;;
  *" run --out "*) if [ -f "$F2_FAKE_DIR/swap" ]; then
      sh -c "$1"; rc=$?
      "$F2_PYTHON" -S "$F2_FAKE_DIR/../swap.py" "$1"
      exit $rc
    fi ;;
esac
exec sh -c "$1"
"""

# Replaces the capture the remote run just made with one bound to another
# machine, as if the address had reached a different host for this phase.
SWAP = """\
import importlib.util, os, shlex, shutil, sys
spec = importlib.util.spec_from_file_location("ec", os.environ["F2_LIBRARY"])
ec = importlib.util.module_from_spec(spec); spec.loader.exec_module(ec)
words = shlex.split(sys.argv[1].split(" && ")[-1])
out, name = words[words.index("--out") + 1], words[words.index("--name") + 1]
tag, commit = words[words.index("--tag") + 1], words[words.index("--commit") + 1]
shutil.rmtree(os.path.join(out, name))
host = dict(ec.host_identity(), machine_id="f" * 32)
ec.capture(["sh", "-c", "echo '== auditctl -s'; echo 'enabled 2'"], out, name, tag, commit,
           host=host, timeout=30)
"""

ROLLBACK = "roll the remediation back"


class Case(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="relprep-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.fake = os.path.join(self.dir, "host-state")
        os.mkdir(self.fake)
        os.environ["F2_FAKE_DIR"] = self.fake
        self.set_state(status="enabled 2\nfailure 1", rules="-w /var/log/sudo.log -p wa")
        self.snapshot = os.path.join(self.dir, "snapshot.sh")
        with open(self.snapshot, "w") as f:
            f.write(FAKE_SNAPSHOT)
        with open(os.path.join(self.dir, "swap.py"), "w") as f:
            f.write(SWAP)
        os.environ["F2_PYTHON"] = sys.executable
        os.environ["F2_LIBRARY"] = str(rp.LIBRARY)
        transport = os.path.join(self.dir, "transport.sh")
        with open(transport, "w") as f:
            f.write(TRANSPORT)
        self.remote = os.path.join(self.dir, "remote")
        self.evidence = os.path.join(self.dir, "evidence")
        self.args = ["--host", "owas-rhn02", "--tag", TAG, "--commit", COMMIT,
                     "--evidence", self.evidence, "--sudo", "",
                     "--remote-python", sys.executable, "--remote-dir", self.remote,
                     "--snapshot", self.snapshot, "--transport", json.dumps(["sh", transport])]
        self.host_dir = os.path.join(self.evidence, "f2", "owas-rhn02")
        self.remote_dir = os.path.join(self.remote, TAG, "f2")

    def set_state(self, status=None, rules=None):
        for name, value in (("status", status), ("rules", rules)):
            if value is not None:
                with open(os.path.join(self.fake, name), "w") as f:
                    f.write(value + "\n")

    def flag(self, name, on=True):
        p = os.path.join(self.fake, name)
        if on:
            open(p, "w").close()
        elif os.path.exists(p):
            os.unlink(p)

    def step(self, name, *extra):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = rp.main(["f2", name] + self.args + list(extra))
        return code, out.getvalue(), err.getvalue()

    def ok(self, name):
        code, out, err = self.step(name)
        self.assertEqual(code, 0, err)
        return out

    def local(self, *parts):
        return os.path.join(self.host_dir, *parts)

    def wait_for(self, pred, seconds=10):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if pred():
                return True
            time.sleep(0.05)
        return False


class F2PhasesInOrder(Case):
    """AC-01: three verified captures, in order, with the next step named."""

    def test_the_three_phases_capture_verify_and_prompt_in_order(self):
        out = self.ok("preflight")
        self.assertIn("remediate the audit_rule_set rule", out)
        self.assertNotIn(ROLLBACK, out)
        self.set_state(rules="-w /var/log/sudo.log -p wa\n-w /etc/sudoers -p wa")
        out = self.ok("staged")
        self.assertIn(ROLLBACK, out)
        self.assertIn(self.local("f2-staged"), out)
        self.set_state(rules="-w /var/log/sudo.log -p wa")
        out = self.ok("after")
        self.assertIn("f2 packet", out)
        for phase in ("preflight", "staged", "after"):
            rec = ec.verify_capture(self.local("f2-" + phase), tag=TAG, commit=COMMIT)
            self.assertEqual(rec["exit"]["code"], 0)
            ec.verify_capture(self.local("f2-%s.remote-run" % phase), tag=TAG, commit=COMMIT)
            ec.verify_capture(self.local("f2-%s.transfer" % phase), tag=TAG, commit=COMMIT)
        with open(self.local("f2-staged", "stdout"), "rb") as f:
            self.assertIn(b"-w /etc/sudoers -p wa", f.read())

    def test_the_library_sent_to_the_host_is_recorded_by_digest(self):
        self.ok("preflight")
        with open(self.local("f2-preflight.remote-run", "record.json")) as f:
            rec = json.load(f)
        with open(rp.LIBRARY, "rb") as f:
            want = hashlib.sha256(f.read()).hexdigest()
        self.assertEqual(rec["invocation"]["stdin"]["sha256"], want)

    def test_status_reports_progress(self):
        code, out, _ = self.step("status")
        self.assertEqual(code, 0)
        self.assertIn("next: preflight", out)
        self.ok("preflight")
        self.ok("staged")
        _, out, _ = self.step("status")
        self.assertRegex(out, r"staged\s+verified")
        self.assertIn("next: after", out)

    def test_a_phase_is_never_captured_twice(self):
        self.ok("preflight")
        code, _, err = self.step("preflight")
        self.assertEqual(code, 1)
        self.assertIn("already exists", err)


class F2RollbackGate(Case):
    """AC-02: rollback is prompted only after the staged capture verifies."""

    def assert_no_rollback(self, code, out):
        self.assertEqual(code, 1)
        self.assertNotIn(ROLLBACK, out)

    def test_staged_needs_a_verified_preflight(self):
        code, out, err = self.step("staged")
        self.assert_no_rollback(code, out)
        self.assertIn("f2-preflight", err)
        self.assertFalse(os.path.exists(self.remote), "the host was contacted")

    def test_after_needs_a_verified_staged_capture(self):
        self.ok("preflight")
        code, out, err = self.step("after")
        self.assertEqual(code, 1)
        self.assertIn("f2-staged", err)
        self.assertFalse(os.path.exists(self.local("f2-after")))

    def test_a_failed_staged_snapshot_gives_no_rollback_prompt(self):
        self.ok("preflight")
        self.flag("fail")
        code, out, err = self.step("staged")
        self.assert_no_rollback(code, out)
        self.assertIn("ended with exit=", err)
        self.flag("fail", False)
        code, _, err = self.step("after")
        self.assertEqual(code, 1)

    def test_a_broken_transfer_gives_no_rollback_prompt(self):
        self.ok("preflight")
        self.flag("corrupt")
        code, out, err = self.step("staged")
        self.assert_no_rollback(code, out)
        self.assertIn("was not accepted", err)
        self.assertTrue(os.path.isdir(self.local("f2-staged.transfer-failed")))
        self.assertFalse(os.path.exists(self.local("f2-staged")))
        self.flag("corrupt", False)
        code, _, _ = self.step("after")
        self.assertEqual(code, 1)

    def test_an_altered_staged_capture_blocks_after(self):
        self.ok("preflight")
        self.ok("staged")
        p = self.local("f2-staged", "stdout")
        os.chmod(p, 0o600)
        with open(p, "ab") as f:
            f.write(b"edited\n")
        code, _, err = self.step("after")
        self.assertEqual(code, 1)
        self.assertIn("does not verify", err)
        _, out, _ = self.step("status")
        self.assertIn("next: staged", out)

    def test_staged_from_another_machine_is_refused(self):
        self.ok("preflight")
        self.flag("swap")
        code, out, err = self.step("staged")
        self.assert_no_rollback(code, out)
        self.assertIn("machine-id", err)
        self.assertTrue(os.path.isdir(self.local("f2-staged.transfer-failed")))
        self.assertFalse(os.path.exists(self.local("f2-staged")))

    def test_staged_from_another_candidate_does_not_count(self):
        self.ok("preflight")
        self.ok("staged")
        i = self.args.index("--commit")
        self.args[i + 1] = OTHER_COMMIT
        code, _, err = self.step("after")
        self.assertEqual(code, 1)
        self.assertIn("does not verify", err)


class F2Preconditions(Case):
    """AC-03: the host and candidate are checked before anything is staged."""

    def test_preflight_requires_enabled_2(self):
        self.set_state(status="enabled 1")
        code, out, err = self.step("preflight")
        self.assertEqual(code, 1)
        self.assertIn("enabled 2", err)
        self.assertNotIn("remediate", out)
        self.assertTrue(os.path.isdir(self.local("f2-preflight")), "the evidence must be kept")
        code, _, _ = self.step("staged")
        self.assertEqual(code, 1)

    def test_bad_host_or_candidate_is_refused_before_contact(self):
        for flag, value in (("--host", "../x"), ("--commit", "abc"), ("--tag", "0.8.5")):
            args = list(self.args)
            args[args.index(flag) + 1] = value
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = rp.main(["f2", "preflight"] + args)
            self.assertEqual(code, 1, flag)
        self.assertFalse(os.path.exists(self.remote))
        self.assertFalse(os.path.exists(self.evidence))

    def test_the_maintained_snapshot_is_read_only(self):
        with open(rp.SNAPSHOT) as f:
            text = f.read()
        body = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
        # The only writes allowed: auditctl's output into the private temporary
        # file, and removing that file.
        allowed = ('auditctl -l > "$tmp"', 'rm -f -- "$tmp"')
        checked = body
        for line in allowed:
            self.assertIn(line, checked)
            checked = checked.replace(line, "")
        for pattern in (r"\brm\b", r"\bmv\b", r"\bcp\b", r"\btee\b", r"sed -i", r"augenrules",
                        r"auditctl -[ReDaAwW]", r"systemctl", r"[^2]>[^&]", r"\bdnf\b",
                        r"\byum\b", r"\bapt"):
            self.assertIsNone(re.search(pattern, checked), pattern)
        for section in ("auditctl -s", "rules.d contents", "rules.d digests", "loaded rules",
                        "audit.rules digest", "boot"):
            self.assertIn('section "%s"' % section, text)
        # POSIX sh has no pipefail, so there are no pipes at all; and output is
        # never held in a variable, which would strip trailing newlines.
        for line in body.splitlines():
            self.assertIsNone(re.search(r"(?<!\|)\|(?!\|)", line), line)
        self.assertNotIn("$(auditctl", body)


AUDITCTL_SHIM = """\
#!/bin/sh
case "$1" in
  -s) if [ -f "$F2_FAKE_DIR/fail-s" ]; then echo "auditctl: status failed" >&2; exit 1; fi
      cat "$F2_FAKE_DIR/status" ;;
  -l) if [ -f "$F2_FAKE_DIR/rules_bytes" ]; then cat "$F2_FAKE_DIR/rules_bytes"
      elif [ -f "$F2_FAKE_DIR/fail-l" ]; then echo "-w /partial -p wa"
      else cat "$F2_FAKE_DIR/rules"; fi
      if [ -f "$F2_FAKE_DIR/hang-l" ]; then exec sleep 60; fi
      if [ -f "$F2_FAKE_DIR/fail-l" ]; then echo "auditctl: list failed" >&2; exit 42; fi ;;
  *) exit 2 ;;
esac
"""


class F2MaintainedSnapshot(Case):
    """AC-06: the maintained snapshot fails when any required section fails.

    The real release/prep/f2-host-snapshot.sh runs against a fake root, with
    auditctl and uptime replaced by shims on PATH."""

    def setUp(self):
        Case.setUp(self)
        self.root = os.path.join(self.dir, "root")
        rules = os.path.join(self.root, "etc", "audit", "rules.d")
        os.makedirs(rules)
        os.makedirs(os.path.join(self.root, "proc", "sys", "kernel", "random"))
        self.rules_dir = rules
        self.write(os.path.join(rules, "10-base.rules"), "-D\n-b 8192\n")
        self.write(os.path.join(rules, "50-sudo.rules"), "-w /var/log/sudo.log -p wa\n")
        self.write(os.path.join(self.root, "etc", "audit", "audit.rules"), "-D\n")
        self.write(os.path.join(self.root, "proc", "sys", "kernel", "random", "boot_id"), "b-1\n")
        shims = os.path.join(self.dir, "shims")
        os.mkdir(shims)
        self.write(os.path.join(shims, "auditctl"), AUDITCTL_SHIM, mode=0o755)
        self.write(os.path.join(shims, "uptime"), "#!/bin/sh\necho 2026-10-01 00:00:00\n",
                   mode=0o755)
        self.tmpdir = os.path.join(self.dir, "tmp")
        os.mkdir(self.tmpdir)
        old_tmp = os.environ.get("TMPDIR")
        os.environ["TMPDIR"] = self.tmpdir
        self.addCleanup(lambda: os.environ.pop("TMPDIR", None) if old_tmp is None
                        else os.environ.__setitem__("TMPDIR", old_tmp))
        old_path, old_root = os.environ.get("PATH", ""), os.environ.get("F2_SNAPSHOT_ROOT")
        os.environ["PATH"] = shims + os.pathsep + old_path
        os.environ["F2_SNAPSHOT_ROOT"] = self.root
        self.addCleanup(os.environ.__setitem__, "PATH", old_path)
        self.addCleanup(lambda: os.environ.pop("F2_SNAPSHOT_ROOT", None) if old_root is None
                        else os.environ.__setitem__("F2_SNAPSHOT_ROOT", old_root))
        i = self.args.index("--snapshot")
        self.args[i + 1] = str(rp.SNAPSHOT)

    def write(self, path, text, mode=0o644):
        with open(path, "w") as f:
            f.write(text)
        os.chmod(path, mode)

    def run_snapshot(self, raw=False):
        r = subprocess.run(["sh", str(rp.SNAPSHOT)], stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
        if raw:
            return r.returncode, r.stdout, r.stderr.decode()
        return r.returncode, r.stdout.decode(), r.stderr.decode()

    def loaded_rules_section(self, stdout):
        """(raw bytes, trailer byte count, trailer digest, section exit) from stdout bytes."""
        m = re.search(rb"== loaded rules\n(.*)\n--- auditctl -l output above: (\d+) bytes, "
                      rb"sha256 ([0-9a-f]{64})\n== exit (\d+)\n", stdout, re.S)
        self.assertIsNotNone(m, stdout[-400:])
        return m.group(1), int(m.group(2)), m.group(3).decode(), int(m.group(4))

    def assert_no_temporary_left(self):
        self.assertEqual(os.listdir(self.tmpdir), [])

    def broken_rules_file_before_a_good_one(self):
        os.symlink(os.path.join(self.dir, "absent"), os.path.join(self.rules_dir, "00-broken.rules"))

    def test_a_healthy_host_passes_every_phase(self):
        code, out, err = self.run_snapshot()
        self.assertEqual(code, 0, err)
        self.assertNotIn("== exit 1", out)
        self.assertIn("--- auditctl -l output above: ", out)
        self.assert_no_temporary_left()
        self.ok("preflight")
        self.ok("staged")
        self.ok("after")
        self.ok("packet")

    def test_a_failed_auditctl_list_fails_the_snapshot_and_keeps_its_output(self):
        self.flag("fail-l")
        code, out, err = self.run_snapshot()
        self.assertEqual(code, 1)
        self.assertIn("-w /partial -p wa", out)
        self.assertIn("== exit 42", out)
        self.assertIn("loaded rules (exit 42)", err)
        self.assert_no_temporary_left()

    def test_loaded_rules_are_emitted_byte_for_byte_with_their_digest(self):
        for raw, fails in ((b"rule\n\n\n", False), (b"rule", False), (b"", False),
                           (b"-w /a -p wa\n-w /b -p x\n", False),
                           (b"-w /partial -p wa\n\n", True), (b"partial-no-newline", True)):
            with open(os.path.join(self.fake, "rules_bytes"), "wb") as f:
                f.write(raw)
            self.flag("fail-l", fails)
            code, out, err = self.run_snapshot(raw=True)
            got, count, digest, status = self.loaded_rules_section(out)
            self.assertEqual(got, raw, raw)
            self.assertEqual(count, len(raw), raw)
            self.assertEqual(digest, hashlib.sha256(raw).hexdigest(), raw)
            self.assertEqual(status, 42 if fails else 0, raw)
            self.assertEqual(code, 1 if fails else 0, (raw, err))
            self.assert_no_temporary_left()

    def test_an_interrupted_snapshot_removes_its_temporary_file(self):
        self.flag("hang-l")
        p = subprocess.Popen(["sh", str(rp.SNAPSHOT)], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True)
        try:
            self.assertTrue(self.wait_for(lambda: len(os.listdir(self.tmpdir)) == 1),
                            "the temporary file never appeared")
            os.killpg(p.pid, signal.SIGTERM)
            p.communicate(timeout=30)
        finally:
            if p.poll() is None:
                os.killpg(p.pid, signal.SIGKILL)
                p.communicate()
        self.assertEqual(p.returncode, 143)
        self.assert_no_temporary_left()

    def test_staged_evidence_keeps_the_exact_loaded_rule_bytes(self):
        self.ok("preflight")
        raw = b"-w /var/log/sudo.log -p wa\n-w /etc/sudoers -p wa\n\n\n"
        with open(os.path.join(self.fake, "rules_bytes"), "wb") as f:
            f.write(raw)
        self.assertIn(ROLLBACK, self.ok("staged"))
        with open(self.local("f2-staged", "stdout"), "rb") as f:
            got, count, digest, status = self.loaded_rules_section(f.read())
        self.assertEqual((got, count, status), (raw, len(raw), 0))
        self.assertEqual(digest, hashlib.sha256(raw).hexdigest())

    def test_a_failed_read_before_a_good_one_fails_the_snapshot(self):
        self.broken_rules_file_before_a_good_one()
        code, out, err = self.run_snapshot()
        self.assertEqual(code, 1)
        self.assertIn("-w /var/log/sudo.log -p wa", out, "later files must still be printed")
        self.assertIn("rules.d contents (exit", err)
        self.assertIn("rules.d digests (exit", err)

    def test_an_empty_rules_directory_or_a_missing_boot_id_fails(self):
        for name in os.listdir(self.rules_dir):
            os.unlink(os.path.join(self.rules_dir, name))
        code, _, err = self.run_snapshot()
        self.assertEqual(code, 1)
        self.assertIn("rules.d contents (exit", err)
        self.write(os.path.join(self.rules_dir, "10-base.rules"), "-D\n")
        os.unlink(os.path.join(self.root, "proc", "sys", "kernel", "random", "boot_id"))
        code, _, err = self.run_snapshot()
        self.assertEqual(code, 1)
        self.assertIn("boot (exit", err)

    def assert_staged_rejected(self):
        code, out, err = self.step("staged")
        self.assertEqual(code, 1)
        self.assertNotIn(ROLLBACK, out)
        code, _, err2 = self.step("after")
        self.assertEqual(code, 1)
        self.assertIn("f2-staged", err2)
        code, _, err3 = self.step("packet")
        self.assertEqual(code, 1)
        return err

    def test_a_failed_auditctl_list_while_staged_gives_no_rollback_prompt(self):
        self.ok("preflight")
        self.flag("fail-l")
        err = self.assert_staged_rejected()
        self.assertIn("ended with exit=1", err)

    def test_a_failed_rules_read_while_staged_gives_no_rollback_prompt(self):
        self.ok("preflight")
        self.broken_rules_file_before_a_good_one()
        err = self.assert_staged_rejected()
        self.assertIn("ended with exit=1", err)

    def test_a_reported_failure_is_refused_even_when_the_script_exits_0(self):
        self.ok("preflight")
        masked = os.path.join(self.dir, "masked.sh")
        self.write(masked, FAKE_SNAPSHOT.replace(
            'echo "== rules.d contents"; cat "$F2_FAKE_DIR/rules"; echo "== exit 0"',
            'echo "== loaded rules"; echo "== exit 42"'))
        i = self.args.index("--snapshot")
        self.args[i + 1] = masked
        err = self.assert_staged_rejected()
        self.assertIn("failed sections: loaded rules (exit 42)", err)


class F2Timeouts(Case):
    """AC-04: every capture and transfer has an explicit timeout."""

    def test_every_capture_and_fetch_passes_the_declared_timeout(self):
        seen = []
        real_capture, real_fetch = ec.capture, ec.fetch

        def capture(*a, **kw):
            seen.append(("capture", kw.get("timeout")))
            return real_capture(*a, **kw)

        def fetch(*a, **kw):
            seen.append(("fetch", kw.get("timeout")))
            return real_fetch(*a, **kw)
        ec.capture, ec.fetch = capture, fetch
        self.addCleanup(setattr, ec, "capture", real_capture)
        self.addCleanup(setattr, ec, "fetch", real_fetch)
        self.ok("preflight")
        self.ok("staged")
        self.ok("after")
        # Per phase: the remote run, the fetch, and the fetch's own capture of
        # the transfer, which inherits the fetch's timeout.
        want = []
        for phase in rp.F2_PHASES:
            want += [("capture", phase.timeout + rp.SSH_MARGIN),
                     ("fetch", phase.transfer_timeout), ("capture", phase.transfer_timeout)]
        self.assertEqual(seen, want)
        with open(self.local("f2-staged.remote-run", "record.json")) as f:
            argv = json.load(f)["invocation"]["argv"]
        self.assertIn("--timeout %d" % rp._phase("staged").timeout, argv[-1])

    def test_a_phase_without_a_timeout_cannot_run(self):
        phase = rp._phase("preflight")
        for bad in (None, 0, -5):
            old = phase.timeout
            phase.timeout = bad
            try:
                code, _, err = self.step("preflight")
            finally:
                phase.timeout = old
            self.assertEqual(code, 1)
            self.assertIn("explicit positive timeout", err)
        self.assertFalse(os.path.exists(self.remote))

    def test_a_hung_snapshot_is_stopped_by_the_phase_timeout(self):
        phase = rp._phase("preflight")
        old, old_margin = phase.timeout, rp.SSH_MARGIN
        phase.timeout, rp.SSH_MARGIN = 1, 20
        self.addCleanup(setattr, phase, "timeout", old)
        self.addCleanup(setattr, rp, "SSH_MARGIN", old_margin)
        self.flag("hang")
        t0 = time.monotonic()
        code, out, err = self.step("preflight")
        self.assertLess(time.monotonic() - t0, 20)
        self.assertEqual(code, 1)
        self.assertNotIn("remediate", out)
        self.assertIn("the remote run of f2-preflight", err)
        self.assertFalse(os.path.exists(self.local("f2-preflight.transfer")), "fetch was attempted")
        self.assertTrue(os.path.isdir(os.path.join(self.remote_dir, "f2-preflight.timed-out")))
        self.assertFalse(os.path.exists(self.local("f2-preflight")))


class F2Packet(Case):
    """AC-05: the packet is derived from verified captures and records no verdict."""

    def test_packet_needs_all_three_phases(self):
        self.ok("preflight")
        self.ok("staged")
        code, _, err = self.step("packet")
        self.assertEqual(code, 1)
        self.assertIn("f2-after", err)
        self.assertFalse(os.path.exists(self.local("F2-PACKET.md")))

    def test_packet_shows_raw_digests_and_derived_changes_with_blank_confirmations(self):
        self.ok("preflight")
        self.set_state(rules="-w /var/log/sudo.log -p wa\n-w /etc/sudoers -p wa")
        self.ok("staged")
        self.set_state(rules="-w /var/log/sudo.log -p wa")
        self.ok("after")
        out = self.ok("packet")
        self.assertIn("F2-PACKET.md", out)
        with open(self.local("F2-PACKET.md")) as f:
            text = f.read()
        for phase in ("preflight", "staged", "after"):
            with open(self.local("f2-" + phase, "stdout"), "rb") as f:
                self.assertIn(hashlib.sha256(f.read()).hexdigest(), text)
        self.assertIn("+-w /etc/sudoers -p wa", text)
        self.assertIn("-w /etc/sudoers -p wa", text.split("### staged to after")[1])
        self.assertIn("Derived from the raw stdout files above, which are authoritative", text)
        self.assertIn("It records no verdict", text)
        for field in ("with a working Roll back: ______", "Observed by: ______",
                      "Observed at: ______"):
            self.assertIn(field, text)
        code, _, err = self.step("packet")
        self.assertEqual(code, 1)
        self.assertIn("never overwritten", err)


if __name__ == "__main__":
    unittest.main(verbosity=2)
