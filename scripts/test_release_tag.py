#!/usr/bin/env python3
"""Tests for the explicit-SHA release tagger (CP bugs/OW-118).

    python3 -S scripts/test_release_tag.py

Real git repositories (a bare origin and a working clone), a throwaway GnuPG
home with generated keys, and a fake `gh` that lists release tags from a
file. The user's own git and GnuPG configuration is never read or changed.
One class per criterion of spec release-tagging; packaging/tests/
release_tag_test.go counts the passing cases. No network.
"""

import contextlib
import importlib.util
import io
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

_here = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("release_tag", _here / "release_tag.py")
rt = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rt)

CHECK_SCRIPT = _here.parent / "packaging" / "check-tag-version.sh"
VERSION = "0.9.0"
TAG = "v" + VERSION


def run(argv, cwd=None, env=None, input_bytes=None, check=True):
    r = subprocess.run(argv, cwd=cwd, env=env, input=input_bytes, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
    if check and r.returncode != 0:
        raise AssertionError("%s: %s" % (argv, r.stderr.decode()))
    return r


class Keys(object):
    """One throwaway GnuPG home for the whole suite: generating keys is slow."""

    home = None

    @classmethod
    def setup(cls):
        if cls.home:
            return
        # gpg-agent's socket path must stay short.
        cls.home = tempfile.mkdtemp(prefix="rtg-", dir="/tmp")
        os.chmod(cls.home, 0o700)
        cls.env = dict(os.environ, GNUPGHOME=cls.home)
        cls.release = cls.gen("Release Test <release@example.invalid>")
        cls.other = cls.gen("Other Test <other@example.invalid>")
        cls.nosecret = cls.gen("No Secret <nosecret@example.invalid>")
        cls.nosecret_pub = run(["gpg", "--batch", "--armor", "--export", cls.nosecret],
                               env=cls.env).stdout
        run(["gpg", "--batch", "--yes", "--delete-secret-keys", cls.nosecret], env=cls.env)

    @classmethod
    def gen(cls, uid):
        run(["gpg", "--batch", "--passphrase", "", "--quick-gen-key", uid, "ed25519", "sign",
             "1d"], env=cls.env)
        out = run(["gpg", "--batch", "--with-colons", "--list-keys", uid], env=cls.env)
        return rt._primary_fingerprints(out.stdout.decode())[0]

    @classmethod
    def teardown(cls):
        if cls.home:
            run(["gpgconf", "--kill", "gpg-agent"], env=cls.env, check=False)
            shutil.rmtree(cls.home, True)
            cls.home = None


def setUpModule():
    Keys.setup()


def tearDownModule():
    Keys.teardown()


class Case(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="reltag-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.env = dict(Keys.env, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
                        GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
                        GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")
        self.old_env = dict(os.environ)
        os.environ.clear()
        os.environ.update(self.env)
        self.addCleanup(self.restore_env)
        self.origin = os.path.join(self.dir, "origin.git")
        self.work = os.path.join(self.dir, "work")
        self.git("init", "--quiet", "--bare", "--initial-branch=main", self.origin, cwd=self.dir)
        self.git("clone", "--quiet", self.origin, self.work, cwd=self.dir)
        self.releases = os.path.join(self.dir, "releases.txt")
        open(self.releases, "w").close()
        self.gh = os.path.join(self.dir, "gh")
        with open(self.gh, "w") as f:
            f.write('#!/bin/sh\n[ -f "%s.fail" ] && { echo "gh: auth" >&2; exit 4; }\n'
                    'cat "%s"\n' % (self.releases, self.releases))
        os.chmod(self.gh, 0o755)
        self.candidate = self.commit_release(VERSION, "candidate")
        self.git("push", "--quiet", "origin", "main")

    def restore_env(self):
        os.environ.clear()
        os.environ.update(self.old_env)

    def git(self, *args, **kw):
        return run(["git"] + list(args), cwd=kw.pop("cwd", self.work), env=self.env, **kw)

    def write(self, rel, text, mode=0o644):
        p = os.path.join(self.work, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb" if isinstance(text, bytes) else "w") as f:
            f.write(text)
        os.chmod(p, mode)

    def commit_release(self, version, message, readme=None, changelog=None, keys=None,
                       check=None):
        self.write("packaging/version.env", 'VERSION="%s"\nCODENAME="Test"\n' % version)
        self.write("README.md", "> The current version is `%s`.\n" % (readme or version))
        self.write("CHANGELOG.md", "## [Unreleased]\n\n## [%s] Test (2026-10-10)\n"
                   % (changelog or version))
        with open(CHECK_SCRIPT) as f:
            self.write("packaging/check-tag-version.sh", check or f.read(), mode=0o755)
        if keys is None:
            keys = run(["gpg", "--batch", "--armor", "--export", Keys.release],
                       env=self.env).stdout
        self.write("security/KEYS", keys)
        self.git("add", "-A")
        self.git("commit", "--quiet", "--allow-empty", "-m", message)
        return self.git("rev-parse", "HEAD").stdout.decode().strip()

    def tagger(self, *extra, commit=None, key=None):
        out = io.StringIO()
        code = rt.main(["--commit", commit or self.candidate, "--key", key or Keys.release,
                        "--repo", self.work, "--gh", self.gh] + list(extra), out=out)
        return code, out.getvalue()

    def origin_refs(self):
        return self.git("ls-remote", self.origin).stdout.decode().split("\n")

    def origin_tags(self):
        return [l for l in self.origin_refs() if "refs/tags/" in l]

    def local_tags(self):
        return self.git("tag", "--list").stdout.decode().split()


class TagExplicitCandidate(Case):
    """AC-01: the candidate is a full SHA on origin/main, never a branch."""

    def test_a_dry_run_checks_everything_and_creates_nothing(self):
        code, out = self.tagger()
        self.assertEqual(code, 0, out)
        self.assertIn("DRY RUN", out)
        self.assertEqual(out.count("\nok ") + out.startswith("ok "), 6, out)
        self.assertEqual(self.local_tags(), [])
        self.assertEqual(self.origin_tags(), [])

    def test_the_candidate_is_tagged_after_main_moves_on_with_the_same_version(self):
        later = self.commit_release(VERSION, "later work, same VERSION")
        self.git("push", "--quiet", "origin", "main")
        self.assertNotEqual(later, self.candidate)
        code, out = self.tagger("--sign")
        self.assertEqual(code, 0, out)
        code, out = self.tagger("--push")
        self.assertEqual(code, 0, out)
        peeled = self.git("ls-remote", self.origin, "refs/tags/%s^{}" % TAG).stdout.decode()
        self.assertTrue(peeled.startswith(self.candidate), peeled)
        self.assertNotIn(later, peeled)

    def test_branch_names_short_and_malformed_shas_are_refused(self):
        for bad in ("main", "HEAD", "origin/main", self.candidate[:12], self.candidate.upper(),
                    self.candidate + "0"):
            code, out = self.tagger(commit=bad)
            self.assertEqual(code, 1, bad)
            self.assertIn("full 40-character", out)
        self.assertEqual(self.local_tags(), [])

    def test_an_unknown_commit_is_refused(self):
        code, out = self.tagger(commit="0" * 40)
        self.assertEqual(code, 1)
        self.assertIn("is not a commit", out)

    def test_a_commit_not_on_main_is_refused(self):
        self.git("switch", "--quiet", "-c", "side")
        side = self.commit_release(VERSION, "side branch")
        self.git("push", "--quiet", "origin", "side")
        code, out = self.tagger(commit=side)
        self.assertEqual(code, 1)
        self.assertIn("not an ancestor of origin/main", out)


class TagVersionAgreement(Case):
    """AC-02: the tag is derived from the candidate's own files, which must agree."""

    def candidate_with(self, **kw):
        c = self.commit_release(kw.pop("version", VERSION), "variant", **kw)
        self.git("push", "--quiet", "origin", "main")
        return c

    def test_readme_or_changelog_disagreement_is_refused(self):
        for kw in ({"readme": "0.8.9"}, {"changelog": "0.8.9"}):
            code, out = self.tagger(commit=self.candidate_with(**kw))
            self.assertEqual(code, 1, kw)
            self.assertIn("versions disagree", out)

    def test_a_version_that_makes_no_tag_is_refused(self):
        code, out = self.tagger(commit=self.candidate_with(version="0.9"))
        self.assertEqual(code, 1)
        self.assertIn("does not make a release tag", out)

    def test_the_candidates_own_check_script_is_run(self):
        c = self.candidate_with(check="#!/bin/sh\necho refused-by-candidate >&2\nexit 1\n")
        code, out = self.tagger(commit=c)
        self.assertEqual(code, 1)
        self.assertIn("refused-by-candidate", out)

    def test_the_tag_name_comes_from_the_candidate_not_from_main(self):
        self.commit_release("0.9.1", "next version on main")
        self.git("push", "--quiet", "origin", "main")
        code, out = self.tagger()
        self.assertEqual(code, 0, out)
        self.assertIn("DRY RUN: every check passed for %s -> %s" % (TAG, self.candidate), out)


class TagNeverReused(Case):
    """AC-03: an existing tag, anywhere, refuses the candidate."""

    def test_a_local_tag_is_refused(self):
        self.git("tag", TAG, self.candidate)
        code, out = self.tagger()
        self.assertEqual(code, 1)
        self.assertIn("already exists locally", out)

    def test_a_tag_on_origin_is_refused(self):
        other = os.path.join(self.dir, "other")
        self.git("clone", "--quiet", self.origin, other, cwd=self.dir)
        self.git("tag", TAG, "HEAD", cwd=other)
        self.git("push", "--quiet", "origin", "refs/tags/%s" % TAG, cwd=other)
        self.git("tag", "-d", TAG, cwd=other)
        code, out = self.tagger()
        self.assertEqual(code, 1)
        self.assertIn("already exists on origin", out)
        self.assertEqual(self.local_tags(), [], "origin's tags must not be fetched")

    def test_a_release_or_draft_using_the_tag_is_refused(self):
        with open(self.releases, "w") as f:
            f.write("v0.8.4\n%s\n" % TAG)
        code, out = self.tagger()
        self.assertEqual(code, 1)
        self.assertIn("possibly a draft", out)

    def test_an_unreadable_release_list_is_refused(self):
        open(self.releases + ".fail", "w").close()
        code, out = self.tagger()
        self.assertEqual(code, 1)
        self.assertIn("exited 4", out)


class TagReleaseKey(Case):
    """AC-04: only a primary key in security/KEYS at the candidate, with its secret."""

    def test_a_key_not_in_keys_is_refused(self):
        code, out = self.tagger(key=Keys.other)
        self.assertEqual(code, 1)
        self.assertIn("not a primary key in security/KEYS", out)

    def test_a_malformed_fingerprint_is_refused(self):
        for bad in (Keys.release[-16:], Keys.release.lower(), "release"):
            code, out = self.tagger(key=bad)
            self.assertEqual(code, 1, bad)
            self.assertIn("full 40-character fingerprint", out)

    def test_a_key_without_its_secret_is_refused(self):
        c = self.commit_release(VERSION, "KEYS names a key we cannot sign with",
                                keys=Keys.nosecret_pub)
        self.git("push", "--quiet", "origin", "main")
        code, out = self.tagger(commit=c, key=Keys.nosecret)
        self.assertEqual(code, 1)
        self.assertIn("secret key", out)


class TagSignAndPush(Case):
    """AC-05: sign the candidate, verify the object and signature, push only that ref."""

    def test_sign_creates_a_verified_tag_and_pushes_nothing(self):
        code, out = self.tagger("--sign")
        self.assertEqual(code, 0, out)
        self.assertIn("SIGNED %s -> %s locally. Nothing was pushed." % (TAG, self.candidate), out)
        self.assertEqual(self.git("cat-file", "-t", TAG).stdout.decode().strip(), "tag")
        self.assertEqual(self.git("rev-parse", TAG + "^{commit}").stdout.decode().strip(),
                         self.candidate)
        self.assertEqual(self.origin_tags(), [])

    def test_push_sends_only_the_tag_ref_and_checks_origin(self):
        self.tagger("--sign")
        main_before = [l for l in self.origin_refs() if "refs/heads/" in l]
        self.write("unpushed.txt", "local work\n")
        self.git("add", "-A")
        self.git("commit", "--quiet", "-m", "must not be pushed")
        self.git("tag", "unrelated-local-tag")
        code, out = self.tagger("--push")
        self.assertEqual(code, 0, out)
        self.assertIn("PUSHED %s -> %s" % (TAG, self.candidate), out)
        self.assertEqual([l for l in self.origin_refs() if "refs/heads/" in l], main_before)
        tags = dict(reversed(l.split("\t")) for l in self.origin_tags() if l)
        self.assertEqual(sorted(tags), ["refs/tags/" + TAG, "refs/tags/%s^{}" % TAG])
        local_obj = self.git("rev-parse", "refs/tags/" + TAG).stdout.decode().strip()
        self.assertEqual(tags["refs/tags/" + TAG], local_obj)
        self.assertEqual(tags["refs/tags/%s^{}" % TAG], self.candidate)

    def test_push_refuses_an_unsigned_or_foreign_or_misplaced_tag(self):
        later = self.commit_release(VERSION, "later")
        self.git("push", "--quiet", "origin", "main")
        cases = (
            ("unsigned", ["tag", "-a", "-m", TAG, TAG, self.candidate], "valid signature"),
            ("foreign key", ["tag", "-s", "-u", Keys.other, "-m", TAG, TAG, self.candidate],
             "valid signature from " + Keys.release),
            ("lightweight", ["tag", TAG, self.candidate], "not an annotated tag object"),
            ("wrong commit", ["tag", "-s", "-u", Keys.release, "-m", TAG, TAG, later],
             "not commit " + self.candidate),
        )
        for name, argv, reason in cases:
            self.git(*argv)
            code, out = self.tagger("--push")
            self.assertEqual(code, 1, name)
            self.assertIn(reason, out, name)
            self.assertEqual(self.origin_tags(), [], name)
            self.git("tag", "-d", TAG)

    def test_a_signing_failure_leaves_nothing_to_push(self):
        fail = os.path.join(self.dir, "gpg-fail")
        with open(fail, "w") as f:
            f.write("#!/bin/sh\necho 'gpg: signing failed: Operation cancelled' >&2\nexit 2\n")
        os.chmod(fail, 0o755)
        self.git("config", "gpg.program", fail)
        code, out = self.tagger("--sign")
        self.assertEqual(code, 1)
        self.assertIn("signing failed, no tag was pushed", out)
        self.assertEqual(self.local_tags(), [])
        self.assertEqual(self.origin_tags(), [])

    def test_the_repository_signing_key_is_not_used(self):
        # The repo config names another key; the tag must still be signed by --key.
        self.git("config", "user.signingkey", Keys.other)
        self.git("config", "tag.gpgSign", "true")
        code, out = self.tagger("--sign")
        self.assertEqual(code, 0, out)
        raw = self.git("verify-tag", "--raw", TAG, check=False).stderr.decode()
        self.assertIn(Keys.release, raw)
        self.assertNotIn("VALIDSIG " + Keys.other, raw)

    def test_sign_and_push_cannot_be_combined(self):
        err = io.StringIO()
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(err):
            rt.main(["--commit", self.candidate, "--key", Keys.release, "--repo", self.work,
                     "--gh", self.gh, "--sign", "--push"], out=io.StringIO())
        self.assertIn("not allowed with argument", err.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
