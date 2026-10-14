#!/usr/bin/env python3
"""Temporary-directory ownership for release checks and local test fixtures."""
import contextlib
import gc
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import warnings
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('release_status_cleanup', HERE / 'release-status.py')
rs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rs)


class TemporaryOwnership(unittest.TestCase):
    def setUp(self):
        self.parent = Path(self.enterContext(tempfile.TemporaryDirectory(prefix='ow-cleanup-test-')))
        self.enterContext(patch.object(tempfile, 'tempdir', str(self.parent)))

    def assert_empty(self):
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_tagged_checker_is_callable_after_import_directory_is_removed(self):
        source = b'def candidate_docs(c): return [c]\ndef eval_doc_review(*a): return "PASS", "ok"\n'
        with patch.object(rs, 'sh_bytes', return_value=(0, source)):
            mod = rs.load_tagged_checker('a' * 40)
        self.assert_empty()
        self.assertEqual(mod.candidate_docs('candidate'), ['candidate'])
        self.assertEqual(mod.eval_doc_review(), ('PASS', 'ok'))

    def test_tagged_checker_failure_and_interrupt_remove_import_directory(self):
        for source, error in [(b'raise RuntimeError("failed import")', None),
                              (b'MARK = 1', None), (b'raise KeyboardInterrupt()', KeyboardInterrupt)]:
            with self.subTest(source=source), patch.object(rs, 'sh_bytes', return_value=(0, source)):
                if error:
                    with self.assertRaises(error):
                        rs.load_tagged_checker('a' * 40)
                else:
                    self.assertIsNone(rs.load_tagged_checker('a' * 40))
            self.assert_empty()

    def test_evaluation_cleans_on_exhaustion_failure_interrupt_and_close(self):
        for ending in ('success', 'failure', 'interrupt', 'close'):
            with self.subTest(ending=ending):
                seen = []

                def gates(g, tag, commit, directory):
                    seen.append(directory)
                    (directory / 'download').write_bytes(b'asset')
                    yield ('A1', 'asset', 'PASS', 'ok')
                    if ending == 'failure':
                        raise RuntimeError('failed check')
                    if ending == 'interrupt':
                        raise KeyboardInterrupt()
                with patch.object(rs, '_evaluate', gates):
                    rows = rs.evaluate({}, 'v1.0.0', 'a' * 40)
                    self.assertEqual(next(rows)[2], 'PASS')
                    self.assertTrue((seen[0] / 'download').is_file())
                    if ending in ('failure', 'interrupt'):
                        with self.assertRaises(RuntimeError if ending == 'failure' else KeyboardInterrupt):
                            next(rows)
                    elif ending == 'close':
                        rows.close()
                    else:
                        self.assertEqual(list(rows), [])
                self.assert_empty()

    def test_real_evaluation_keeps_workspace_until_last_row_then_cleans(self):
        seen = []

        def download(info, digests, directory):
            directory.mkdir()
            (directory / 'asset').write_bytes(b'payload')
            seen.append(directory)
            return rs.PASS, 'download checked'
        with contextlib.ExitStack() as stack:
            for name, value in [('check_runs', {}), ('release_info', {}),
                                ('release_assets', []), ('release_digests', {}), ('load_attestations', [])]:
                stack.enter_context(patch.object(rs, name, return_value=value))
            stack.enter_context(patch.object(rs, 'verify_asset_digests', side_effect=download))
            rows = rs.evaluate({'gate': [{'id': 'A1', 'title': 'assets', 'evidence': 'asset-digests'}]},
                               'v1.0.0', 'a' * 40)
            self.assertEqual(next(rows)[2], rs.PASS)
            self.assertTrue((seen[0] / 'asset').exists())
            self.assertEqual(list(rows), [])
        self.assert_empty()

    def test_caller_workspace_and_outputs_survive_every_exit(self):
        for ending in ('success', 'failure', 'interrupt', 'close'):
            with self.subTest(ending=ending):
                directory = self.parent / ending
                directory.mkdir()
                (directory / 'existing').write_bytes(b'keep')

                def gates(g, tag, commit, workspace):
                    self.assertEqual(workspace, directory)
                    (workspace / 'output').write_bytes(b'keep output')
                    yield ('A1', 'asset', 'PASS', 'ok')
                    if ending == 'failure':
                        raise RuntimeError()
                    if ending == 'interrupt':
                        raise KeyboardInterrupt()
                with patch.object(rs, '_evaluate', gates):
                    rows = rs.evaluate({}, 'v1.0.0', 'a' * 40, workdir=directory)
                    next(rows)
                    if ending in ('failure', 'interrupt'):
                        with self.assertRaises(RuntimeError if ending == 'failure' else KeyboardInterrupt):
                            next(rows)
                    elif ending == 'close':
                        rows.close()
                    else:
                        list(rows)
                self.assertEqual((directory / 'existing').read_bytes(), b'keep')
                self.assertEqual((directory / 'output').read_bytes(), b'keep output')

    def test_fixture_suites_leave_no_directories_on_success(self):
        import test_ci_strict as ci
        import test_doc_style_gate as docs
        classes = [ci.Verdicts, ci.ConcurrencyAndResults,
                   docs.TheRealCheckerCatchesWhatChangedCannotSee,
                   docs.LocalCarryForwardsSurviveAnAdoption,
                   docs.ThePinIsTheOnlySourceOfTheCheckerVersion,
                   docs.TheReadingExemptionIsScopedToOneFileAndOneRule]
        suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(c) for c in classes)
        output = io.StringIO()
        result = unittest.TextTestRunner(stream=output).run(suite)
        self.assertTrue(result.wasSuccessful(), output.getvalue())
        self.assert_empty()

    def test_fixture_cleanup_is_registered_before_setup_can_fail(self):
        import test_ci_strict as ci
        import test_doc_style_gate as docs
        for error in (RuntimeError, KeyboardInterrupt):
            for kind in ('ci', 'gate', 'sql', 'pin', 'exempt'):
                with self.subTest(error=error, kind=kind):
                    owner = unittest.TestCase()
                    # Fail after the directory is allocated, before setup finishes.
                    try:
                        with self.assertRaises(error):
                            if kind == 'ci':
                                with patch.object(Path, 'mkdir', side_effect=error):
                                    ci.make_repo(owner)
                            else:
                                with patch.object(subprocess, 'run', side_effect=error):
                                    if kind == 'gate':
                                        docs.TheRealCheckerCatchesWhatChangedCannotSee.make_repo(owner, {})
                                    elif kind == 'sql':
                                        docs.LocalCarryForwardsSurviveAnAdoption.test_sql_is_still_checked(owner)
                                    elif kind == 'pin':
                                        docs.ThePinIsTheOnlySourceOfTheCheckerVersion.make_tree(owner)
                                    else:
                                        docs.TheReadingExemptionIsScopedToOneFileAndOneRule.make_tree(owner, {})
                        self.assertTrue(list(self.parent.iterdir()), 'allocation must be reached')
                    finally:
                        owner.doCleanups()
                    self.assert_empty()



publish_spec = importlib.util.spec_from_file_location('release_publish_cleanup', HERE / 'release-publish.py')
rp = importlib.util.module_from_spec(publish_spec)
publish_spec.loader.exec_module(rp)


class RemainingOwnership(unittest.TestCase):
    """release-publish.py's own workdir, and the release-status and release-publish suites."""

    def setUp(self):
        self.parent = Path(self.enterContext(tempfile.TemporaryDirectory(prefix='ow-cleanup-test-')))
        self.enterContext(patch.object(tempfile, 'tempdir', str(self.parent)))

    def assert_empty(self):
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_publish_main_removes_its_workdir_on_every_exit(self):
        for ending in ('return', 'failure', 'interrupt'):
            with self.subTest(ending=ending):
                seen = []

                def publish(tag, gates, confirm, workdir, out=print):
                    # The workdir exists and is usable while publish runs.
                    self.assertTrue(workdir.is_dir())
                    (workdir / 'downloaded').write_bytes(b'asset')
                    seen.append(workdir)
                    if ending == 'failure':
                        raise RuntimeError('publish failed')
                    if ending == 'interrupt':
                        raise KeyboardInterrupt()
                    return 0
                with patch.object(rp, 'publish', publish), \
                        patch.object(sys, 'argv', ['release-publish.py', '--tag', 'v1.0.0']):
                    if ending == 'return':
                        self.assertEqual(rp.main(), 0)
                    else:
                        with self.assertRaises(RuntimeError if ending == 'failure' else KeyboardInterrupt):
                            rp.main()
                self.assertEqual(len(seen), 1)
                self.assertTrue(seen[0].name.startswith('release-publish-'))
                self.assert_empty()

    def test_release_status_and_publish_suites_leave_no_directories(self):
        import test_release_status as status
        import test_release_publish as publish
        suite = unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromModule(status),
                                    unittest.defaultTestLoader.loadTestsFromModule(publish)])
        output = io.StringIO()
        # A TemporaryDirectory nobody released is still removed by its
        # finalizer when garbage-collected, with a ResourceWarning. That hides
        # a missing cleanup from the directory check, so the warning fails too.
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always', ResourceWarning)
            result = unittest.TextTestRunner(stream=output).run(suite)
            gc.collect()
        self.assertTrue(result.wasSuccessful(), output.getvalue())
        self.assertGreater(result.testsRun, 150)
        implicit = [str(w.message) for w in caught if issubclass(w.category, ResourceWarning)
                    and 'Implicitly cleaning up' in str(w.message)]
        self.assertEqual(implicit, [], 'temporary directories left to the garbage collector')
        self.assert_empty()


if __name__ == '__main__':
    unittest.main(verbosity=2)
