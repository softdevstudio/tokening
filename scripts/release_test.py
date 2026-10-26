import importlib.util
import contextlib
import io
import json
import pathlib
import re
import subprocess
import tempfile
import types
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('tokening_release', pathlib.Path(__file__).with_name('release.py'))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseGuardTests(unittest.TestCase):
    def test_review_is_bound_to_tracked_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            subprocess.run(['git', 'init', '-q'], cwd=root, check=True)
            (root / 'cmd/tokening').mkdir(parents=True)
            source = root / 'cmd/tokening/main.go'
            source.write_text('package main\nconst version = "0.1.0"\n')
            subprocess.run(['git', 'add', 'cmd'], cwd=root, check=True)
            record = root / 'release-readiness.json'
            record.write_text(json.dumps({'version':'0.1.0','status':'approved','source_sha256':release.source_digest(root)}))
            release.check_review(root)
            source.write_text(source.read_text() + '// changed source\n')
            with self.assertRaises(RuntimeError):
                release.check_review(root)
            source.write_text('package main\nconst version = "0.1.0"\n')
            record.write_text(json.dumps({'version':'0.1.0','status':'pending','source_sha256':release.source_digest(root)}))
            with self.assertRaises(RuntimeError):
                release.check_review(root)

    def test_failure_results_must_include_measured_race_and_every_case(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = pathlib.Path(temporary) / 'tests.jsonl'
            records = [{'Test':name,'Action':'pass'} for name in release.REQUIRED]
            with self.assertRaises(RuntimeError):
                log.write_text('\n'.join(json.dumps(record) for record in records))
                release.test_summary(log)
            race = {'consumer_race':{'runs':1000,'allowed':1000,'exhausted':1000,'callers_per_run':2,'remaining_uses':0}}
            records.append({'Output':'    test.go:1: '+json.dumps(race)+'\n'})
            log.write_text('\n'.join(json.dumps(record) for record in records))
            self.assertEqual(release.test_summary(log)['consumer_race'],race['consumer_race'])
            for short in (0,1,999):
                altered = {'consumer_race':dict(race['consumer_race'],runs=short,allowed=short,exhausted=short)}
                records[-1]={'Output':json.dumps(altered)}
                log.write_text('\n'.join(json.dumps(record) for record in records))
                with self.assertRaises(RuntimeError):
                    release.test_summary(log)
            records[-1]={'Output':json.dumps(race)}
            records[0]['Action']='fail'
            log.write_text('\n'.join(json.dumps(record) for record in records))
            with self.assertRaises(RuntimeError):
                release.test_summary(log)

    def test_drafts_resume_but_conflicting_tags_never_receive_assets(self):
        with mock.patch.object(release,'remote_tag_commit',return_value='reviewed'), mock.patch.object(release,'github',return_value={'draft':True,'target_commitish':'reviewed'}):
            self.assertEqual(release.release_state('v0.1.0','reviewed',False),'resume')
        with mock.patch.object(release,'remote_tag_commit',return_value='other'), mock.patch.object(release,'github',return_value=None):
            with self.assertRaises(RuntimeError):
                release.release_state('v0.1.0','reviewed',True)
        with mock.patch.object(release,'remote_tag_commit',return_value='reviewed'), mock.patch.object(release,'github',return_value={'draft':False}):
            self.assertEqual(release.release_state('v0.1.0','reviewed',False),'published')

    def test_archive_contains_the_manuals_relative_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = pathlib.Path(temporary)/'tokening'
            binary.write_bytes(b'native binary fixture')
            names = {name for _,name in release.archive_files(binary)}
            for target in re.findall(r'\[[^\]]+\]\(([^)]+)\)',(release.ROOT/'README.md').read_text()):
                if not target.startswith(('https:','http:','#')):
                    self.assertIn(target,names)

    def test_old_tag_rebuild_does_not_replace_newer_latest_release(self):
        self.assertFalse(release.latest_allowed('v0.1.0',{'tag_name':'v0.2.0'}))
        self.assertTrue(release.latest_allowed('v0.2.0',{'tag_name':'v0.1.0'}))
        self.assertTrue(release.latest_allowed('v0.1.0',None))
        self.assertFalse(release.latest_allowed('v0.1.0',{'tag_name':'unknown-channel'}))

    def test_native_download_diagnostics_do_not_corrupt_json_recording(self):
        def run(args,**kwargs):
            kwargs['stderr'].write('go: downloading a dependency\n')
            for name in release.REQUIRED:
                kwargs['stdout'].write(json.dumps({'Test':name,'Action':'pass'})+'\n')
            kwargs['stdout'].write(json.dumps({'Output':json.dumps({'consumer_race':{'runs':1000,'allowed':1000,'exhausted':1000,'callers_per_run':2,'remaining_uses':0}})})+'\n')
            return types.SimpleNamespace(returncode=0)
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(release.subprocess,'run',side_effect=run):
            logs=pathlib.Path(directory)
            self.assertEqual(release.record_native_tests(logs)['consumer_race']['runs'],1000)
            self.assertIn('downloading',(logs/'test-stderr.log').read_text())
            self.assertNotIn('downloading',(logs/'tests.jsonl').read_text())

    def test_nonzero_native_test_exit_still_blocks_packaging(self):
        def run(args,**kwargs):
            kwargs['stderr'].write('synthetic compiler failure\n')
            return types.SimpleNamespace(returncode=1)
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(release.subprocess,'run',side_effect=run), contextlib.redirect_stdout(io.StringIO()):
            logs=pathlib.Path(directory)
            with self.assertRaises(RuntimeError):
                release.record_native_tests(logs)
            self.assertIn('compiler failure',(logs/'test-stderr.log').read_text())


if __name__ == '__main__':
    unittest.main()
