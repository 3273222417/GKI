import contextlib
import copy
import io
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import cleanup_build_artifacts as cleanup

SHA = 'a' * 40
ASSETS = [{'name': name, 'size': size, 'digest': 'sha256:' + digest * 64}
          for name, size, digest in [('SukiSU_v4.2.1_41050-release.apk', 123, 'b'),
                                    ('android12-5.10.246-2025-12-AnyKernel3.zip', 456, 'c'),
                                    ('SHA256SUMS.txt', 80, 'd')]]


class ArtifactCleanupTests(unittest.TestCase):
    def setUp(self):
        self.release = {'draft': False, 'prerelease': False, 'target_commitish': SHA, 'assets': copy.deepcopy(ASSETS)}
        self.artifacts = [{'id': i, 'name': asset['name'], 'size_in_bytes': asset['size'],
                           'digest': asset['digest'], 'expired': False} for i, asset in enumerate(ASSETS, 1)]
        self.artifacts += [{'id': 4, 'name': 'Release-Manager-abcdefg'},
                           {'id': 5, 'name': 'Manager-Identity-abcdefg'},
                           {'id': 6, 'name': 'Release-SukiSU-android12'},
                           {'id': 7, 'name': 'patch-rejects'}]
        self.deleted = []
        self.environment = patch.dict(os.environ, {'GITHUB_REPOSITORY': 'owner/gki', 'GITHUB_RUN_ID': '123',
                                                  'GITHUB_SHA': SHA, 'GITHUB_RUN_ATTEMPT': '1'})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def api(self, repo, resource, *, method='GET'):
        self.assertEqual(repo, 'owner/gki')
        if method == 'DELETE':
            self.deleted.append(resource)
            return None
        if resource == '/actions/runs/123':
            return {'head_sha': SHA, 'head_repository': {'full_name': 'owner/gki'}}
        if resource.startswith('/releases/tags/'):
            return self.release
        return {'total_count': len(self.artifacts), 'artifacts': self.artifacts}

    def invoke(self):
        with patch.object(cleanup, 'api', side_effect=self.api), contextlib.redirect_stdout(io.StringIO()):
            return cleanup.cleanup('123')

    def test_verified_raw_files_survive_and_only_staging_is_deleted(self):
        self.assertEqual(self.invoke(), ['Release-Manager-abcdefg', 'Manager-Identity-abcdefg', 'Release-SukiSU-android12'])
        self.assertEqual(self.deleted, ['/actions/artifacts/4', '/actions/artifacts/5', '/actions/artifacts/6'])

    def test_wrong_run_is_rejected_without_any_api_access(self):
        with patch.object(cleanup, 'api') as api, self.assertRaisesRegex(cleanup.CleanupError, 'current run'):
            cleanup.cleanup('456')
        api.assert_not_called()

    def test_missing_changed_expired_or_duplicate_raw_file_preserves_every_staging_file(self):
        original = copy.deepcopy(self.artifacts)
        for change in ('missing', 'digest', 'size', 'expired', 'duplicate'):
            self.artifacts = copy.deepcopy(original)
            if change == 'missing':
                self.artifacts.pop(1)
            elif change == 'duplicate':
                self.artifacts.append(copy.deepcopy(self.artifacts[1]))
            else:
                self.artifacts[1][{'digest': 'digest', 'size': 'size_in_bytes', 'expired': 'expired'}[change]] = True
            with self.subTest(change=change), self.assertRaises(cleanup.CleanupError):
                self.invoke()
            self.assertEqual(self.deleted, [])

    def test_unpublished_or_different_source_release_is_not_used(self):
        for field, value in (('draft', True), ('prerelease', True), ('target_commitish', 'main')):
            original = self.release[field]
            self.release[field] = value
            with self.subTest(field=field), self.assertRaises(cleanup.CleanupError):
                self.invoke()
            self.release[field] = original
        self.assertEqual(self.deleted, [])

    def test_partial_cleanup_can_resume_without_deleting_final_files(self):
        def partial(repo, resource, *, method='GET'):
            if method == 'DELETE' and resource.endswith('/5'):
                raise cleanup.CleanupError('temporary error')
            return self.api(repo, resource, method=method)
        with patch.object(cleanup, 'api', side_effect=partial), self.assertRaises(cleanup.CleanupError):
            cleanup.cleanup('123')
        self.artifacts = [item for item in self.artifacts if item['id'] != 4]
        self.deleted.clear()
        self.invoke()
        self.assertEqual(self.deleted, ['/actions/artifacts/5', '/actions/artifacts/6'])

    def test_pagination_does_not_skip_final_files_on_second_page(self):
        fillers = [{'id': i + 100, 'name': f'diagnostic-{i}'} for i in range(100)]
        def pages(repo, resource, *, method='GET'):
            if '/artifacts?' in resource:
                batch = fillers if resource.endswith('page=1') else self.artifacts
                return {'total_count': 107, 'artifacts': batch}
            return self.api(repo, resource, method=method)
        with patch.object(cleanup, 'api', side_effect=pages), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(len(cleanup.cleanup('123')), 3)


class PrebuildArtifactCleanupTests(unittest.TestCase):
    def setUp(self):
        self.run = {'id': 123, 'workflow_id': 77, 'path': cleanup.PREBUILD_PATH,
                    'head_sha': SHA, 'head_branch': 'main', 'event': 'workflow_dispatch',
                    'run_attempt': 1, 'status': 'in_progress', 'conclusion': None,
                    'repository': {'id': 12, 'full_name': 'owner/gki'},
                    'head_repository': {'id': 12, 'full_name': 'owner/gki'}}
        self.workflow = {'id': 77, 'path': cleanup.PREBUILD_PATH}
        self.jobs = [self.job(11, 'BakaSU · 最新版 · 预编译管理器 APK'),
                     self.job(12, 'SukiSU · 正式版 · 预编译管理器 APK'),
                     self.job(13, 'BakaSU · 原生模块'),
                     self.job(14, cleanup.PREBUILD_RECORD, status='in_progress', conclusion=None)]
        self.internal = 'internal-manager-native-BakaSU-' + SHA + '-' + 'b' * 24 + '-android16-6.12-' + 'c' * 16 + '-' + 'd' * 64
        self.artifacts = [self.artifact(21, self.internal), self.artifact(22, ASSETS[0]['name']),
                          self.artifact(23, 'gki-manager-apk-observations.json'),
                          self.artifact(24, 'SHA256SUMS.txt'), self.artifact(25, 'Release-manager'),
                          self.artifact(26, self.internal + '.apk'),
                          self.artifact(27, self.internal.replace('BakaSU-', 'unknown-'))]
        self.calls, self.deleted = [], []
        environment = patch.dict(os.environ, {'GITHUB_REPOSITORY': 'owner/gki', 'GITHUB_RUN_ID': '123',
                                              'GITHUB_SHA': SHA, 'GITHUB_RUN_ATTEMPT': '1',
                                              'GITHUB_JOB': 'record-manager-prebuild'})
        environment.start()
        self.addCleanup(environment.stop)

    def job(self, identifier, name, *, status='completed', conclusion='success'):
        return {'id': identifier, 'name': name, 'run_id': 123, 'status': status, 'conclusion': conclusion}

    def artifact(self, identifier, name):
        return {'id': identifier, 'name': name, 'expired': False, 'size_in_bytes': 123,
                'digest': 'sha256:' + 'e' * 64,
                'workflow_run': {'id': 123, 'head_sha': SHA, 'head_branch': 'main',
                                 'repository_id': 12, 'head_repository_id': 12}}

    def api(self, repository, resource, *, method='GET'):
        self.assertEqual('owner/gki', repository)
        self.calls.append((method, resource))
        if method == 'DELETE':
            self.assertRegex(resource, r'^/actions/artifacts/[0-9]+$')
            self.deleted.append(resource)
        elif resource == cleanup.PREBUILD_API:
            return self.workflow
        elif resource == '/actions/runs/123':
            return copy.deepcopy(self.run)
        elif resource.startswith('/actions/runs/123/attempts/1/jobs?'):
            return {'total_count': len(self.jobs), 'jobs': self.jobs}
        elif resource.startswith('/actions/runs/123/artifacts?'):
            return {'total_count': len(self.artifacts), 'artifacts': self.artifacts}
        else:
            self.fail('Unexpected API access ' + resource)

    def invoke(self, **options):
        with patch.object(cleanup, 'api', side_effect=self.api), contextlib.redirect_stdout(io.StringIO()):
            return cleanup.cleanup_prebuild('123', **options)

    def complete(self):
        self.run.update(status='completed', conclusion='success')
        self.jobs[-1].update(status='completed', conclusion='success')

    def test_preview_and_cleanup_preserve_apks_records_and_unrelated_attachments(self):
        self.assertEqual([self.internal], self.invoke())
        self.assertEqual([], self.deleted)
        self.assertEqual([self.internal], self.invoke(execute=True))
        self.assertEqual(['/actions/artifacts/21'], self.deleted)

    def test_completed_run_requires_matching_successful_prebuild_identity(self):
        self.complete()
        self.assertEqual([self.internal], self.invoke(repository='owner/gki', source_sha=SHA, completed=True, execute=True))
        self.assertEqual(['/actions/artifacts/21'], self.deleted)

    def test_running_failed_or_cancelled_historical_runs_preserve_all_attachments(self):
        for status, conclusion in (('in_progress', None), ('completed', 'failure'), ('completed', 'cancelled')):
            self.run.update(status=status, conclusion=conclusion)
            with self.subTest(status=status, conclusion=conclusion), self.assertRaises(cleanup.CleanupError):
                self.invoke(completed=True, execute=True)
            self.assertEqual([], self.deleted)

    def test_wrong_workflow_source_repository_attempt_or_branch_preserves_everything(self):
        original = copy.deepcopy(self.run)
        for changes in ({'path': '.github/workflows/kernel-full-feature-matrix.yml'}, {'workflow_id': 78},
                        {'head_sha': 'f' * 40}, {'head_branch': 'other'}, {'run_attempt': 2},
                        {'head_repository': {'id': 13, 'full_name': 'fork/gki'}}, {'id': 456}):
            self.run = {**original, **changes}
            with self.subTest(changes=changes), self.assertRaises(cleanup.CleanupError):
                self.invoke(execute=True)
            self.assertEqual([], self.deleted)
        self.run = original
        self.workflow['path'] = '.github/workflows/kernel-full-feature-matrix.yml'
        with self.assertRaises(cleanup.CleanupError):
            self.invoke(execute=True)
        self.assertEqual([], self.deleted)

    def test_failed_unfinished_or_missing_apk_consumers_cannot_unlock_cleanup(self):
        original = copy.deepcopy(self.jobs)
        for replacement in (self.job(11, original[0]['name'], conclusion='failure'),
                            self.job(11, original[0]['name'], status='in_progress', conclusion=None),
                            self.job(11, 'unrecognized worker')):
            self.jobs = [replacement, *copy.deepcopy(original[1:])]
            if replacement['name'] == 'unrecognized worker':
                self.jobs[1]['name'] = 'another unrecognized worker'
            with self.subTest(replacement=replacement), self.assertRaises(cleanup.CleanupError):
                self.invoke(execute=True)
            self.assertEqual([], self.deleted)

    def test_running_cleanup_requires_the_current_final_recorder(self):
        with patch.dict(os.environ, {'GITHUB_JOB': 'prebuild-manager-native'}), \
                patch.object(cleanup, 'api') as api, self.assertRaises(cleanup.CleanupError):
            cleanup.cleanup_prebuild('123', execute=True)
        api.assert_not_called()

    def test_attachment_provenance_and_inventory_are_verified_before_first_delete(self):
        original = copy.deepcopy(self.artifacts)
        for changes in ({'workflow_run': {**original[0]['workflow_run'], 'id': 456}},
                        {'workflow_run': {**original[0]['workflow_run'], 'head_sha': 'f' * 40}},
                        {'digest': 'bad'}, {'expired': True}, {'size_in_bytes': False}):
            self.artifacts = [{**original[0], **changes}, *copy.deepcopy(original[1:])]
            with self.subTest(changes=changes), self.assertRaises(cleanup.CleanupError):
                self.invoke(execute=True)
            self.assertEqual([], self.deleted)
        self.artifacts = original + [copy.deepcopy(original[0])]
        with self.assertRaises(cleanup.CleanupError):
            self.invoke(execute=True)
        self.assertEqual([], self.deleted)

    def test_complete_pagination_is_required_before_deleting_second_page_candidates(self):
        original = self.api
        fillers = [self.artifact(100 + index, 'diagnostic-' + str(index)) for index in range(100)]
        def pages(repository, resource, *, method='GET'):
            if '/artifacts?' in resource:
                batch = fillers if resource.endswith('page=1') else self.artifacts
                return {'total_count': 107, 'artifacts': batch}
            return original(repository, resource, method=method)
        with patch.object(cleanup, 'api', side_effect=pages), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual([self.internal], cleanup.cleanup_prebuild('123', execute=True))
        self.assertEqual(['/actions/artifacts/21'], self.deleted)
        self.deleted.clear()
        self.artifacts.pop()
        with patch.object(cleanup, 'api', side_effect=pages), self.assertRaises(cleanup.CleanupError):
            cleanup.cleanup_prebuild('123', execute=True)
        self.assertEqual([], self.deleted)

    def test_changed_attempt_before_deletion_preserves_every_attachment(self):
        original = self.api
        reads = 0
        def changed(repository, resource, *, method='GET'):
            nonlocal reads
            if resource == '/actions/runs/123':
                reads += 1
                if reads == 2:
                    self.run['run_attempt'] = 2
            return original(repository, resource, method=method)
        with patch.object(cleanup, 'api', side_effect=changed), self.assertRaises(cleanup.CleanupError):
            cleanup.cleanup_prebuild('123', execute=True)
        self.assertEqual([], self.deleted)

    def test_only_complete_native_transfer_names_match(self):
        for variant in cleanup.MANAGERS:
            for kmi in cleanup.KMIS:
                name = 'internal-manager-native-' + variant + '-' + SHA + '-' + 'b' * 24 + '-' + kmi + '-' + 'c' * 16 + '-' + 'd' * 64
                self.assertIsNotNone(cleanup.INTERNAL_NATIVE.fullmatch(name))
        for name in (self.internal.replace('b' * 24, 'b' * 16), self.internal + '.zip',
                     self.internal.replace('c' * 16, 'C' * 16), self.internal.replace('android16-6.12', 'android18-6.19')):
            with self.subTest(name=name):
                self.assertIsNone(cleanup.INTERNAL_NATIVE.fullmatch(name))

    def test_completed_cli_requires_explicit_repository_and_sha(self):
        for arguments in ([], ['--repo', 'owner/gki'], ['--source-sha', SHA]):
            with self.subTest(arguments=arguments), patch.object(cleanup, 'api') as api, \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(1, cleanup.main(['--run-id', '123', '--prebuild-internal', '--completed-run', *arguments]))
            api.assert_not_called()

if __name__ == '__main__':
    unittest.main()
