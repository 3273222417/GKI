from io import BytesIO, StringIO
from contextlib import redirect_stdout
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from apk_fixture import manager_metadata, signed_apk
from manager_lkm_jobs import KMIS
from prebuilt_manager_history import (APK_ARTIFACT_PAGE_SIZE, APK_BUILD_RUN_PAGE_SIZE,
                                     APK_BUILD_WORKFLOWS, WORKFLOW_FILE, IdentityError,
                                     manager_apk_runs, named_artifacts, successful_runs)
from restore_prebuilt_manager_apk import (HISTORY_LIST_PAGES, HistoryExhausted, HistoryReader,
                                         main, restore, version_cache_key)
from reusable_manager_apk import manager_selection
from test_additional_managers import manifest


WORKFLOW_IDS = {WORKFLOW_FILE: 42, 'kernel-full-feature-matrix.yml': 43, 'oplus-full-feature-matrix.yml': 44}


def history_run(run_id, workflow=WORKFLOW_FILE, **changes):
    repository = {'id': 12, 'full_name': 'cyzrqh/GKI'}
    return {'id': run_id, 'workflow_id': WORKFLOW_IDS[workflow], 'run_attempt': 1,
            'path': '.github/workflows/' + workflow, 'event': 'workflow_dispatch',
            'status': 'completed', 'conclusion': 'success', 'head_branch': 'main',
            'head_sha': f'{run_id:040x}', 'repository': repository,
            'head_repository': repository, **changes}


def history_artifact(artifact_id, run, payload, *, name):
    return {'id': artifact_id, 'name': name, 'size_in_bytes': len(payload), 'expired': False,
            'digest': 'sha256:' + hashlib.sha256(payload).hexdigest(),
            'workflow_run': {'id': run['id'], 'head_sha': run['head_sha'], 'head_branch': run['head_branch'],
                             'repository_id': run['repository']['id'],
                             'head_repository_id': run['head_repository']['id']}}


def runs_endpoint(workflow, page=1):
    size = 25 if workflow == WORKFLOW_FILE else APK_BUILD_RUN_PAGE_SIZE
    return f'actions/workflows/{workflow}/runs?branch=main&status=success&per_page={size}&page={page}'


class FakeHistory:
    def __init__(self, values):
        self.values = {f'actions/workflows/{filename}': {'id': workflow_id,
                       'path': '.github/workflows/' + filename} for filename, workflow_id in WORKFLOW_IDS.items()}
        self.values.update(values)
        self.requests = []

    def get(self, endpoint, *, binary=False):
        self.requests.append((endpoint, binary))
        return self.values[endpoint]


class RetainedManagerApkTests(unittest.TestCase):
    def test_recover_original_after_eviction_and_reject_same_version_different_source(self):
        source = {'ref': 'b' * 40, 'git_tree': '1' * 40, 'git_count': 512, 'git_describe': 'v4.2.0'}
        identity = manager_metadata(ksu_branch='Stable(标准)', manager_recipe_sha256='c' * 64,
                                    manager_source_identity=source, manager_native_proof={
                                        'schema_version': 1, 'supported_kmis': sorted(KMIS),
                                        'lkm_report_sha256': 'd' * 64, 'boot_report_sha256': 'e' * 64})
        package = manifest('com.sukisu.ultra', code=40922, version='4.2.0')
        wrong = {**identity, 'ksu_ref': '2' * 40, 'manager_source_identity': {**source, 'ref': '2' * 40}}
        apk = signed_apk(identity, manifest_bytes=package)
        wrapped = BytesIO()
        with ZipFile(wrapped, 'w') as archive:
            archive.writestr(identity['file'], apk)
        selection = manager_selection('SukiSU', 'Latest(最新)', source['ref'], identity['manager_cert_size'],
                                      identity['manager_cert_sha256'], identity['manager_recipe_sha256'], source)
        consumer = {'repository': 'cyzrqh/GKI', 'run_id': 456, 'run_attempt': 1, 'head_sha': 'f' * 40}
        artifacts = [{'name': 'SukiSU_v4.2.0_40921-release.apk'}, {'name': identity['file']}, {'name': identity['file']}]
        with (tempfile.TemporaryDirectory() as directory,
              patch('restore_prebuilt_manager_apk.manager_apk_runs', return_value=iter([{'id': 789}])),
              patch('restore_prebuilt_manager_apk.run_artifacts', return_value=iter(artifacts)),
              patch('restore_prebuilt_manager_apk.verified_artifact',
                    side_effect=(signed_apk(wrong, manifest_bytes=package), wrapped.getvalue())) as download):
            root = Path(directory).resolve()
            result = restore(object(), cache=root / 'evicted', output=root / 'output', consumer=consumer,
                             selection=selection, branch='main', version=40922)
            self.assertEqual(2, download.call_count)
            self.assertEqual('true', result['manager_apk_reused'])
            self.assertEqual(apk, (root / 'output' / identity['file']).read_bytes())

    def test_full_build_recovers_original_apk_after_all_kernel_artifact_pages(self):
        source = {'ref': 'b' * 40, 'git_tree': '1' * 40, 'git_count': 512, 'git_describe': 'v4.2.0'}
        identity = manager_metadata(ksu_branch='Stable(标准)', manager_recipe_sha256='c' * 64,
                                    manager_source_identity=source, manager_native_proof={
                                        'schema_version': 1, 'supported_kmis': sorted(KMIS),
                                        'lkm_report_sha256': 'd' * 64, 'boot_report_sha256': 'e' * 64})
        apk = signed_apk(identity, manifest_bytes=manifest('com.sukisu.ultra', code=40922, version='4.2.0'))
        wrapped = BytesIO()
        with ZipFile(wrapped, 'w') as archive:
            archive.writestr(identity['file'], apk)
        selection = manager_selection('SukiSU', 'Latest(最新)', source['ref'], identity['manager_cert_size'],
                                      identity['manager_cert_sha256'], identity['manager_recipe_sha256'], source)
        consumer = {'repository': 'cyzrqh/GKI', 'run_id': 456, 'run_attempt': 1, 'head_sha': 'f' * 40}
        run = history_run(789, 'kernel-full-feature-matrix.yml')
        retained = history_artifact(9999, run, wrapped.getvalue(), name=identity['file'])
        artifacts = [history_artifact(index + 1, run, b'kernel', name=f'kernel-{index}.zip')
                     for index in range(512)] + [retained]
        values = {runs_endpoint(WORKFLOW_FILE): {'workflow_runs': []},
                  runs_endpoint('kernel-full-feature-matrix.yml'): {'workflow_runs': [run]},
                  'actions/artifacts/9999/zip': wrapped.getvalue()}
        for offset in range(0, len(artifacts), APK_ARTIFACT_PAGE_SIZE):
            page = offset // APK_ARTIFACT_PAGE_SIZE + 1
            values[f'actions/runs/789/artifacts?per_page=100&page={page}'] = {
                'artifacts': artifacts[offset:offset + APK_ARTIFACT_PAGE_SIZE]}
        reader = FakeHistory(values)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            result = restore(reader, cache=root / 'evicted', output=root / 'output', consumer=consumer,
                             selection=selection, branch='main', version=40922)
            self.assertEqual('true', result['manager_apk_reused'])
            self.assertEqual(apk, (root / 'output' / identity['file']).read_bytes())
        self.assertIn(('actions/runs/789/artifacts?per_page=100&page=6', False), reader.requests)
        self.assertEqual([('actions/artifacts/9999/zip', True)], [item for item in reader.requests if item[1]])
        self.assertNotIn(('actions/workflows/oplus-full-feature-matrix.yml', False), reader.requests)

    def test_same_version_reuses_signed_historic_recipe_without_changing_bytes(self):
        source = {'ref': 'b' * 40, 'git_tree': '1' * 40, 'git_count': 512, 'git_describe': 'v4.2.0'}
        identity = manager_metadata(ksu_branch='Stable(标准)', manager_recipe_sha256='c' * 64,
                                    manager_source_identity=source, manager_native_proof={
                                        'schema_version': 1, 'supported_kmis': sorted(KMIS),
                                        'lkm_report_sha256': 'd' * 64, 'boot_report_sha256': 'e' * 64})
        apk = signed_apk(identity, manifest_bytes=manifest('com.sukisu.ultra', code=40922, version='4.2.0'))
        selected = manager_selection('SukiSU', 'Latest(最新)', source['ref'], identity['manager_cert_size'],
                                     identity['manager_cert_sha256'], 'a' * 64, source)
        consumer = {'repository': 'cyzrqh/GKI', 'run_id': 456, 'run_attempt': 1, 'head_sha': 'f' * 40}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            cache = root / 'cache'
            cache.mkdir()
            (cache / identity['file']).write_bytes(apk)
            with patch('restore_prebuilt_manager_apk.manager_apk_runs', side_effect=AssertionError('No history for cache hit')):
                result = restore(object(), cache=cache, output=root / 'output', consumer=consumer,
                                 selection=selected, branch='main', version=40922)
            receipt = json.loads(result['manager_adoption'])
            self.assertEqual('c' * 64, receipt['selection']['manager_recipe_sha256'])
            self.assertEqual('Latest(最新)', receipt['selection']['ksu_branch'])
            self.assertEqual(consumer, receipt['consumer'])
            self.assertEqual(apk, (root / 'output' / identity['file']).read_bytes())
            mismatches = [({'version': 40923}, selected),
                          ({}, {**selected, 'manager_cert_sha256': '9' * 64}),
                          ({}, {**selected, 'manager_source_identity': {**source, 'git_tree': '9' * 40}})]
            for options, selection in mismatches:
                with self.subTest(options=options, selection=selection), patch(
                        'restore_prebuilt_manager_apk.manager_apk_runs', return_value=iter([])):
                    self.assertEqual(restore(object(), cache=cache, output=root / 'rejected', consumer=consumer,
                                             selection=selection, branch='main', **{'version': 40922, **options}), {})

    def test_version_cache_key_ignores_channel_and_recipe_but_keeps_selected_identity(self):
        selection = {'ksu_variant': 'SukiSU', 'ksu_branch': 'Latest(最新)', 'ksu_ref': 'b' * 40,
                     'package': 'com.sukisu.ultra', 'manager_cert_size': 512, 'manager_cert_sha256': 'c' * 64,
                     'manager_recipe_sha256': 'd' * 64, 'manager_source_identity': {'ref': 'b' * 40}}
        key = version_cache_key(selection, 41150)
        self.assertEqual(key, version_cache_key({**selection, 'ksu_branch': 'Stable(标准)',
                                                'manager_recipe_sha256': 'a' * 64}, 41150))
        self.assertNotEqual(key, version_cache_key(selection, 41151))
        for field, value in (('ksu_variant', 'BakaSU'), ('package', 'other.package'),
                             ('ksu_ref', 'a' * 40), ('manager_cert_sha256', 'a' * 64),
                             ('manager_source_identity', {'ref': 'a' * 40})):
            with self.subTest(field=field):
                self.assertNotEqual(key, version_cache_key({**selection, field: value}, 41150))

    def test_write_version_key_cli_does_not_require_recipe_or_workflow_or_history(self):
        source = {'ref': 'b' * 40, 'git_tree': '1' * 40, 'git_count': 512, 'git_describe': 'v4.2.0'}
        output = StringIO()
        with (patch('restore_prebuilt_manager_apk.manager_source_package', return_value='com.sukisu.ultra'),
              patch('restore_prebuilt_manager_apk.native_version_code', return_value=40922),
              patch('restore_prebuilt_manager_apk.recipe_hash', side_effect=AssertionError('No recipe read')),
              patch('restore_prebuilt_manager_apk.workflow_consumer', side_effect=AssertionError('No consumer read')),
              patch('restore_prebuilt_manager_apk.GitHubReader', side_effect=AssertionError('No network')),
              patch.dict('os.environ', {'GITHUB_OUTPUT': ''}), redirect_stdout(output)):
            self.assertEqual(main(['--write-version-key', '--variant', 'SukiSU', '--channel', 'Latest(最新)',
                                   '--ksu-ref', source['ref'], '--cert-size', '512', '--cert-sha256', 'c' * 64,
                                   '--source-identity', json.dumps(source), '--source-dir', 'source']), 0)
        self.assertRegex(json.loads(output.getvalue())['apk_version_cache_key'],
                         r'\Agki-manager-apk-version-v1-[0-9a-f]{64}\Z')


class ManagerApkHistoryTests(unittest.TestCase):
    def test_standalone_first_then_bounded_gki_and_oplus_successes(self):
        self.assertEqual(APK_BUILD_WORKFLOWS, ('kernel-full-feature-matrix.yml', 'oplus-full-feature-matrix.yml'))
        workflow = 'kernel-full-feature-matrix.yml'
        reader = FakeHistory({
            runs_endpoint(WORKFLOW_FILE): {'workflow_runs': [history_run(100), history_run(95)]},
            runs_endpoint(workflow): {'workflow_runs': [history_run(89, workflow)]},
            runs_endpoint('oplus-full-feature-matrix.yml'): {'workflow_runs': [
                history_run(88, 'oplus-full-feature-matrix.yml')]},
        })
        self.assertEqual([run['id'] for run in manager_apk_runs(reader, 'cyzrqh/GKI', 'main', current_run=100)],
                         [95, 89, 88])
        self.assertNotIn((runs_endpoint(workflow, 2), False), reader.requests)
        self.assertFalse(any('actions/runs?' in path for path, _ in reader.requests))

    def test_ordinary_history_stops_after_one_recent_run(self):
        workflow = 'kernel-full-feature-matrix.yml'
        rejected = [history_run(index, workflow, status='in_progress')
                    for index in range(1, APK_BUILD_RUN_PAGE_SIZE + 1)]
        reader = FakeHistory({
            runs_endpoint(WORKFLOW_FILE): {'workflow_runs': []},
            runs_endpoint(workflow): {'workflow_runs': rejected},
            runs_endpoint('oplus-full-feature-matrix.yml'): {'workflow_runs': []},
        })
        self.assertEqual(list(manager_apk_runs(reader, 'cyzrqh/GKI', 'main')), [])
        self.assertNotIn((runs_endpoint(workflow, 2), False), reader.requests)

    def test_ordinary_runs_reject_wrong_branch_workflow_repository_and_failed_status(self):
        workflow = 'kernel-full-feature-matrix.yml'
        for changes in ({'head_branch': 'topic'}, {'workflow_id': 42}, {'path': '.github/workflows/untrusted.yml'},
                        {'conclusion': 'failure'}, {'head_repository': {'id': 13, 'full_name': 'fork/GKI'}},
                        {'repository': {'id': 13, 'full_name': 'cyzrqh/GKI'}}, {'run_attempt': 0}, {'status': 'in_progress'}):
            with self.subTest(changes=changes):
                reader = FakeHistory({runs_endpoint(WORKFLOW_FILE): {'workflow_runs': []},
                                      runs_endpoint(workflow): {'workflow_runs': [history_run(95, workflow, **changes)]},
                                      runs_endpoint('oplus-full-feature-matrix.yml'): {'workflow_runs': []}})
                self.assertEqual(list(manager_apk_runs(reader, 'cyzrqh/GKI', 'main')), [])

    def test_history_page_and_elapsed_budgets_stop_before_more_requests(self):
        path = 'actions/runs/95/artifacts?per_page=100&page=1'
        reader = FakeHistory({path: {'artifacts': []}})
        bounded = HistoryReader(reader)
        for _ in range(HISTORY_LIST_PAGES):
            bounded.get(path)
        with self.assertRaises(HistoryExhausted):
            bounded.get(path)
        self.assertEqual(len(reader.requests), HISTORY_LIST_PAGES)
        with patch('restore_prebuilt_manager_apk.time.monotonic', side_effect=[0, 8]):
            bounded = HistoryReader(reader)
            with self.assertRaises(HistoryExhausted):
                bounded.get(path)
        self.assertEqual(len(reader.requests), HISTORY_LIST_PAGES)

    def test_each_ordinary_workflow_requires_exact_metadata_path_and_positive_id(self):
        for workflow in APK_BUILD_WORKFLOWS:
            for invalid in ({'path': '.github/workflows/other.yml', 'id': WORKFLOW_IDS[workflow]},
                            {'path': '.github/workflows/' + workflow, 'id': True}):
                with self.subTest(workflow=workflow, invalid=invalid):
                    values = {runs_endpoint(filename): {'workflow_runs': []} for filename in WORKFLOW_IDS}
                    values['actions/workflows/' + workflow] = invalid
                    with self.assertRaises(IdentityError):
                        list(manager_apk_runs(FakeHistory(values), 'cyzrqh/GKI', 'main'))

    def test_state_discovery_still_excludes_ordinary_build_runs(self):
        standalone = history_run(95)
        ordinary = history_run(94, 'kernel-full-feature-matrix.yml')
        name = 'manager-prebuild-state'
        values = {
            runs_endpoint(WORKFLOW_FILE): {'workflow_runs': [ordinary, standalone]},
            f'actions/artifacts?name={name}&per_page=25&page=1': {'artifacts': [
                history_artifact(74, ordinary, b'state', name=name),
                history_artifact(75, standalone, b'state', name=name)]},
            'actions/runs/94': ordinary, 'actions/runs/95': standalone,
        }
        reader = FakeHistory(values)
        self.assertEqual(list(successful_runs(reader, 'cyzrqh/GKI', 'main')), [standalone])
        self.assertEqual([(run['id'], artifact['id']) for run, artifact in named_artifacts(
            reader, 'cyzrqh/GKI', 'main', name)], [(95, 75)])
        self.assertFalse(any(path.startswith('actions/workflows/' + workflow)
                             for path, _ in reader.requests for workflow in APK_BUILD_WORKFLOWS))


if __name__ == '__main__':
    unittest.main()
