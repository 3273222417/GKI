from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

from approved_manager_builds import APPROVED_PATH
from generate_workflow import create_workflow
from manager_prebuild import (LATEST, STABLE, STATE_ARTIFACT, main, plan,
                              restore_previous, validate_state)
from manager_prebuild_workflow import OUTPUT, STATE_KEY, UPDATER_PATH, prebuild_workflow
from manager_variants import MANAGERS
from prebuilt_manager_history import WORKFLOW_API, WORKFLOW_PATH, run_artifacts, successful_runs, verified_artifact
from wait_manager_identity import IdentityError
from workflow_jobs import updater_workflow


def ref(number: int) -> str:
    return f'{number:040x}'


def approved_channels() -> dict:
    channels = {variant: {LATEST: (ref(number), 'main'), STABLE: (ref(number + 10), 'v4.0')}
                for number, variant in enumerate(MANAGERS, start=1)}
    channels['SukiSU'][LATEST] = (ref(31), 'dev')
    channels['BakaSU'].pop(STABLE)
    channels['FinaSU'][STABLE] = (channels['FinaSU'][LATEST][0], 'v4.0')
    return channels


def history_run(run_id: int, **changes) -> dict:
    repository = {'id': 12, 'full_name': 'cyzrqh/GKI'}
    return {'id': run_id, 'workflow_id': 42, 'run_attempt': 1, 'path': WORKFLOW_PATH,
            'event': 'workflow_run', 'status': 'completed', 'conclusion': 'success',
            'repository': repository, 'head_repository': repository, 'head_branch': 'main',
            'head_sha': ref(run_id), **changes}


def history_artifact(artifact_id: int, run_id: int, payload: bytes, **changes) -> dict:
    origin = {'id': run_id, 'repository_id': 12, 'head_repository_id': 12,
              'head_branch': 'main', 'head_sha': ref(run_id)}
    return {'id': artifact_id, 'name': STATE_ARTIFACT, 'size_in_bytes': len(payload), 'expired': False,
            'digest': 'sha256:' + hashlib.sha256(payload).hexdigest(), 'workflow_run': origin, **changes}


class FakeHistory:
    def __init__(self, values):
        self.values = {WORKFLOW_API: {'path': WORKFLOW_PATH, 'id': 42}, **values}
        self.requests = []

    def get(self, endpoint, *, binary=False):
        self.requests.append((endpoint, binary))
        return self.values[endpoint]


class ManagerPrebuildTest(unittest.TestCase):
    def test_backfill_uses_frozen_official_tiers_and_deduplicates_same_sha(self):
        channels = approved_channels()
        matrix, state = plan(channels, {})
        self.assertEqual(len(matrix['include']), 10)
        by_manager = {}
        for row in matrix['include']:
            by_manager.setdefault(row['variant'], []).append(row)
        self.assertEqual([(row['tier'], row['source_branch']) for row in by_manager['SukiSU']],
                         [(STABLE, 'v4.0'), (LATEST, 'dev')])
        self.assertEqual([row['tier'] for row in by_manager['BakaSU']], [LATEST])
        self.assertEqual(by_manager['FinaSU'][0]['channels'], '正式版 / 最新版')
        self.assertEqual(by_manager['FinaSU'][0]['tier'], STABLE)
        self.assertEqual(validate_state(json.loads(json.dumps(state)))['SukiSU'][LATEST], (ref(31), 'dev'))

    def test_automatic_only_builds_changed_approved_channels(self):
        channels = approved_channels()
        _, state = plan(channels, {})
        channels['KowSU'][LATEST] = (ref(82), 'main')
        matrix, _ = plan(channels, validate_state(state))
        self.assertEqual([(row['variant'], row['tier'], row['reference']) for row in matrix['include']],
                         [('KowSU', LATEST, ref(82))])

    def test_new_formal_channel_is_built_even_if_its_commit_is_already_latest(self):
        channels = approved_channels()
        _, state = plan(channels, {})
        channels['BakaSU'][STABLE] = (channels['BakaSU'][LATEST][0], 'v4.0')
        matrix, _ = plan(channels, validate_state(state))
        self.assertEqual(matrix['include'], [{'variant': 'BakaSU', 'tier': STABLE, 'reference': ref(2),
                                             'slot': 'bakasu_stable', 'source_branch': 'v4.0', 'channels': '正式版'}])

    def test_changed_formal_tag_on_same_commit_is_one_new_build(self):
        channels = approved_channels()
        _, state = plan(channels, {})
        channels['FinaSU'][STABLE] = (ref(6), 'v4.0-r2')
        matrix, _ = plan(channels, validate_state(state))
        self.assertEqual(matrix['include'], [{'variant': 'FinaSU', 'tier': STABLE, 'reference': ref(6),
                                             'slot': 'finasu_stable', 'source_branch': 'v4.0-r2', 'channels': '正式版'}])

    def test_removed_channel_has_no_build_but_a_reintroduced_release_is_selected(self):
        channels = approved_channels()
        _, before = plan(channels, {})
        stable = channels['FinaSU'].pop(STABLE)
        matrix, observed = plan(channels, validate_state(before))
        self.assertEqual(matrix, {'include': []})
        self.assertNotEqual(before, observed)
        channels['FinaSU'][STABLE] = stable
        matrix, _ = plan(channels, validate_state(observed))
        self.assertEqual([row['variant'] for row in matrix['include']], ['FinaSU'])

    def test_discovery_uses_the_approved_versions_without_observing_live_channels(self):
        channels = approved_channels()
        with patch('manager_prebuild.read_approved', return_value=channels) as read, \
                patch('resolve_build_sources.github_json') as network, \
                patch('manager_prebuild.write_outputs') as outputs, \
                patch.dict('os.environ', {'GITHUB_OUTPUT': 'test-output'}):
            self.assertEqual(main(['discover']), 0)
        read.assert_called_once_with(ROOT)
        network.assert_not_called()
        matrix = json.loads(outputs.call_args.args[0]['matrix'])['include']
        self.assertEqual({row['tier'] for row in matrix if row['variant'] == 'BakaSU'}, {LATEST})
        self.assertIn(ref(31), {row['reference'] for row in matrix if row['variant'] == 'SukiSU'})

    def test_rejects_incomplete_and_invalid_observation_state(self):
        _, state = plan(approved_channels(), {})
        incomplete = {**state, 'channels': {key: value for key, value in state['channels'].items() if key != 'FinaSU'}}
        with self.assertRaises(ValueError):
            validate_state(incomplete)
        state['channels']['BakaSU'][LATEST]['reference'] = 'main'
        with self.assertRaises(ValueError):
            validate_state(state)

    def test_changed_local_release_recipe_rebuilds_existing_official_versions(self):
        channels = approved_channels()
        _, state = plan(channels, {})
        changed = '0' * 64 if state['recipe_sha256'] != '0' * 64 else '1' * 64
        with patch('manager_prebuild.recipe_hash', return_value=changed):
            with self.assertRaisesRegex(ValueError, '预编译记录'):
                validate_state(state)
            matrix, new_state = plan(channels, {})
            self.assertEqual(10, len(matrix['include']))
            self.assertEqual(changed, new_state['recipe_sha256'])

    def test_evicted_state_recovers_from_successful_verified_standalone_run(self):
        channels = approved_channels()
        _, state = plan(channels, {})
        payload = json.dumps(state).encode()
        reader = FakeHistory({
            f'actions/artifacts?name={STATE_ARTIFACT}&per_page=25&page=1': {'artifacts': [
                history_artifact(77, 100, payload),
                history_artifact(76, 99, payload),
                history_artifact(75, 98, payload),
                history_artifact(74, 97, payload),
            ]},
            'actions/runs/99': history_run(99, conclusion='failure'),
            'actions/runs/98': history_run(98),
            'actions/runs/97': history_run(97),
            'actions/artifacts/75/zip': b'X' * len(payload),
            'actions/artifacts/74/zip': payload,
        })
        self.assertEqual(restore_previous(reader, 'cyzrqh/GKI', 'main', 100), channels)
        self.assertNotIn(('actions/runs/100', False), reader.requests)
        self.assertNotIn(('actions/artifacts/76/zip', True), reader.requests)
        self.assertEqual(plan(channels, restore_previous(reader, 'cyzrqh/GKI', 'main', 100))[0], {'include': []})

    def test_history_filters_branch_workflow_repository_and_artifact_origin(self):
        run = history_run(95, event='workflow_dispatch')
        payload = b'{"verified":true}'
        valid = history_artifact(73, 95, payload)
        invalid = history_artifact(74, 95, payload, workflow_run={**valid['workflow_run'], 'head_sha': ref(31)})
        reader = FakeHistory({
            WORKFLOW_API + '/runs?branch=main&status=success&per_page=25&page=1': {'workflow_runs': [
                history_run(100), history_run(99, head_branch='fork'),
                history_run(98, workflow_id=41), history_run(97, event='workflow_dispatch', head_branch='topic'),
                history_run(96, head_repository={'id': 13, 'full_name': 'fork/GKI'}), run,
            ]},
            'actions/runs/95/artifacts?per_page=25&page=1': {'artifacts': [invalid, valid]},
            'actions/artifacts/73/zip': payload,
        })
        self.assertEqual(list(successful_runs(reader, 'cyzrqh/GKI', 'main', current_run=100)), [run])
        self.assertEqual(list(run_artifacts(reader, run)), [valid])
        self.assertEqual(verified_artifact(reader, run, valid, limit=len(payload)), payload)
        with self.assertRaises(IdentityError):
            verified_artifact(reader, run, invalid, limit=len(payload))
        with self.assertRaises(IdentityError):
            verified_artifact(reader, run, valid, limit=len(payload) - 1)

    def test_named_workflow_supports_automatic_and_manual_entry_on_main(self):
        updater = updater_workflow()
        self.assertNotIn('prebuild-managers', updater['jobs'])
        self.assertEqual(updater['on']['schedule'], [{'cron': '0 4,16 * * *'}])
        workflow = prebuild_workflow(create_workflow(ROOT))
        self.assertEqual(set(workflow['on']), {'workflow_run', 'push', 'workflow_dispatch'})
        self.assertEqual(workflow['on']['workflow_dispatch'], {})
        self.assertEqual(workflow['on']['workflow_run'], {'workflows': [updater['name']],
                                                        'types': ['completed'], 'branches': ['main']})
        self.assertEqual(workflow['on']['push']['branches'], ['main'])
        paths = workflow['on']['push']['paths']
        self.assertEqual(paths[:2], [OUTPUT, APPROVED_PATH])
        self.assertEqual(len(paths), len(set(paths)))
        # A recipe change invalidates signed APK reuse, so it must also ask
        # the existing automatic workflow to build the replacement.
        from reusable_manager_apk import RECIPE_INPUTS, RECIPE_PATTERNS
        self.assertTrue(set(RECIPE_INPUTS).issubset(paths))
        self.assertTrue(set(RECIPE_PATTERNS).issubset(paths))
        self.assertIn('tools/build_fina_manager.py', paths)
        discovery = workflow['jobs']['check-upstream']
        self.assertIn("github.event_name == 'workflow_dispatch'", discovery['if'])
        self.assertIn("&& github.ref == format('refs/heads/{0}', github.event.repository.default_branch)",
                      discovery['if'])
        self.assertIn(f"github.event.workflow_run.path == '{UPDATER_PATH}'", discovery['if'])
        self.assertIn('github.event.workflow_run.head_repository.full_name == github.repository', discovery['if'])
        self.assertIn("github.event.workflow_run.event == 'schedule'", discovery['if'])
        self.assertIn("github.event.workflow_run.event == 'workflow_dispatch'", discovery['if'])
        auto = workflow['jobs']['prebuild-manager-sources']
        self.assertIn("manager_prebuild_pending == 'true'", auto['if'])
        self.assertIn('sukisu_latest_ksu_ref', auto['outputs'])
        self.assertIn('sukisu_stable_ksu_ref', auto['outputs'])
        self.assertIn('manager_prebuild_lkm_matrix', workflow['jobs']['prebuild-manager-native']['strategy']['matrix'])
        self.assertTrue(all('uses' not in workflow['jobs'][name] for name in (
            'prebuild-manager-sources', 'prebuild-manager-native', 'prebuild-manager-apks')))
        recorder = workflow['jobs']['record-manager-prebuild']
        self.assertIn("prebuild-manager-apks.result == 'success'", recorder['if'])
        self.assertIn("prebuild-manager-apks.result == 'skipped'", recorder['if'])
        self.assertIn("manager_prebuild_state_changed == 'true'", recorder['if'])
        self.assertEqual(recorder['steps'][-1]['with']['key'], STATE_KEY)
        self.assertEqual(recorder['steps'][-2]['uses'], 'actions/upload-artifact@v7')
        self.assertEqual(recorder['steps'][-2]['with']['path'], '${{ runner.temp }}/' + STATE_ARTIFACT)
        self.assertFalse(recorder['steps'][-2]['with']['archive'])

    def test_every_slot_publishes_the_ddk_lock_used_to_restore_all_native_modules(self):
        jobs = prebuild_workflow(create_workflow(ROOT))['jobs']
        source = jobs['prebuild-manager-sources']
        self.assertIn('lkm-matrix', {step.get('id') for step in source['steps']})
        for name in ('prebuild-manager-native', 'prebuild-manager-apks'):
            fields = set(re.findall(r"needs\.prebuild-manager-sources\.outputs\[format\('\{0\}_(\w+)', matrix\.slot\)\]",
                                    json.dumps(jobs[name])))
            self.assertTrue(fields)
            for variant in MANAGERS:
                for tier in ('stable', 'latest'):
                    self.assertLessEqual({f'{variant.lower()}_{tier}_{field}' for field in fields}, source['outputs'].keys())
        for variant in MANAGERS:
            self.assertIn('steps.lkm-matrix.outputs.matrix', source['outputs'][variant.lower() + '_latest_ddk_matrix'])

    def test_discovery_runs_independently_of_the_susfs_probe(self):
        check = prebuild_workflow(create_workflow(ROOT))['jobs']['check-upstream']
        self.assertNotIn('needs', check)
        self.assertIn('python3 tools/manager_prebuild.py discover', check['steps'][-1]['run'])
        self.assertIn('--previous', check['steps'][-1]['run'])
        self.assertIn('--artifact-history-branch "$DEFAULT_BRANCH"', check['steps'][-1]['run'])


if __name__ == '__main__':
    unittest.main()
