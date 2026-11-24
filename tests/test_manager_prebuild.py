from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

from approved_manager_builds import APPROVED_PATH
from check_official_updates import LOOKUP_ATTEMPTS, UpdateError
from generate_workflow import create_workflow
from manager_lkm_jobs import KMIS
from manager_prebuild import (LATEST, STABLE, STATE_ARTIFACT, main, plan,
                              restore_previous, validate_state)
from manager_prebuild_workflow import OUTPUT, STATE_KEY, UPDATER_PATH, prebuild_workflow
from manager_variants import MANAGERS
from prebuilt_manager_history import WORKFLOW_API, WORKFLOW_PATH, run_artifacts, successful_runs, verified_artifact
import resolve_build_sources as sources
from resolve_build_sources import NoStableRelease, REPOSITORIES, SourceResolutionError
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

    def test_automatic_only_builds_changed_official_channels(self):
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

    def test_discovery_queues_updated_official_sources_without_waiting_for_sync(self):
        channels = approved_channels()
        previous = {variant: dict(tiers) for variant, tiers in channels.items()}
        channels['KernelSU-Next'][LATEST] = (ref(53), 'dev')
        channels['BakaSU'][LATEST] = (ref(54), 'main')

        def lookup(repository, tier, custom_ref):
            variant = next(name for name in MANAGERS if REPOSITORIES[name] == repository)
            if tier not in channels[variant]:
                raise NoStableRelease('No official release')
            return channels[variant][tier]

        with patch('manager_prebuild.official_selection', side_effect=lookup), \
                patch('approved_manager_builds.read_approved', side_effect=AssertionError('Old approved pin read')), \
                patch('manager_prebuild.load_previous', return_value=previous), \
                patch('manager_prebuild.write_outputs') as outputs, \
                patch.dict('os.environ', {'GITHUB_OUTPUT': 'test-output'}):
            self.assertEqual(main(['discover', '--previous', 'previous.json']), 0)
        matrix = json.loads(outputs.call_args.args[0]['matrix'])['include']
        self.assertEqual([(row['variant'], row['tier'], row['reference'], row['source_branch']) for row in matrix],
                         [('BakaSU', LATEST, ref(54), 'main'), ('KernelSU-Next', LATEST, ref(53), 'dev')])

    def test_failed_official_lookup_never_uses_old_prebuild_state(self):
        with patch('manager_prebuild.official_selection', side_effect=SourceResolutionError('Invalid commit')), \
                patch('manager_prebuild.write_outputs') as outputs, redirect_stderr(io.StringIO()):
            self.assertEqual(main(['discover']), 1)
        outputs.assert_not_called()

    def test_missing_official_stable_is_omitted_without_retrying_or_using_approved_state(self):
        from manager_prebuild import discover_channels
        channels = approved_channels()

        def lookup(repository, tier, custom_ref):
            variant = next(name for name in MANAGERS if REPOSITORIES[name] == repository)
            if tier not in channels[variant]:
                raise NoStableRelease('No official release')
            return channels[variant][tier]

        with patch('manager_prebuild.official_selection', side_effect=lookup) as official, \
                patch('check_official_updates.time.sleep') as sleep:
            self.assertEqual(channels, discover_channels())
        self.assertEqual(len(MANAGERS) * 2, official.call_count)
        sleep.assert_not_called()

    def test_transient_official_failure_is_bounded_and_never_becomes_missing_stable(self):
        from manager_prebuild import discover_channels
        with patch('manager_prebuild.official_selection', side_effect=SourceResolutionError('GitHub source lookup failed')) as official, \
                patch('check_official_updates.time.sleep') as sleep:
            with self.assertRaisesRegex(UpdateError, 'after 3 attempts'):
                discover_channels()
        self.assertEqual(LOOKUP_ATTEMPTS, official.call_count)
        self.assertEqual([1, 2], [call.args[0] for call in sleep.call_args_list])

    def test_frozen_prebuild_cli_uses_discovered_sha_and_channel_without_requerying(self):
        for variant in MANAGERS:
            for tier, branch in ((LATEST, 'dev'), (STABLE, 'v4.0')):
                expected = sources.source_result(ref(73), REPOSITORIES[variant], branch, tier)
                with self.subTest(variant=variant, tier=tier), \
                        patch.object(sources, 'resolve_sources', side_effect=AssertionError('Moving source lookup')), \
                        patch.object(sources, 'github_json') as network, \
                        patch.dict('os.environ', {'GITHUB_OUTPUT': ''}), redirect_stdout(io.StringIO()):
                    self.assertEqual(expected, sources.frozen_channel_source(variant, tier, ref(73), branch))
                    self.assertEqual(0, sources.main(['--variant', variant, '--tier', tier, '--susfs', 'false',
                                                     '--fixed-ref', ref(73), '--fixed-source-branch', branch]))
                network.assert_not_called()

    def test_frozen_prebuild_rejects_partial_mutable_or_mixed_source_selection(self):
        command = ['--variant', 'BakaSU', '--tier', LATEST, '--susfs', 'false']
        for arguments in (['--fixed-ref', ref(73)], ['--fixed-source-branch', 'main'],
                          ['--fixed-ref', 'main', '--fixed-source-branch', 'main'],
                          ['--fixed-ref', 'A' * 40, '--fixed-source-branch', 'main'],
                          ['--fixed-ref', ref(73), '--fixed-source-branch', '../invalid'],
                          ['--fixed-ref', ref(73), '--fixed-source-branch', 'main', '--custom-ref', ref(74)]):
            with self.subTest(arguments=arguments), patch.object(sources, 'github_json') as network, \
                    patch.dict('os.environ', {'GITHUB_OUTPUT': ''}), redirect_stderr(io.StringIO()):
                self.assertEqual(1, sources.main(command + arguments))
            network.assert_not_called()

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
        self.assertEqual(workflow['run-name'], '自动预编译管理器 APK')
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
        frozen = next(step for step in auto['steps'] if step.get('id') == 'sources')
        self.assertIn('--fixed-ref "$EXPECTED_REF" --fixed-source-branch "$EXPECTED_SOURCE_BRANCH"', frozen['run'])
        self.assertNotIn('GH_TOKEN', frozen['env'])
        self.assertNotIn('CUSTOM_REF', frozen['env'])
        self.assertIn('manager_prebuild_lkm_matrix', workflow['jobs']['prebuild-manager-native']['strategy']['matrix'])
        self.assertEqual(len(MANAGERS) * 2, workflow['jobs']['prebuild-manager-apks']['strategy']['max-parallel'])
        self.assertTrue(all('uses' not in workflow['jobs'][name] for name in (
            'prebuild-manager-sources', 'prebuild-manager-native', 'prebuild-manager-apks')))
        recorder = workflow['jobs']['record-manager-prebuild']
        self.assertIn("prebuild-manager-apks.result == 'success'", recorder['if'])
        self.assertIn("prebuild-manager-apks.result == 'skipped'", recorder['if'])
        self.assertIn("manager_prebuild_state_changed == 'true'", recorder['if'])
        archive, cache = recorder['steps'][-2:]
        self.assertEqual(cache['with']['key'], STATE_KEY)
        self.assertEqual(archive['uses'], 'actions/upload-artifact@v7')
        self.assertEqual(archive['with']['path'], '${{ runner.temp }}/' + STATE_ARTIFACT)
        self.assertFalse(archive['with']['archive'])

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

    def test_prebuild_hands_off_all_native_modules_without_uploading_attachments(self):
        base = create_workflow(ROOT)
        jobs = prebuild_workflow(base)['jobs']
        self.assertNotIn('internal-manager-native-', json.dumps(jobs))
        self.assertIn('internal-manager-native-', json.dumps(base['jobs']['build-sukisu-lkm']))
        native = jobs['prebuild-manager-native']['steps']
        manager = jobs['prebuild-manager-apks']['steps']
        cache_key = next(step['with']['key'] for step in native
                         if step.get('id') == 'lkm-cache')
        rebuild = next(step for step in manager if step['name'] == '在本次 APK 作业补编缺失的原生模块')
        staging = next(step for step in manager if step['name'] == '按官方流程打包完整 LKM 模块')
        for index, kmi in enumerate(KMIS):
            cache_id = f'prebuild-kmi-{index}'
            restore = next(step for step in manager if step.get('id') == cache_id)
            ddk = ("fromJSON(needs.prebuild-manager-sources.outputs[format('{0}_ddk_matrix', matrix.slot)])"
                   f'.include[{index}].ddk_short')
            self.assertEqual(cache_key.replace('matrix.kmi', repr(kmi)).replace('matrix.ddk_short', ddk),
                             restore['with']['key'])
            self.assertEqual('manager-lkm/' + kmi, restore['with']['path'])
            self.assertEqual(restore['if'], rebuild['if'])
            self.assertIn("matrix.slot)] == ''", restore['if'])
            self.assertEqual('${{ steps.' + cache_id + '.outputs.cache-hit }}', rebuild['env'][f'PREBUILD_KMI_{index}'])
            self.assertLess(manager.index(restore), manager.index(rebuild))
        self.assertLess(manager.index(rebuild), manager.index(staging))
        self.assertIn('tools/prepare_manager_lkm.py stage', staging['run'])
        self.assertIn('tools/manager_full_native.py stage', staging['run'])

    def test_discovery_runs_independently_of_the_susfs_probe(self):
        check = prebuild_workflow(create_workflow(ROOT))['jobs']['check-upstream']
        self.assertNotIn('needs', check)
        self.assertIn('python3 tools/manager_prebuild.py discover', check['steps'][-1]['run'])
        self.assertIn('--previous', check['steps'][-1]['run'])
        self.assertIn('--artifact-history-branch "$DEFAULT_BRANCH"', check['steps'][-1]['run'])


if __name__ == '__main__':
    unittest.main()
