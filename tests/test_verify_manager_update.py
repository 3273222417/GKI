"""Source integration is a required gate, separate from update discovery."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'tests'))
import verify_manager_update as verifier
from test_official_sync_report import snapshot


class ManagerUpdateTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = snapshot()
        self.history = mock.patch.object(verifier, 'source_repository', return_value=Path('source-cache'))
        self.history.start()
        self.addCleanup(self.history.stop)
        counts = {self.snapshot['sukisu']['head']: 10, self.snapshot['sukisu']['development']['head']: 20,
                  self.snapshot['bakasu']['head']: 30}
        counting = mock.patch.object(verifier, 'fetch_reference', side_effect=lambda repository, ref: counts[ref])
        counting.start()
        self.addCleanup(counting.stop)
        checking = mock.patch.object(verifier, 'check_source', return_value={
            'version_code': 41117, 'checks': ['complete source integration']})
        self.checking = checking.start()
        self.addCleanup(checking.stop)

    def test_all_available_channels_are_checked_with_latest_main_dev_selection(self):
        report = verifier.validate_manager_snapshot(self.snapshot, cache=Path('cache'))
        self.assertTrue(report['passed'])
        self.assertEqual(3, self.checking.call_count)
        self.assertEqual({'正式版', '测试版'}, {row['channel'] for row in report['rows']})
        latest = next(row for row in report['rows'] if row['source'] == 'SukiSU' and row['channel'] == '测试版')
        self.assertEqual(self.snapshot['sukisu']['development']['head'], latest['commit'])
        self.assertEqual('passed', latest['status'])

    def test_incompatible_source_is_recorded_with_version_channel_and_never_passes(self):
        self.checking.side_effect = verifier.SourceIntegrationError('complete SUSFS patch does not apply', 41117)
        with verifier.temporary_directory(ROOT / 'tests', '.manager-verification-') as directory:
            path = directory / 'compatibility.json'
            with self.assertRaisesRegex(verifier.ManagerUpdateError, '未合并同步'):
                verifier.validate_manager_snapshot(self.snapshot, cache=Path('cache'), report_path=path)
            report = json.loads(path.read_text('utf-8'))
            self.assertFalse(report['passed'])
            self.assertIn('失败，未同步', path.with_suffix('.md').read_text('utf-8'))
            self.assertTrue(all(row['commit'] for row in report['rows'] if row['status'] == 'failure'))
            self.assertTrue(all(row['version_code'] == 41117 for row in report['rows'] if row['status'] == 'failure'))

    def test_both_channels_are_checked_without_duplicate_version_tables(self):
        before = copy.deepcopy(self.snapshot)
        before['sukisu']['development']['head'] = '8' * 40
        result = verifier.validate_manager_snapshot(self.snapshot, cache=Path('cache'), before_snapshot=before)
        text = verifier.render_report(result)
        self.assertNotIn('| SukiSU | 正式版 |', text)
        self.assertNotIn('| BakaSU |', text)
        self.assertNotIn('| SukiSU | 测试版 |', text)
        self.assertIn('配套验证通过', text)
        self.assertEqual(3, self.checking.call_count)


class ManagerPromotionTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = snapshot()
        self.approved = {variant: {verifier.LATEST: ('9' * 40, 'main')} for variant in verifier.MANAGERS}
        self.approved['SukiSU'][verifier.STABLE] = ('a' * 40, 'v4.2.1-r1')
        self.approved['BakaSU'][verifier.LATEST] = ('4' * 40, 'main')
        self.pins = ({'SukiSU': {'android12-5.10': '1' * 40}},
                     {'SukiSU': {'android12-5.10': 'v2.4.0'}})
        patchers = (
            ('checking', mock.patch.object(verifier, 'check_source', return_value={'version_code': 41117, 'checks': []})),
            ('history', mock.patch.object(verifier, 'source_repository', return_value=Path('source-cache'))),
            ('counts', mock.patch.object(verifier, 'fetch_reference', return_value=20)),
            ('compare', mock.patch('resolve_build_sources.compare_sukisu_channels', return_value=('c' * 40, 'dev'))),
        )
        for name, patch in patchers:
            setattr(self, name, patch.start())
            self.addCleanup(patch.stop)

    def plan(self, *, proposed_pins=None):
        return verifier.plan_approvals(self.approved, self.snapshot, cache=Path('cache'),
            before_pins=self.pins, proposed_pins=self.pins if proposed_pins is None else proposed_pins)

    def test_failed_latest_is_retained_while_an_independent_channel_advances(self):
        def validate(repository, variant, reference, count, **options):
            if variant == 'SukiSU':
                raise verifier.SourceIntegrationError('SUSFS patch does not apply', 41117)
            return {'version_code': 35259, 'checks': []}
        self.checking.side_effect = validate
        after, report = self.plan()
        self.assertTrue(report['approved_changed'])
        self.assertEqual(1, report['pending_slots'])
        self.assertEqual(self.approved['SukiSU'], after['SukiSU'])
        self.assertEqual(('d' * 40, 'main'), after['BakaSU'][verifier.LATEST])
        self.assertEqual([('c' * 40, 'failure'), ('d' * 40, 'passed')],
                         [(row['commit'], row['status']) for row in report['rows']])
        self.assertEqual(2, self.checking.call_count)

    def test_unchanged_observation_is_retried_and_only_changed_identity_is_verified(self):
        self.approved['BakaSU'][verifier.LATEST] = ('d' * 40, 'main')
        after, report = self.plan()
        self.assertEqual(('c' * 40, 'dev'), after['SukiSU'][verifier.LATEST])
        self.assertEqual(0, report['pending_slots'])
        self.checking.assert_called_once()
        self.assertEqual('c' * 40, self.checking.call_args.args[2])

    def test_failed_selection_never_moves_a_channel_or_blocks_other_candidates(self):
        self.compare.side_effect = RuntimeError('Official source comparison is unavailable')
        after, report = self.plan()
        self.assertEqual(self.approved['SukiSU'], after['SukiSU'])
        self.assertEqual(('d' * 40, 'main'), after['BakaSU'][verifier.LATEST])
        self.assertEqual(1, report['pending_slots'])
        self.checking.assert_called_once()

    def test_native_command_failure_is_scoped_and_excludes_command_arguments(self):
        self.checking.side_effect = [subprocess.CalledProcessError(128, ['untrusted-argument']),
                                     {'version_code': 35259, 'checks': []}]
        after, report = self.plan()
        self.assertEqual(self.approved['SukiSU'], after['SukiSU'])
        self.assertEqual(('d' * 40, 'main'), after['BakaSU'][verifier.LATEST])
        self.assertIn('128', report['rows'][0]['reason'])
        self.assertNotIn('untrusted-argument', report['rows'][0]['reason'])

    def test_pin_changes_verify_both_old_channels_and_roll_back_before_candidate_checks(self):
        proposal = ({'SukiSU': {'android12-5.10': '2' * 40}}, self.pins[1])

        def validate(repository, variant, reference, count, **options):
            if variant == 'SukiSU' and options['susfs24_pins']['android12-5.10'] == '2' * 40 and reference == '9' * 40:
                raise verifier.SourceIntegrationError('SUSFS does not match retained latest', 41100)
            return {'version_code': 41117, 'checks': []}
        self.checking.side_effect = validate
        after, report = self.plan(proposed_pins=proposal)
        self.assertTrue(report['pins_retained'])
        self.assertEqual('测试版', report['pin_failures'][0]['channel'])
        self.assertEqual(('c' * 40, 'dev'), after['SukiSU'][verifier.LATEST])
        suki_checks = [(call.args[2], call.kwargs['susfs24_pins']['android12-5.10'])
                       for call in self.checking.call_args_list if call.args[1] == 'SukiSU']
        self.assertEqual([('9' * 40, '2' * 40), ('a' * 40, '2' * 40), ('c' * 40, '1' * 40)], suki_checks)

    def test_no_candidate_retains_a_previous_stable_even_if_release_disappears(self):
        self.snapshot['sukisu']['release'] = None
        after, _ = self.plan()
        self.assertEqual(self.approved['SukiSU'][verifier.STABLE], after['SukiSU'][verifier.STABLE])

    def test_cli_restores_matching_pin_receipt_and_writes_only_approved_slots(self):
        from test_update_susfs_sources import profiles
        profile, manager_pins = profiles()
        baseline = {verifier.PROFILE: profile, verifier.MANAGER_PINS: manager_pins,
                    verifier.SUSFS_RECEIPT: {'fixed': 'original bytes'},
                    verifier.APPROVED_PATH: verifier.approved_document(self.approved),
                    'data/upstream-candidates.json': {'sources': self.snapshot}}
        with verifier.temporary_directory(ROOT / 'tests', '.manager-promotion-') as workspace:
            originals = {}
            for name, value in baseline.items():
                path = workspace / name
                path.parent.mkdir(parents=True, exist_ok=True)
                originals[name] = (json.dumps(value) + '\n').encode()
                path.write_bytes(originals[name])
            verifier.git(workspace, 'init', '-q')
            verifier.git(workspace, 'add', '--', *baseline)
            verifier.git(workspace, '-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid',
                         '-c', 'commit.gpgsign=false', 'commit', '-qm', 'fixture')
            self.assertEqual(('4' * 40, 'main'), verifier.read_approved(workspace)['BakaSU'][verifier.LATEST])
            profile['sukisu_susfs']['pins']['android12-5.10'] = '2' * 40
            (workspace / verifier.PROFILE).write_text(json.dumps(profile), encoding='utf-8')
            (workspace / verifier.SUSFS_RECEIPT).write_text('{"fixed":"proposed"}', encoding='utf-8')

            def verify(repository, variant, reference, count, **options):
                if variant == 'SukiSU':
                    raise verifier.SourceIntegrationError('SUSFS source unavailable', 41117)
                return {'version_code': 35259, 'checks': []}
            self.checking.side_effect = verify
            report, outputs = workspace / 'verify.json', workspace / 'outputs'
            code = verifier.main(['--root', str(workspace), '--sources', 'data/upstream-candidates.json',
                '--source-cache', str(workspace / 'cache'), '--compatibility-report', str(report),
                '--github-output', str(outputs)])
            self.assertEqual(0, code)
            self.assertEqual(('d' * 40, 'main'), verifier.read_approved(workspace)['BakaSU'][verifier.LATEST])
            self.assertEqual(self.approved['SukiSU'], verifier.read_approved(workspace)['SukiSU'])
            self.assertEqual('approved_changed=true\npending_slots=1\npins_retained=true\n',
                             outputs.read_text(encoding='utf-8'))
            self.assertEqual('SukiSU', json.loads(report.read_text('utf-8'))['pin_failures'][0]['source'])
            for name in (verifier.PROFILE, verifier.MANAGER_PINS, verifier.SUSFS_RECEIPT):
                self.assertEqual(originals[name], (workspace / name).read_bytes())


if __name__ == '__main__':
    unittest.main()
