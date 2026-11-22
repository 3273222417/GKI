"""Replay the observed Sui download failure through actual child processes."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import call, patch

import build_fina_manager as builder


FAILURE = (Path(__file__).parent / 'fixtures/fina-gradle-429.txt').read_text('utf-8')
DRIVER = '''
import json, os, sys
from pathlib import Path
step = sys.argv[1]
record = Path('calls.json')
calls = json.loads(record.read_text()) if record.exists() else []
calls.append({'stage': step, 'abis': os.environ.get('ABIS'), 'kmis': os.environ.get('KMIS'),
              'key': os.environ.get('KEYSTORE_PROPS'),
              'permanent_key_present': 'SUKISU_APK_KEYSTORE' in os.environ,
              'key_available': Path(os.environ.get('KEYSTORE_PROPS', 'missing-key')).is_file()})
record.write_text(json.dumps(calls))
attempt = sum(c['stage'] == step for c in calls)
if step == 'repack' or (step == os.environ['FAIL_STAGE'] and attempt <= int(os.environ['FAIL_COUNT'])):
    print(Path(os.environ['FAIL_LOG']).read_text())
    sys.exit(1)
print('completed ' + step)
'''


class FinaGradleRetryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        self.driver = self.root / 'driver.py'
        self.driver.write_text(DRIVER, encoding='utf-8')
        self.failure = self.root / 'failure.log'
        self.failure.write_text(FAILURE, encoding='utf-8')
        self.environment = {**os.environ, 'FAIL_STAGE': 'sui', 'FAIL_COUNT': '1',
                            'FAIL_LOG': str(self.failure), 'ABIS': 'arm64-v8a x86_64 riscv64',
                            'KMIS': 'android12-5.10 android16-6.12'}

    def calls(self):
        return json.loads((self.source / 'calls.json').read_text())

    def full_build_until_repack(self, stage='sui', count=1):
        native_popen = subprocess.Popen

        def redirected(arguments, **options):
            name = arguments[2] if arguments[1] == 'build.sh' else 'daemon'
            return native_popen([sys.executable, str(self.driver), name], **options)

        def generate(key, password, environment):
            key.write_bytes(b'disposable-test-key')

        environment = {**self.environment, 'RUNNER_TEMP': str(self.root),
                       'FAIL_STAGE': stage, 'FAIL_COUNT': str(count),
                       'SUKISU_APK_KEYSTORE': 'permanent-key-must-not-leave-caller'}
        with (patch.dict(os.environ, environment), patch.object(builder, 'prepare'),
              patch.object(builder, 'official_abis', return_value=('arm64-v8a', 'x86_64', 'riscv64')),
              patch.object(builder, 'payload_steps', return_value=['nomount', 'sui', 'folkzygisk', 'apk']),
              patch.object(builder, 'generate_build_key', side_effect=generate),
              patch.object(builder.subprocess, 'Popen', side_effect=redirected),
              patch.object(builder.time, 'sleep') as sleep, redirect_stdout(io.StringIO())):
            with self.assertRaisesRegex(ValueError, 'canonical native build'):
                builder.build(self.source, self.root / 'output')
        return sleep.call_args_list

    def test_sui_retry_preserves_nomount_all_payloads_and_disposable_key(self):
        sleeps = self.full_build_until_repack()
        rows = self.calls()
        self.assertEqual(['nomount', 'sui', 'sui', 'folkzygisk', 'apk', 'daemon', 'repack'],
                         [r['stage'] for r in rows])
        self.assertEqual([call(30)], sleeps)
        self.assertEqual(1, len({r['key'] for r in rows}))
        self.assertTrue(all(r['key_available'] for r in rows))
        self.assertFalse(any(r['permanent_key_present'] for r in rows))
        self.assertTrue(all(r['abis'] == 'arm64-v8a x86_64 riscv64' for r in rows))
        self.assertTrue(all(r['kmis'] == ' '.join(builder.KMIS) for r in rows))
        self.assertFalse(Path(rows[0]['key']).exists())
        self.assertFalse((self.root / 'output/manager-unsigned.apk').exists())

    def test_apk_retry_does_not_rebuild_sui_nomount_or_folkzygisk(self):
        self.assertEqual([call(30)], self.full_build_until_repack('apk'))
        self.assertEqual(['nomount', 'sui', 'folkzygisk', 'apk', 'apk', 'daemon', 'repack'],
                         [r['stage'] for r in self.calls()])

    def test_persistent_rate_limit_stops_after_three_tries_without_publishing(self):
        self.assertEqual([call(30), call(60)], self.full_build_until_repack(count=99))
        self.assertEqual(['nomount', 'sui', 'sui', 'sui'], [r['stage'] for r in self.calls()])
        self.assertFalse(Path(self.calls()[0]['key']).exists())
        self.assertFalse((self.root / 'output/manager-unsigned.apk').exists())

    def test_temporary_http_downloads_only(self):
        self.assertTrue(builder.transient_gradle_download(FAILURE))
        for code in ('408', '429', '500', '502', '503', '504'):
            with self.subTest(code=code):
                self.assertTrue(builder.transient_gradle_download(FAILURE.replace('code 429', 'code ' + code)))
        for code in ('301', '401', '403', '404', '422'):
            with self.subTest(code=code):
                self.assertFalse(builder.transient_gradle_download(FAILURE.replace('code 429', 'code ' + code)))
        self.assertFalse(builder.transient_gradle_download(FAILURE.replace('repo.maven.apache.org', 'unknown.invalid')))
        self.assertFalse(builder.transient_gradle_download('Received status code 429 from server'))

    def test_current_compile_integrity_or_signing_error_never_retries(self):
        for problem in ('Compilation error', 'checksum verification failed',
                        'keystore invalid', 'error: unresolved reference: broken'):
            with self.subTest(problem=problem):
                self.assertFalse(builder.transient_gradle_download(
                    FAILURE.replace('* Try:', problem + '\n* Try:')))
        current_failure = '\n* What went wrong:\nExecution failed: Compilation error\n* Try:\n'
        self.assertFalse(builder.transient_gradle_download(FAILURE + current_failure))
        self.failure.write_text(FAILURE + current_failure, encoding='utf-8')
        with patch.object(builder.time, 'sleep') as sleep, redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ValueError, 'canonical native build'):
                builder.run_stage([sys.executable, str(self.driver), 'sui'], self.source,
                                  self.environment, 'test-password', retry_gradle=True)
        sleep.assert_not_called()
        self.assertEqual(['sui'], [r['stage'] for r in self.calls()])

    def test_output_still_redacts_the_disposable_password(self):
        self.failure.write_text(FAILURE + '\ntest-secret-password\n', encoding='utf-8')
        self.environment['FAIL_COUNT'] = '99'
        with patch.object(builder.time, 'sleep'), redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(ValueError):
                builder.run_stage([sys.executable, str(self.driver), 'sui'], self.source,
                                  self.environment, 'test-secret-password', retry_gradle=True)
        self.assertNotIn('test-secret-password', output.getvalue())


if __name__ == '__main__':
    unittest.main()
