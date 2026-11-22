"""Real shallow sparse checkouts and interrupted official Re-Kernel transfers."""
from contextlib import redirect_stderr, redirect_stdout
from http.client import IncompleteRead
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest import mock
from urllib.error import HTTPError, URLError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import rekernel_source as source
import snapshot_ksu_source as snapshot


@unittest.skipUnless(shutil.which('git'), 'Git is required')
class ReKernelSourceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = snapshot.temporary_directory(ROOT.parent, '.rs-')
        self.root = self.temporary.__enter__()
        self.addCleanup(self.temporary.__exit__, None, None, None)
        self.upstream = self.root / 'official-fixture'
        self.upstream.mkdir()
        snapshot.git(self.upstream, 'init', '--quiet')
        snapshot.git(self.upstream, 'config', 'user.name', 'Source transport regression')
        snapshot.git(self.upstream, 'config', 'user.email', 'test@example.invalid')
        snapshot.git(self.upstream, 'config', 'core.autocrlf', 'false')
        snapshot.git(self.upstream, 'config', 'uploadpack.allowFilter', 'true')
        driver = self.upstream / 'LKM-Source'
        driver.mkdir()
        for name in source.REQUIRED:
            (driver / name).write_text('original real Git fixture: ' + name + '\n', encoding='utf-8')
        (driver / 'rekernel_binder.c').write_text('int binder_fixture(void) { return 1; }\n', encoding='utf-8')
        (self.upstream / 'unused-binary.bin').write_bytes(b'unused binary payload\0' * 1024)
        unused = self.upstream / 'unused-directory'
        unused.mkdir()
        (unused / 'archive.zip').write_bytes(b'not part of the driver')
        self.commit()
        self.reference = snapshot.git(self.upstream, 'rev-parse', 'HEAD')
        self.output = self.root / 'downloaded'
        self.calls = []
        # Existing Git regressions must never reach the real public API.
        self.api = self.enterContext(mock.patch.object(source, 'api_head', return_value=None))

    def commit(self):
        snapshot.git(self.upstream, 'add', '.')
        snapshot.git(self.upstream, 'commit', '--quiet', '-m', 'official source fixture')

    def transport(self, directory, *args, **kwargs):
        self.calls.append((Path(directory), args, kwargs))
        if 'ls-remote' in args or 'fetch' in args or 'checkout' in args:
            self.assertEqual(120 if 'ls-remote' not in args else 45, kwargs['timeout'])
            self.assertIn('http.version=HTTP/1.1', args)
            self.assertIn('http.lowSpeedTime=30', args)
            self.assertIn('credential.helper=', args)
            # Production still uses the sole fixed official remote; only the
            # test transport redirects that URL to this real local Git server.
            rewrite = 'url.' + self.upstream.as_uri() + '.insteadOf=' + source.OFFICIAL
            return snapshot.git(directory, '-c', rewrite, *args, **kwargs)
        return snapshot.git(directory, *args, **kwargs)

    def download(self, transport=None):
        with mock.patch.object(source, 'git', side_effect=transport or self.transport), \
                mock.patch.object(source.time, 'sleep'):
            return source.download_source(self.output)

    def assert_no_partial_output(self):
        self.assertFalse(self.output.exists())
        self.assertEqual([], list(self.root.glob('.gki-rekernel-*')))

    def test_sparse_shallow_driver_preserves_exact_source_and_skips_unused_binaries(self):
        reference = self.download()
        self.assertEqual(self.reference, reference)
        self.assertEqual(self.reference, snapshot.git(self.output, 'rev-parse', 'HEAD'))
        self.assertEqual(source.OFFICIAL, snapshot.git(self.output, 'remote', 'get-url', 'origin'))
        self.assertEqual('true', snapshot.git(self.output, 'rev-parse', '--is-shallow-repository'))
        self.assertEqual('', snapshot.git(self.output, 'status', '--porcelain', '--untracked-files=all'))
        self.assertFalse((self.output / 'unused-binary.bin').exists())
        self.assertFalse((self.output / 'unused-directory').exists())
        for path in (self.upstream / 'LKM-Source').iterdir():
            self.assertEqual(path.read_bytes(), (self.output / 'LKM-Source' / path.name).read_bytes())
        fetches = [args for _, args, _ in self.calls if 'fetch' in args]
        self.assertEqual(1, len(fetches))
        self.assertIn('--depth=1', fetches[0])
        self.assertIn('--filter=blob:none', fetches[0])
        self.assertIn('--no-tags', fetches[0])
        self.assertIn(self.reference, fetches[0])
        self.assertEqual([], list(self.root.glob('.gki-rekernel-*')))

    def test_truncated_fetch_is_discarded_and_retried_with_same_selected_commit(self):
        attempts = []

        def interrupted(directory, *args, **kwargs):
            if 'fetch' in args:
                attempts.append(Path(directory))
                if len(attempts) == 1:
                    (Path(directory) / '.git/incomplete-pack').write_bytes(b'truncated pack')
                    # Upstream moves while the retry is waiting. It must not
                    # change the already selected source revision.
                    (self.upstream / 'LKM-Source/rekernel_main.c').write_text('new upstream\n', encoding='utf-8')
                    self.commit()
                    raise snapshot.GitCommandError('fetch', category='connection failure', returncode=128)
                self.assertFalse(attempts[0].exists())
                self.assertFalse((Path(directory) / '.git/incomplete-pack').exists())
                self.assertIn(self.reference, args)
            return self.transport(directory, *args, **kwargs)

        self.assertEqual(self.reference, self.download(interrupted))
        self.assertEqual(2, len(attempts))
        self.assertNotEqual(attempts[0], attempts[1])
        self.assertIn('original real Git fixture',
                      (self.output / 'LKM-Source/rekernel_main.c').read_text(encoding='utf-8'))
        self.assertEqual(1, sum('ls-remote' in args for _, args, _ in self.calls))

    def test_interrupted_lazy_checkout_restarts_with_fresh_repository(self):
        attempts = []

        def interrupted(directory, *args, **kwargs):
            if 'checkout' in args:
                attempts.append(Path(directory))
                if len(attempts) == 1:
                    partial = Path(directory) / 'LKM-Source'
                    partial.mkdir()
                    (partial / 'rekernel_main.c').write_text('partial corrupt checkout', encoding='utf-8')
                    raise snapshot.GitCommandError('checkout', timeout=120)
                self.assertFalse(attempts[0].exists())
            return self.transport(directory, *args, **kwargs)

        self.assertEqual(self.reference, self.download(interrupted))
        self.assertEqual(2, len(attempts))
        self.assertNotIn('partial corrupt', (self.output / 'LKM-Source/rekernel_main.c').read_text())

    def test_all_fetches_fail_without_publishing_partial_source_or_removing_neighbor(self):
        neighbor = self.root / 'unrelated'
        neighbor.mkdir()
        (neighbor / 'keep').write_bytes(b'preserved')
        attempts = []

        def unavailable(directory, *args, **kwargs):
            if 'fetch' in args:
                attempts.append(Path(directory))
                raise snapshot.GitCommandError('fetch', category='connection failure', returncode=128)
            return self.transport(directory, *args, **kwargs)

        with self.assertRaisesRegex(snapshot.SnapshotError, 'after three attempts'):
            self.download(unavailable)
        self.assertEqual(3, len(attempts))
        self.assertEqual(3, len(set(attempts)))
        self.assert_no_partial_output()
        self.assertEqual(b'preserved', (neighbor / 'keep').read_bytes())

    def test_head_lookup_retries_then_resolves_once_before_fetch(self):
        calls = []

        def intermittent(directory, *args, **kwargs):
            if 'ls-remote' in args:
                calls.append(args)
                if len(calls) < 3:
                    raise snapshot.GitCommandError('command', timeout=45)
            return self.transport(directory, *args, **kwargs)

        self.assertEqual(self.reference, self.download(intermittent))
        self.assertEqual(3, len(calls))

    def test_stalled_git_head_uses_api_and_pins_fetch_after_upstream_moves(self):
        self.api.return_value = self.reference
        original = self.reference

        def interrupted(directory, *args, **kwargs):
            if 'ls-remote' in args:
                (self.upstream / 'LKM-Source/rekernel_main.c').write_text('new upstream\n', encoding='utf-8')
                self.commit()
                raise snapshot.GitCommandError('ls-remote', timeout=45)
            return self.transport(directory, *args, **kwargs)

        self.assertEqual(original, self.download(interrupted))
        self.api.assert_called_once()
        self.assertEqual(original, snapshot.git(self.output, 'rev-parse', 'HEAD'))
        self.assertNotEqual(original, snapshot.git(self.upstream, 'rev-parse', 'HEAD'))
        self.assertIn('original real Git fixture',
                      (self.output / 'LKM-Source/rekernel_main.c').read_text(encoding='utf-8'))

    def test_permanent_git_failure_never_uses_api(self):
        with mock.patch.object(source, 'git', side_effect=snapshot.GitCommandError(
                'ls-remote', category='authentication failure', returncode=128)), \
                mock.patch.object(source.time, 'sleep'):
            with self.assertRaisesRegex(snapshot.SnapshotError, 'after three attempts'):
                source.download_source(self.output)
        self.api.assert_not_called()
        self.assert_no_partial_output()

    def test_missing_or_empty_required_driver_does_not_retry_or_publish(self):
        for mutation in ('missing', 'empty'):
            with self.subTest(mutation=mutation):
                target = self.upstream / 'LKM-Source/rekernel_main.c'
                if mutation == 'missing':
                    target.unlink()
                else:
                    target.write_bytes(b'')
                self.commit()
                self.calls.clear()
                with self.assertRaisesRegex(snapshot.SnapshotError, 'required driver files|missing, empty'):
                    self.download()
                self.assertEqual(1, sum('fetch' in args for _, args, _ in self.calls))
                self.assert_no_partial_output()

    def test_existing_output_is_never_removed_or_modified(self):
        self.output.mkdir()
        keep = self.output / 'keep'
        keep.write_bytes(b'caller owned')
        with mock.patch.object(source, 'git') as transport:
            with self.assertRaisesRegex(snapshot.SnapshotError, 'already exists'):
                source.download_source(self.output)
        transport.assert_not_called()
        self.assertEqual(b'caller owned', keep.read_bytes())

    def test_tracked_symlink_is_rejected_even_if_git_materializes_it_as_a_plain_file(self):
        # Windows Git can materialize mode 120000 as a plain text file when
        # symlink creation is unavailable. The committed mode still rejects it.
        result = subprocess.run(['git', '-C', str(self.upstream), 'hash-object', '-w', '--stdin'],
                                input='../../outside-source\n', capture_output=True, text=True,
                                encoding='utf-8', check=True)
        digest = result.stdout.strip()
        snapshot.git(self.upstream, 'update-index', '--cacheinfo', '120000', digest, 'LKM-Source/rekernel.h')
        snapshot.git(self.upstream, 'commit', '--quiet', '-m', 'symlink source fixture')
        with self.assertRaisesRegex(snapshot.SnapshotError, 'symlink or unsupported Git entry'):
            self.download()
        self.assert_no_partial_output()

    def test_retries_remain_bounded_by_total_deadline(self):
        error = snapshot.GitCommandError('fetch', timeout=120)
        with mock.patch.object(source.time, 'monotonic', return_value=298.0), \
                mock.patch.object(source.time, 'sleep') as sleep:
            with self.assertRaisesRegex(snapshot.SnapshotError, 'five-minute deadline'):
                source._retry(0, 300.0, error)
        sleep.assert_not_called()

    def test_output_that_appears_during_download_is_never_removed_or_replaced(self):
        def concurrent(directory, *args, **kwargs):
            result = self.transport(directory, *args, **kwargs)
            if 'checkout' in args:
                self.output.mkdir()
                (self.output / 'keep').write_bytes(b'new caller owned output')
            return result

        with self.assertRaisesRegex(snapshot.SnapshotError, 'appeared while downloading'):
            self.download(concurrent)
        self.assertEqual(b'new caller owned output', (self.output / 'keep').read_bytes())
        self.assertEqual([], list(self.root.glob('.gki-rekernel-*')))

    def test_total_download_deadline_stops_before_running_network(self):
        with mock.patch.object(source.time, 'monotonic', side_effect=(10.0, 311.0)), \
                mock.patch.object(source, 'git') as transport:
            with self.assertRaisesRegex(snapshot.SnapshotError, 'five-minute deadline'):
                source.download_source(self.output)
        transport.assert_not_called()
        self.assert_no_partial_output()

    def test_malformed_or_credential_bearing_head_output_is_not_logged(self):
        secret = 'https://user:fake-secret@example.invalid/private'
        with mock.patch.object(source, 'git', return_value=secret), \
                redirect_stderr(io.StringIO()) as errors, redirect_stdout(io.StringIO()) as output:
            self.assertEqual(1, source.main(['--output', str(self.output)]))
        self.assertNotIn(secret, errors.getvalue() + output.getvalue())
        self.assertIn('one full commit identity', errors.getvalue())
        self.assert_no_partial_output()

    def test_network_timeout_is_sanitized_and_eventually_fails(self):
        def timeout(command, **kwargs):
            raise subprocess.TimeoutExpired(command, timeout=kwargs['timeout'],
                                             stderr='fake-secret-token')

        with mock.patch.object(snapshot.subprocess, 'run', side_effect=timeout), \
                mock.patch.object(source.time, 'sleep'), \
                redirect_stderr(io.StringIO()) as errors, redirect_stdout(io.StringIO()) as output:
            self.assertEqual(1, source.main(['--output', str(self.output)]))
        combined = errors.getvalue() + output.getvalue()
        self.assertNotIn('fake-secret-token', combined)
        self.assertIn('after three attempts', combined)
        self.assert_no_partial_output()


class ReKernelHeadApiTests(unittest.TestCase):
    def setUp(self):
        self.reference = 'a' * 40
        self.opener = self.enterContext(mock.patch.object(source, 'build_opener')).return_value
        self.response = self.opener.open.return_value.__enter__.return_value
        self.response.status = 200
        self.response.geturl.return_value = source.API_HEAD
        self.response.read.return_value = json.dumps([
            {'sha': self.reference, 'url': source.API_COMMITS + '/' + self.reference}]).encode()
        self.enterContext(mock.patch.object(source.time, 'monotonic', return_value=10.0))
        self.enterContext(mock.patch.dict(source.os.environ, {'GH_TOKEN': '', 'GITHUB_TOKEN': ''}))

    def test_fixed_public_api_identity_and_no_redirect_or_credentials(self):
        self.assertEqual(self.reference, source.api_head(300.0))
        request = self.opener.open.call_args.args[0]
        self.assertEqual(source.API_HEAD, request.full_url)
        self.assertFalse(request.has_header('Authorization'))
        self.assertEqual(20, self.opener.open.call_args.kwargs['timeout'])
        self.response.read.assert_called_once_with(source.MAX_HEAD_RESPONSE + 1)
        self.assertIsNone(source._NoRedirect().redirect_request(None, None, 302, '', {},
                                                               'https://example.invalid/'))

    def test_malformed_or_other_repository_commit_is_not_accepted(self):
        for rows in ([], {}, [None], [{'sha': 'bad', 'url': 'secret'}],
                     [{'sha': self.reference, 'url': 'https://example.invalid/secret'}]):
            with self.subTest(rows=rows):
                self.response.read.return_value = json.dumps(rows).encode()
                with self.assertRaises(snapshot.SnapshotError):
                    source.api_head(300.0)

    def test_workflow_token_is_sent_only_to_fixed_api_and_never_logged(self):
        with mock.patch.dict(source.os.environ, {'GH_TOKEN': 'test-workflow-token'}), \
                redirect_stdout(io.StringIO()) as output:
            self.assertEqual(self.reference, source.api_head(300.0))
        request = self.opener.open.call_args.args[0]
        self.assertEqual(source.API_HEAD, request.full_url)
        self.assertEqual('Bearer test-workflow-token', request.get_header('Authorization'))
        self.assertNotIn('test-workflow-token', output.getvalue())

    def test_token_with_control_characters_is_rejected_before_network(self):
        with mock.patch.dict(source.os.environ, {'GH_TOKEN': 'secret\r\nInjected: header'}):
            with self.assertRaisesRegex(snapshot.SnapshotError, 'Invalid authentication'):
                source.api_head(300.0)
        self.opener.open.assert_not_called()

    def test_oversized_invalid_json_and_redirected_response_fail_closed(self):
        for raw in (b'x' * (source.MAX_HEAD_RESPONSE + 1), b'{not json', b'\xff'):
            with self.subTest(raw_size=len(raw)):
                self.response.read.return_value = raw
                with self.assertRaises(snapshot.SnapshotError):
                    source.api_head(300.0)
        self.response.geturl.return_value = 'https://example.invalid/'
        with self.assertRaisesRegex(snapshot.SnapshotError, 'unexpected response'):
            source.api_head(300.0)

    def test_transient_http_or_network_failure_retains_git_retries_without_raw_error(self):
        errors = [HTTPError(source.API_HEAD, code, 'fake-secret', {}, None)
                  for code in (408, 429, 500, 503)]
        errors += [HTTPError(source.API_HEAD, 403, 'fake-secret',
                             {'X-RateLimit-Remaining': '0'}, None), URLError('fake-secret'), TimeoutError('fake-secret')]
        for error in errors:
            with self.subTest(error=type(error).__name__), redirect_stdout(io.StringIO()) as output:
                self.opener.open.side_effect = error
                self.assertIsNone(source.api_head(300.0))
                self.assertNotIn('fake-secret', output.getvalue())

    def test_permanent_http_errors_never_return_a_commit_or_raw_error(self):
        for code in (301, 302, 401, 403, 404, 422):
            with self.subTest(code=code):
                self.opener.open.side_effect = HTTPError(source.API_HEAD, code, 'fake-secret', {}, None)
                with self.assertRaisesRegex(snapshot.SnapshotError, f'HTTP {code}') as found:
                    source.api_head(300.0)
                self.assertNotIn('fake-secret', str(found.exception))

    def test_interrupted_response_body_retains_git_retries_and_does_not_expose_partial_data(self):
        self.response.read.side_effect = IncompleteRead(b'fake-secret-partial-body', 20)
        with redirect_stdout(io.StringIO()) as output:
            self.assertIsNone(source.api_head(300.0))
        self.assertNotIn('fake-secret', output.getvalue())

    def test_deadline_is_shared_and_api_not_called_after_expiry(self):
        self.assertEqual(self.reference, source.api_head(13.0))
        self.assertEqual(3, self.opener.open.call_args.kwargs['timeout'])
        self.opener.open.reset_mock()
        with self.assertRaisesRegex(snapshot.SnapshotError, 'five-minute deadline'):
            source.api_head(10.0)
        self.opener.open.assert_not_called()


if __name__ == '__main__':
    unittest.main()
