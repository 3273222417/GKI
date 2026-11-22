#!/usr/bin/env python3
"""Download only the official Re-Kernel driver, retrying interrupted transfers."""
from __future__ import annotations

import argparse
from http.client import IncompleteRead
import json
import os
from pathlib import Path
import re
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from snapshot_ksu_source import GitCommandError, SnapshotError, git, temporary_directory


OFFICIAL = 'https://github.com/Sakion-Team/Re-Kernel.git'
API_COMMITS = 'https://api.github.com/repos/Sakion-Team/Re-Kernel/commits'
API_HEAD = API_COMMITS + '?per_page=1'
MAX_HEAD_RESPONSE = 128 * 1024
REQUIRED = ('Makefile', 'Kconfig', 'rekernel_main.c', 'rekernel.h')
NETWORK_OPTIONS = (
    '-c', 'http.version=HTTP/1.1',
    '-c', 'http.lowSpeedLimit=1024', '-c', 'http.lowSpeedTime=30',
    '-c', 'http.extraHeader=', '-c', 'http.https://github.com/.extraHeader=',
    '-c', 'credential.helper=', '-c', 'http.followRedirects=false',
    '-c', 'protocol.version=2',
)
ATTEMPTS = 3
TOTAL_TIMEOUT = 300


def _remaining(deadline: float, limit: int) -> int:
    remaining = int(deadline - time.monotonic())
    if remaining < 1:
        raise SnapshotError('Official Re-Kernel download exceeded its five-minute deadline')
    return min(limit, remaining)


def _retry(attempt: int, deadline: float, error: GitCommandError) -> None:
    if attempt + 1 == ATTEMPTS:
        raise SnapshotError('Official Re-Kernel download failed after three attempts: '
                            + error.diagnostic) from None
    delay = (5, 15)[attempt]
    if deadline - time.monotonic() <= delay:
        raise SnapshotError('Official Re-Kernel download exceeded its five-minute deadline') from None
    print(f'Re-Kernel transfer interrupted ({error.diagnostic}); retrying in {delay}s', flush=True)
    time.sleep(delay)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def api_head(deadline: float) -> str | None:
    """Resolve the same official default branch over HTTPS if Git stalls.

    An optional workflow token goes only to this fixed, non-redirecting API.
    A transient outage
    leaves the existing bounded Git retries available; invalid identity or
    permanent HTTP errors stop before any source can be published.
    """
    headers = {
        'Accept': 'application/vnd.github+json', 'User-Agent': 'gki-rekernel-source',
        'X-GitHub-Api-Version': '2022-11-28', 'Cache-Control': 'no-cache'}
    token = os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')
    if token:
        if any(ord(char) < 32 or ord(char) == 127 for char in token):
            raise SnapshotError('Invalid authentication for the official Re-Kernel API')
        headers['Authorization'] = 'Bearer ' + token
    request = Request(API_HEAD, headers=headers)
    try:
        with build_opener(_NoRedirect()).open(request, timeout=_remaining(deadline, 20)) as response:
            if response.status != 200 or response.geturl() != API_HEAD:
                raise SnapshotError('Official Re-Kernel API returned an unexpected response')
            raw = response.read(MAX_HEAD_RESPONSE + 1)
            _remaining(deadline, 1)
    except HTTPError as error:
        transient = (error.code in (408, 429) or 500 <= error.code <= 599
                     or (error.code == 403 and error.headers.get('X-RateLimit-Remaining') == '0'))
        status = error.code
        error.close()
        if not transient:
            raise SnapshotError(f'Official Re-Kernel API refused HEAD lookup (HTTP {status})') from None
        print('Official Re-Kernel API temporarily unavailable; retaining bounded Git retries', flush=True)
        return None
    except (URLError, TimeoutError, OSError, IncompleteRead):
        print('Official Re-Kernel API connection unavailable; retaining bounded Git retries', flush=True)
        return None
    if len(raw) > MAX_HEAD_RESPONSE:
        raise SnapshotError('Official Re-Kernel API HEAD response exceeds its size limit')
    try:
        rows = json.loads(raw)
    except (UnicodeError, ValueError):
        raise SnapshotError('Official Re-Kernel API HEAD response is not valid JSON') from None
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise SnapshotError('Official Re-Kernel API did not return one default-branch commit')
    reference = rows[0].get('sha')
    if (not isinstance(reference, str) or not re.fullmatch(r'[0-9a-f]{40}', reference)
            or rows[0].get('url') != API_COMMITS + '/' + reference):
        raise SnapshotError('Official Re-Kernel API returned an invalid commit identity')
    return reference


def resolve_head(parent: Path, deadline: float) -> str:
    # Resolve once: a retry must not change to a newer moving upstream HEAD.
    for attempt in range(ATTEMPTS):
        try:
            value = git(parent, *NETWORK_OPTIONS, 'ls-remote', '--exit-code', OFFICIAL, 'HEAD',
                        timeout=_remaining(deadline, 45))
        except GitCommandError as error:
            if attempt == 0 and error.transient:
                print('Re-Kernel Git HEAD lookup interrupted; checking the official GitHub API', flush=True)
                reference = api_head(deadline)
                if reference is not None:
                    return reference
            _retry(attempt, deadline, error)
            continue
        rows = value.splitlines()
        if len(rows) != 1 or not re.fullmatch(r'[0-9a-f]{40}\s+HEAD', rows[0]):
            raise SnapshotError('Official Re-Kernel HEAD did not return one full commit identity')
        return rows[0].split()[0]
    raise AssertionError('Unreachable Re-Kernel retry state')


def verify_source(source: Path, reference: str, deadline: float) -> None:
    if git(source, 'rev-parse', '--verify', 'HEAD', timeout=_remaining(deadline, 10)) != reference:
        raise SnapshotError('Official Re-Kernel checkout differs from its selected commit')
    if git(source, 'remote', 'get-url', 'origin', timeout=_remaining(deadline, 10)) != OFFICIAL:
        raise SnapshotError('Re-Kernel source origin differs from the official repository')
    driver = source / 'LKM-Source'
    if driver.is_symlink() or not driver.is_dir():
        raise SnapshotError('Official Re-Kernel source is missing its regular LKM-Source directory')
    entries = git(source, 'ls-tree', '-r', reference, '--', 'LKM-Source',
                  timeout=_remaining(deadline, 10)).splitlines()
    names = set()
    for entry in entries:
        match = re.fullmatch(r'(100644|100755) blob ([0-9a-f]{40})\t(LKM-Source/[^\r\n]+)', entry)
        if not match:
            raise SnapshotError('Re-Kernel LKM source contains a symlink or unsupported Git entry')
        names.add(match[3])
    if any('LKM-Source/' + name not in names for name in REQUIRED):
        raise SnapshotError('Official Re-Kernel source lacks its required driver files')
    for path in {*driver.glob('*.c'), *driver.glob('*.h'), *(driver / name for name in REQUIRED)}:
        if path.is_symlink() or not path.is_file() or not path.stat().st_size:
            raise SnapshotError('Official Re-Kernel driver file is missing, empty or not a regular file')
    if git(source, 'status', '--porcelain', '--untracked-files=all', timeout=_remaining(deadline, 10)):
        raise SnapshotError('Official Re-Kernel checkout is not clean')


def download_source(output: Path) -> str:
    output = output.absolute()
    if output.exists() or output.is_symlink():
        raise SnapshotError('Re-Kernel output already exists; refusing to overwrite it')
    if not output.parent.is_dir():
        raise SnapshotError('Re-Kernel output parent directory does not exist')
    deadline = time.monotonic() + TOTAL_TIMEOUT
    reference = resolve_head(output.parent, deadline)
    print('Selected official Re-Kernel commit: ' + reference, flush=True)
    for attempt in range(ATTEMPTS):
        try:
            with temporary_directory(output.parent, '.gki-rekernel-') as temporary:
                prepared = temporary / 'source'
                prepared.mkdir()
                git(prepared, 'init', '--quiet', timeout=_remaining(deadline, 10))
                git(prepared, 'remote', 'add', 'origin', OFFICIAL, timeout=_remaining(deadline, 10))
                git(prepared, 'config', 'core.sparseCheckout', 'true', timeout=_remaining(deadline, 10))
                git(prepared, 'config', 'remote.origin.promisor', 'true', timeout=_remaining(deadline, 10))
                git(prepared, 'config', 'remote.origin.partialclonefilter', 'blob:none',
                    timeout=_remaining(deadline, 10))
                # Non-cone mode excludes even root-level binaries and archives.
                (prepared / '.git/info/sparse-checkout').write_text('/LKM-Source/\n', encoding='utf-8')
                git(prepared, *NETWORK_OPTIONS, 'fetch', '--quiet', '--depth=1', '--filter=blob:none',
                    '--no-tags', '--no-recurse-submodules', 'origin', reference,
                    timeout=_remaining(deadline, 120))
                # Checkout may lazily fetch the selected driver blobs. The same
                # HTTP/1.1, low-speed and hard time limits cover that request.
                git(prepared, *NETWORK_OPTIONS, 'checkout', '--quiet', '--detach', reference,
                    timeout=_remaining(deadline, 120))
                verify_source(prepared, reference, deadline)
                if output.exists() or output.is_symlink():
                    raise SnapshotError('Re-Kernel output appeared while downloading; refusing to overwrite it')
                prepared.rename(output)
            return reference
        except GitCommandError as error:
            # Every retry gets a fresh isolated directory, including after a
            # truncated pack or interrupted lazy checkout. Never reuse it.
            _retry(attempt, deadline, error)
    raise AssertionError('Unreachable Re-Kernel retry state')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        reference = download_source(args.output)
    except (OSError, ValueError) as error:
        # Git failures are already classified without raw stderr or credentials.
        reason = str(error) if isinstance(error, SnapshotError) else 'Local source preparation failed'
        print('::error::Re-Kernel source download failed: ' + reason, file=sys.stderr)
        return 1
    print('Verified official Re-Kernel driver: ' + reference, flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
