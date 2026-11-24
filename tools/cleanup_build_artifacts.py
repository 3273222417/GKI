#!/usr/bin/env python3
"""Clean verified build transfers while retaining original APKs and Release assets."""
from __future__ import annotations

import argparse
from functools import partial
import json
import os
import re
import sys
from types import SimpleNamespace
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, Request, build_opener

from cleanup_workflow_runs import CleanupError, prebuild_inventory
from manager_lkm_jobs import KMIS
from manager_variants import MANAGERS


PREBUILD_PATH = '.github/workflows/prebuild-manager-apks.yml'
PREBUILD_API = '/actions/workflows/prebuild-manager-apks.yml'
PREBUILD_RECORD = '记录已验证的官方版本状态'
PREBUILD_EVENTS = ('push', 'schedule', 'workflow_run', 'workflow_dispatch')
INTERNAL_NATIVE = re.compile(
    r'internal-manager-native-(?:' + '|'.join(map(re.escape, MANAGERS))
    + r')-[0-9a-f]{40}-[0-9a-f]{24}-(?:' + '|'.join(map(re.escape, KMIS))
    + r')-[0-9a-f]{16}-[0-9a-f]{64}\Z')


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise CleanupError('Artifact maintenance does not follow authenticated redirects')


def api(repository: str, resource: str, *, method: str = 'GET'):
    token = os.environ.get('GH_TOKEN', '')
    if not token or any(ord(char) < 32 or ord(char) == 127 for char in token):
        raise CleanupError('A valid Actions token is required')
    request = Request(f'https://api.github.com/repos/{repository}{resource}', method=method,
                      headers={'Authorization': 'Bearer ' + token,
                               'Accept': 'application/vnd.github+json', 'User-Agent': 'gki-artifact-maintenance'})
    try:
        with build_opener(NoRedirect()).open(request, timeout=45) as response:
            raw = response.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            raise CleanupError('Artifact API response exceeded its limit')
        return json.loads(raw) if raw else None
    except HTTPError as error:
        if method == 'DELETE' and error.code == 404:
            return None
        raise CleanupError(f'Artifact API {method} failed (HTTP {error.code}); remaining artifacts preserved') from None
    except (OSError, URLError, ValueError):
        raise CleanupError('Artifact API request failed; remaining artifacts preserved') from None


def validate_release(release: dict, source_sha: str) -> dict:
    if (not isinstance(release, dict) or release.get('draft') is not False
            or release.get('prerelease') is not False or release.get('target_commitish') != source_sha):
        raise CleanupError('Expected a public Release for the verified build commit')
    assets = release.get('assets')
    if not isinstance(assets, list) or not 2 <= len(assets) <= 1000:
        raise CleanupError('Expected checksums and at least one public build file')
    expected = {}
    for asset in assets:
        name = asset.get('name', '')
        if (not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+@()-]{0,249}', name)
                or '..' in name or name in expected or
                not (name == 'SHA256SUMS.txt' or name.endswith(('.apk', '.img', '-AnyKernel3.zip')))
                or not isinstance(asset.get('size'), int) or asset['size'] <= 0
                or not re.fullmatch(r'sha256:[0-9a-f]{64}', asset.get('digest', ''))):
            raise CleanupError('Public Release asset identity is invalid or duplicated')
        expected[name] = asset
    if 'SHA256SUMS.txt' not in expected:
        raise CleanupError('Public Release is missing its checksums')
    return expected


def cleanup(run_id: str, release_tag: str | None = None, source_sha: str | None = None) -> list[str]:
    repository = os.environ.get('GITHUB_REPOSITORY', '')
    current = os.environ.get('GITHUB_RUN_ID', '')
    head_sha = os.environ.get('GITHUB_SHA', '')
    attempt = os.environ.get('GITHUB_RUN_ATTEMPT', '1')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise CleanupError('Expected a valid Actions repository')
    if not re.fullmatch(r'[1-9][0-9]*', run_id) or run_id != current:
        raise CleanupError('Cleanup may only delete artifacts belonging to the current run')
    source_sha = source_sha or head_sha
    if not re.fullmatch(r'[0-9a-f]{40}', head_sha) or not re.fullmatch(r'[0-9a-f]{40}', source_sha):
        raise CleanupError('Expected a complete verified build commit')
    release_tag = release_tag or f'gki-{run_id}-{attempt}'
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,199}', release_tag):
        raise CleanupError('Invalid Release tag')
    run = api(repository, f'/actions/runs/{run_id}')
    if (run.get('head_sha') != head_sha or run.get('head_repository', {}).get('full_name') != repository):
        raise CleanupError('Current run source identity does not match Actions')
    expected = validate_release(api(repository, '/releases/tags/' + quote(release_tag, safe='')), source_sha)
    artifacts = []
    for page in range(1, 12):
        document = api(repository, f'/actions/runs/{run_id}/artifacts?per_page=100&page={page}')
        batch = document.get('artifacts') if isinstance(document, dict) else None
        if not isinstance(batch, list) or len(batch) > 100 or document.get('total_count', 1001) > 1000:
            raise CleanupError('Artifact listing is invalid or exceeds its limit')
        artifacts.extend(batch)
        if len(batch) < 100:
            break
    else:
        raise CleanupError('Artifact listing did not finish')
    for name, asset in expected.items():
        matches = [item for item in artifacts if item.get('name') == name]
        if (len(matches) != 1 or matches[0].get('expired') is not False
                or matches[0].get('digest') != asset['digest']
                or matches[0].get('size_in_bytes') != asset['size']):
            raise CleanupError(f'Original artifact does not match the public Release: {name}; staging preserved')
    staging = [item for item in artifacts if isinstance(item.get('name'), str) and
               item['name'].startswith(('Release-', 'Manager-Identity-', 'Source-SukiSU-', 'AnyKernel3-', 'SukiSU_kernel-'))]
    ids = [item.get('id') for item in staging]
    if any(type(value) is not int or value <= 0 for value in ids) or len(ids) != len(set(ids)):
        raise CleanupError('Staging artifact IDs are invalid; no files deleted')
    # All verification finishes before the first mutation. Unknown diagnostic
    # artifacts and public Release assets are never removed by this tool.
    deleted = []
    for item in staging:
        api(repository, f'/actions/artifacts/{item["id"]}', method='DELETE')
        deleted.append(item['name'])
    print(json.dumps({'verified_original_files': list(expected), 'deleted_staging': deleted}, ensure_ascii=False))
    return deleted


def prebuild_run(repository: str, run_id: str, source_sha: str, workflow_id: int,
                 *, completed: bool, attempt: int | None = None) -> dict:
    run = api(repository, '/actions/runs/' + run_id)
    identity = run.get('repository') if isinstance(run, dict) else None
    origin = run.get('head_repository') if isinstance(run, dict) else None
    if (not isinstance(run, dict) or type(run.get('id')) is not int or run['id'] != int(run_id)
            or type(run.get('workflow_id')) is not int or run['workflow_id'] != workflow_id or run.get('path') != PREBUILD_PATH
            or run.get('head_sha') != source_sha or run.get('head_branch') != 'main'
            or run.get('event') not in PREBUILD_EVENTS
            or type(run.get('run_attempt')) is not int or run['run_attempt'] <= 0
            or (attempt is not None and run['run_attempt'] != attempt)
            or not isinstance(identity, dict) or not isinstance(origin, dict)
            or identity.get('full_name') != repository or origin.get('full_name') != repository
            or type(identity.get('id')) is not int or identity['id'] <= 0
            or type(origin.get('id')) is not int or origin['id'] != identity['id']):
        raise CleanupError('Prebuild run workflow, repository, attempt or source identity does not match')
    if completed:
        valid = run.get('status') == 'completed' and run.get('conclusion') == 'success'
    else:
        valid = run.get('status') == 'in_progress' and run.get('conclusion') is None
    if not valid:
        raise CleanupError('Prebuild cleanup requires a successful completed run or its active final recorder')
    return run


def cleanup_prebuild(run_id: str, *, repository: str | None = None, source_sha: str | None = None,
                     completed: bool = False, execute: bool = False) -> list[str]:
    """Remove only same-run native transfers after every APK consumer succeeds."""
    repository = repository or os.environ.get('GITHUB_REPOSITORY', '')
    source_sha = source_sha or os.environ.get('GITHUB_SHA', '')
    if (not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository)
            or not isinstance(run_id, str) or not re.fullmatch(r'[1-9][0-9]*', run_id)
            or not re.fullmatch(r'[0-9a-f]{40}', source_sha)):
        raise CleanupError('Expected an exact prebuild repository, run ID and source SHA')
    attempt = None
    if not completed:
        if (repository != os.environ.get('GITHUB_REPOSITORY') or source_sha != os.environ.get('GITHUB_SHA')
                or run_id != os.environ.get('GITHUB_RUN_ID')
                or os.environ.get('GITHUB_JOB') != 'record-manager-prebuild'
                or not re.fullmatch(r'[1-9][0-9]*', os.environ.get('GITHUB_RUN_ATTEMPT', ''))):
            raise CleanupError('Active prebuild cleanup may only run inside its current final recorder')
        attempt = int(os.environ['GITHUB_RUN_ATTEMPT'])
    workflow = api(repository, PREBUILD_API)
    if (not isinstance(workflow, dict) or workflow.get('path') != PREBUILD_PATH
            or type(workflow.get('id')) is not int or workflow['id'] <= 0):
        raise CleanupError('Could not confirm the exact manager prebuild workflow')
    run = prebuild_run(repository, run_id, source_sha, workflow['id'], completed=completed, attempt=attempt)
    attempt = run['run_attempt']
    client = SimpleNamespace(request=partial(api, repository))
    jobs = prebuild_inventory(client, f'/actions/runs/{run_id}/attempts/{attempt}/jobs', 'jobs')
    apks = [job for job in jobs if job['name'].endswith(' · 预编译管理器 APK')]
    if not apks or any(job.get('status') != 'completed' or job.get('conclusion') != 'success' for job in apks):
        raise CleanupError('Every prebuild APK consumer must finish successfully before native cleanup')
    if not completed and sum(job['name'] == PREBUILD_RECORD for job in jobs) != 1:
        raise CleanupError('Current prebuild final recorder is missing or duplicated')
    for job in jobs:
        if type(job.get('run_id')) is not int or job['run_id'] != int(run_id):
            raise CleanupError('Prebuild job belongs to a different run')
        if not completed and job['name'] == PREBUILD_RECORD:
            if job.get('status') == 'in_progress' and job.get('conclusion') is None:
                continue
        if job.get('status') != 'completed' or job.get('conclusion') not in ('success', 'skipped'):
            raise CleanupError('Prebuild consumers are unfinished or failed; native artifacts preserved')
    artifacts = prebuild_inventory(client, f'/actions/runs/{run_id}/artifacts', 'artifacts')
    staging = [item for item in artifacts if INTERNAL_NATIVE.fullmatch(item['name'])]
    for item in staging:
        origin = item.get('workflow_run')
        if (not isinstance(origin, dict) or type(origin.get('id')) is not int or origin['id'] != int(run_id)
                or origin.get('head_sha') != source_sha or origin.get('head_branch') != 'main'
                or type(origin.get('repository_id')) is not int or origin['repository_id'] != run['repository']['id']
                or type(origin.get('head_repository_id')) is not int or origin['head_repository_id'] != run['repository']['id']
                or item.get('expired') is not False
                or type(item.get('size_in_bytes')) is not int or item['size_in_bytes'] <= 0
                or not isinstance(item.get('digest'), str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', item['digest'])):
            raise CleanupError('Internal native artifact provenance is invalid; no artifacts deleted')
    prebuild_run(repository, run_id, source_sha, workflow['id'], completed=completed, attempt=attempt)
    for item in staging:
        if execute:
            api(repository, f'/actions/artifacts/{item["id"]}', method='DELETE')
    names = [item['name'] for item in staging]
    print(json.dumps({'run_id': run_id, 'mode': 'execute' if execute else 'dry-run',
                      'deleted_internal' if execute else 'internal_candidates': names}, ensure_ascii=False))
    return names


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--release-tag')
    parser.add_argument('--source-sha')
    parser.add_argument('--prebuild-internal', action='store_true')
    parser.add_argument('--completed-run', action='store_true')
    parser.add_argument('--repo')
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.prebuild_internal:
            if args.release_tag or (args.completed_run and (not args.repo or not args.source_sha)):
                raise CleanupError('Completed prebuild cleanup requires an explicit repository and source SHA')
            cleanup_prebuild(args.run_id, repository=args.repo, source_sha=args.source_sha,
                             completed=args.completed_run, execute=args.execute)
        else:
            if args.completed_run or args.repo or args.execute:
                raise CleanupError('Prebuild options require --prebuild-internal')
            cleanup(args.run_id, args.release_tag, args.source_sha)
    except (CleanupError, KeyError, TypeError) as error:
        print('Artifact cleanup failed: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
