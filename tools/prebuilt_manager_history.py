"""Read verified artifacts from trusted successful manager-producing runs."""
from __future__ import annotations

import hashlib
import re
from urllib.parse import urlencode

from resolve_build_sources import validate_ref
from wait_manager_identity import GitHubReader, IdentityError, validate_repository


WORKFLOW_FILE = 'prebuild-manager-apks.yml'
WORKFLOW_PATH = '.github/workflows/' + WORKFLOW_FILE
WORKFLOW_API = 'actions/workflows/' + WORKFLOW_FILE
EVENTS = ('push', 'schedule', 'workflow_run', 'workflow_dispatch')
SHA1 = re.compile(r'[0-9a-f]{40}\Z')
DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')
PAGE_SIZE = 25
APK_BUILD_WORKFLOWS = ('kernel-full-feature-matrix.yml', 'oplus-full-feature-matrix.yml')
APK_PREBUILD_RUNS = 4
APK_BUILD_RUN_PAGE_SIZE = 1
APK_BUILD_RUN_PAGES = 1
APK_ARTIFACT_PAGE_SIZE = 100
# A full batch can contain 512 targets with four kernel outputs each, plus
# manager APKs and checksums. Do not stop before an older APK in that listing.
APK_ARTIFACT_PAGES = 24


def _id(value):
    return type(value) is int and 0 < value < 2**63


def _workflow_id(reader, filename=WORKFLOW_FILE):
    workflow = reader.get('actions/workflows/' + filename)
    if (not isinstance(workflow, dict) or workflow.get('path') != '.github/workflows/' + filename
            or not _id(workflow.get('id'))):
        raise IdentityError('Could not confirm the manager APK producer workflow')
    return workflow['id']


def _matching_run(run, repository, branch, workflow_id, current_run, *, workflow_path=WORKFLOW_PATH):
    if (not isinstance(run, dict) or not _id(run.get('id')) or run['id'] == current_run
            or run.get('workflow_id') != workflow_id or run.get('path') != workflow_path
            or run.get('head_branch') != branch or run.get('event') not in EVENTS
            or run.get('status') != 'completed' or run.get('conclusion') != 'success'
            or not _id(run.get('run_attempt')) or not isinstance(run.get('head_sha'), str)
            or not SHA1.fullmatch(run['head_sha'])):
        return False
    identities = (run.get('repository'), run.get('head_repository'))
    return (all(isinstance(item, dict) and _id(item.get('id')) and isinstance(item.get('full_name'), str)
                and item['full_name'].casefold() == repository.casefold() for item in identities)
            and identities[0]['id'] == identities[1]['id'])


def _list(reader, path, key, query, *, max_pages, page_size=PAGE_SIZE):
    for page in range(1, max_pages + 1):
        suffix = path + '?' + urlencode({**query, 'per_page': page_size, 'page': page})
        document = reader.get(suffix)
        if not isinstance(document, dict) or not isinstance(rows := document.get(key), list) or len(rows) > page_size:
            raise IdentityError('Invalid manager prebuild workflow or artifact listing')
        yield from rows
        if len(rows) < page_size:
            break


def successful_runs(reader: GitHubReader, repository: str, branch: str, *, current_run: int | None = None):
    """List recent successful standalone runs on this repository's trusted branch."""
    repository, branch = validate_repository(repository), validate_ref(branch)
    workflow_id = _workflow_id(reader)
    rows = _list(reader, WORKFLOW_API + '/runs', 'workflow_runs', {'branch': branch, 'status': 'success'}, max_pages=2)
    for run in rows:
        if _matching_run(run, repository, branch, workflow_id, current_run):
            yield run


def manager_apk_runs(reader: GitHubReader, repository: str, branch: str, *, current_run: int | None = None):
    """Prefer standalone APKs, then recent successful GKI and OPlus builds.

    ``branch`` is the repository default branch supplied by the workflow. Keep
    ordinary build lookups bounded per exact producer workflow; state recovery
    deliberately continues to use only the standalone workflow helpers.
    """
    repository, branch = validate_repository(repository), validate_ref(branch)
    seen = set()
    for run in successful_runs(reader, repository, branch, current_run=current_run):
        seen.add(run['id'])
        yield run
        if len(seen) >= APK_PREBUILD_RUNS:
            break
    for filename in APK_BUILD_WORKFLOWS:
        workflow_id = _workflow_id(reader, filename)
        workflow_path = '.github/workflows/' + filename
        rows = _list(reader, 'actions/workflows/' + filename + '/runs', 'workflow_runs',
                     {'branch': branch, 'status': 'success'}, max_pages=APK_BUILD_RUN_PAGES,
                     page_size=APK_BUILD_RUN_PAGE_SIZE)
        for run in rows:
            if (_matching_run(run, repository, branch, workflow_id, current_run, workflow_path=workflow_path)
                    and run['id'] not in seen):
                seen.add(run['id'])
                yield run


def _matching_artifact(artifact, run):
    if (not isinstance(artifact, dict) or artifact.get('expired') is not False
            or not _id(artifact.get('id')) or not _id(artifact.get('size_in_bytes'))
            or not isinstance(artifact.get('name'), str)
            or not isinstance(artifact.get('digest'), str) or not DIGEST.fullmatch(artifact['digest'])):
        return False
    origin = artifact.get('workflow_run')
    return (isinstance(origin, dict) and origin.get('id') == run['id']
            and origin.get('head_sha') == run['head_sha'] and origin.get('head_branch') == run['head_branch']
            and origin.get('repository_id') == run['repository']['id']
            and origin.get('head_repository_id') == run['head_repository']['id'])


def run_artifacts(reader: GitHubReader, run: dict, *, max_pages=2, page_size=PAGE_SIZE):
    """List nonexpired artifacts tied to the already verified workflow run."""
    for artifact in _list(reader, f"actions/runs/{run['id']}/artifacts", 'artifacts', {},
                          max_pages=max_pages, page_size=page_size):
        if _matching_artifact(artifact, run):
            yield artifact


def named_artifacts(reader: GitHubReader, repository: str, branch: str, name: str, *, current_run: int | None = None):
    """Find exact-name artifacts without paging through successful no-op runs."""
    repository, branch = validate_repository(repository), validate_ref(branch)
    workflow_id = _workflow_id(reader)
    runs = {}
    for artifact in _list(reader, 'actions/artifacts', 'artifacts', {'name': name}, max_pages=2):
        if not isinstance(artifact, dict) or artifact.get('name') != name or artifact.get('expired') is not False:
            continue
        origin = artifact.get('workflow_run')
        if not isinstance(origin, dict) or not _id(run_id := origin.get('id')) or run_id == current_run:
            continue
        if run_id not in runs:
            run = reader.get(f'actions/runs/{run_id}')
            runs[run_id] = run if _matching_run(run, repository, branch, workflow_id, current_run) and run['id'] == run_id else None
        if (run := runs[run_id]) and _matching_artifact(artifact, run):
            yield run, artifact


def verified_artifact(reader: GitHubReader, run: dict, artifact: dict, *, limit: int) -> bytes:
    """Return original download bytes only when GitHub's provenance and digest match."""
    if not _matching_artifact(artifact, run) or not 0 < artifact['size_in_bytes'] <= limit:
        raise IdentityError('Manager prebuild artifact is too large or belongs to a different run')
    payload = reader.get(f"actions/artifacts/{artifact['id']}/zip", binary=True)
    if (not isinstance(payload, bytes) or len(payload) != artifact['size_in_bytes']
            or 'sha256:' + hashlib.sha256(payload).hexdigest() != artifact['digest']):
        raise IdentityError('Manager prebuild artifact bytes do not match the GitHub digest')
    return payload
