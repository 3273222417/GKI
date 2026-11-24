#!/usr/bin/env python3
"""Recover a signed manager from retained Actions artifacts when its cache is gone."""
from __future__ import annotations

import argparse
import hashlib
import io
import os
from pathlib import Path
import re
import struct
import sys
import tempfile
import time
import zipfile
import zlib

from embedded_build_metadata import MAX_APK_BYTES, metadata_json, read_manager_apk
from manager_variants import MANAGERS, manager_source_package, valid_manager_apk_filename
from prebuilt_manager_history import (APK_ARTIFACT_PAGE_SIZE, APK_ARTIFACT_PAGES,
                                     manager_apk_runs, run_artifacts, verified_artifact)
from prepare_manager_lkm import native_version_code
from reusable_manager_apk import (CHANNELS, compact, manager_selection, positive,
                                  read_regular, recipe_hash, stage, workflow_consumer)
from wait_manager_identity import GitHubReader


INVALID_APK = (OSError, ValueError, RuntimeError, zipfile.BadZipFile, struct.error, zlib.error)
MAX_DOWNLOADS = 4
HISTORY_LIST_PAGES = 12
HISTORY_SECONDS = 8
HISTORY_REQUEST_SECONDS = 4


class HistoryExhausted(RuntimeError):
    pass


class HistoryReader:
    """Bound optional history work without delaying the normal cache-hit path."""
    def __init__(self, reader):
        self.reader = reader
        self.deadline = time.monotonic() + HISTORY_SECONDS
        self.pages = 0

    def get(self, suffix, *, binary=False):
        if time.monotonic() >= self.deadline:
            raise HistoryExhausted('Manager APK history time budget was exhausted')
        if '?' in suffix:
            if self.pages >= HISTORY_LIST_PAGES:
                raise HistoryExhausted('Manager APK history page budget was exhausted')
            self.pages += 1
        return self.reader.get(suffix, binary=binary)


def version_cache_key(selection: dict, version: int) -> str:
    if type(version) is not int or not 1 <= version <= 2100000000:
        raise ValueError('Invalid manager version for APK reuse')
    identity = {key: value for key, value in selection.items()
                if key not in {'ksu_branch', 'manager_recipe_sha256'}}
    identity['ksu_version_code'] = version
    return 'gki-manager-apk-version-v1-' + hashlib.sha256(compact(identity).encode('ascii')).hexdigest()


def stage_version(cache: Path, output: Path, *, consumer: dict, selection: dict, version: int | None) -> dict:
    if version is None:
        return stage(cache, output, consumer=consumer, selection=selection)
    if cache.resolve() != cache.absolute() or not cache.is_dir():
        raise ValueError('No reusable manager APK was restored')
    files = list(cache.iterdir())
    if len(files) != 1 or files[0].suffix != '.apk':
        raise ValueError('Expected exactly one original APK in the cache')
    path = files[0]
    metadata = read_manager_apk(read_regular(path, MAX_APK_BYTES), filename=path.name)
    if positive(metadata.get('ksu_version_code'), 2100000000) != version:
        raise ValueError('Signed manager APK version differs from the selected native source')
    # Reuse the original signed build at this version, keeping its recorded
    # recipe in the adoption receipt. The original stage still verifies source,
    # package, certificate, manifest, and the complete native build proof.
    original = {**selection, 'manager_recipe_sha256': metadata.get('manager_recipe_sha256')}
    return stage(cache, output, consumer=consumer, selection=original)


def artifact_apk(data: bytes, filename: str) -> bytes:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        if 'AndroidManifest.xml' in archive.namelist():
            return data
        entries = archive.infolist()
        if len(entries) != 1 or entries[0].filename != filename or not 0 < entries[0].file_size <= MAX_APK_BYTES:
            raise ValueError('Expected one original manager APK')
        return archive.read(entries[0])


def restore(reader, *, cache: Path, output: Path, consumer: dict, selection: dict, branch: str,
            version: int | None) -> dict:
    try:
        return stage_version(cache, output, consumer=consumer, selection=selection, version=version)
    except INVALID_APK:
        pass
    if version is None:
        return {}
    version_suffix = re.compile(rf'_{version}(?:-(?:arm64-v8a|universal))?-release\.apk\Z')
    downloads = 0
    reader = HistoryReader(reader)
    try:
        for run in manager_apk_runs(reader, consumer['repository'], branch, current_run=consumer['run_id']):
            for item in run_artifacts(reader, run, max_pages=APK_ARTIFACT_PAGES, page_size=APK_ARTIFACT_PAGE_SIZE):
                name = item['name']
                if (not valid_manager_apk_filename(name, selection['ksu_variant'], package=selection['package'])
                        or not version_suffix.search(name)):
                    continue
                if downloads >= MAX_DOWNLOADS:
                    return {}
                downloads += 1
                try:
                    payload = verified_artifact(reader, run, item, limit=MAX_APK_BYTES)
                    apk = artifact_apk(payload, name)
                    with tempfile.TemporaryDirectory(prefix='gki-apk-restore-') as temporary:
                        directory = Path(temporary)
                        (directory / name).write_bytes(apk)
                        result = stage_version(directory, output, consumer=consumer, selection=selection, version=version)
                    print(f"Recovered signed manager APK from run {run['id']}: {name}", file=sys.stderr)
                    return result
                except HistoryExhausted:
                    raise
                except INVALID_APK:
                    continue
    except HistoryExhausted as error:
        print(str(error) + '; building the selected source.', file=sys.stderr)
    return {}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--variant', required=True, choices=MANAGERS)
    parser.add_argument('--channel', required=True, choices=CHANNELS)
    parser.add_argument('--ksu-ref', required=True)
    parser.add_argument('--cert-size', required=True)
    parser.add_argument('--cert-sha256', required=True)
    parser.add_argument('--source-identity', required=True)
    parser.add_argument('--cache-dir', type=Path)
    parser.add_argument('--output-dir', type=Path)
    parser.add_argument('--source-dir', required=True, type=Path)
    parser.add_argument('--branch')
    parser.add_argument('--write-version-key', action='store_true')
    args = parser.parse_args(argv)
    if not args.write_version_key and (args.cache_dir is None or args.output_dir is None or args.branch is None):
        parser.error('--cache-dir, --output-dir and --branch are required for APK recovery')
    try:
        recipe = '0' * 64 if args.write_version_key else recipe_hash(Path('.'))
        identity = metadata_json(args.source_identity.encode('utf-8'))
        selection = manager_selection(args.variant, args.channel, args.ksu_ref, args.cert_size,
                                      args.cert_sha256, recipe, identity,
                                      package=manager_source_package(args.variant, args.source_dir))
        try:
            version = native_version_code(args.source_dir, identity['git_count'], variant=args.variant)
        except (OSError, ValueError):
            version = None
        if args.write_version_key:
            result = {'apk_version_cache_key': version_cache_key(selection, version)} if version is not None else {}
        else:
            consumer = workflow_consumer()
            reader = GitHubReader(consumer['repository'], request_timeout=HISTORY_REQUEST_SECONDS, attempts=1)
            result = restore(reader, cache=args.cache_dir, output=args.output_dir,
                             consumer=consumer, selection=selection, branch=args.branch, version=version)
    except INVALID_APK as error:
        print('Manager APK recovery unavailable: ' + str(error), file=sys.stderr)
        result = {}
    if not result and not args.write_version_key:
        print('No matching signed manager APK was found; building the selected source.', file=sys.stderr)
    if output := os.environ.get('GITHUB_OUTPUT'):
        with Path(output).open('a', encoding='utf-8', newline='\n') as stream:
            for key, value in result.items():
                stream.write(f'{key}={value}\n')
    else:
        print(compact(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
