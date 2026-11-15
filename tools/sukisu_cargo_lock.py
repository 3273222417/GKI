#!/usr/bin/env python3
"""Prune stale SukiSU workspace lock entries without changing dependency pins."""
from pathlib import Path
import subprocess
import sys
import tomllib


def package_pins(document):
    return {(item['name'], item['version'], item.get('source'), item.get('checksum'))
            for item in document['package']}


def reconcile_sukisu_cargo_lock(source: Path, platform: str, *, environment=None) -> None:
    lock = source / 'Cargo.lock'
    if lock.is_symlink() or not lock.is_file():
        raise ValueError('Expected a regular SukiSU workspace Cargo.lock')
    original = lock.read_bytes()
    before = tomllib.loads(original.decode('utf-8'))
    try:
        subprocess.run(['cargo', 'metadata', '--format-version', '1', '--filter-platform', platform],
                       cwd=source, env=environment, check=True, stdout=subprocess.DEVNULL, timeout=300)
        current = lock.read_bytes()
        if current != original:
            after = tomllib.loads(current.decode('utf-8'))
            if after['version'] != before['version'] or not package_pins(after) <= package_pins(before):
                raise ValueError('SukiSU Cargo.lock requires an unpinned dependency or lock format change')
            print('Reconciled SukiSU Cargo.lock; all retained dependencies stay pinned.', flush=True)
    except Exception:
        lock.write_bytes(original)
        raise


if __name__ == '__main__':
    reconcile_sukisu_cargo_lock(Path(sys.argv[1]), sys.argv[2])
