"""Apply the frozen upstream release repacker before independent APK signing."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile

from manager_full_native import official_abis, verify_apk


def upstream_repacker(source: Path):
    path = source / 'repack_apk.py'
    original = subprocess.check_output(['git', '-C', str(source), 'show', 'HEAD:repack_apk.py'])
    if path.is_symlink() or not path.is_file() or path.read_bytes() != original:
        raise ValueError('The official release repacker differs from the selected source revision')
    spec = importlib.util.spec_from_file_location('_gki_official_release_repacker', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_contents(before: Path, after: Path) -> None:
    """Upstream may strip native ELF files; all other release content stays intact."""
    with zipfile.ZipFile(before) as original, zipfile.ZipFile(after) as repacked:
        if (set(original.namelist()) != set(repacked.namelist())
                or len(repacked.namelist()) != len(set(repacked.namelist()))
                or repacked.testzip() is not None):
            raise ValueError('Official repack removed or added an APK entry')
        for name in original.namelist():
            if name.startswith('lib/') and name.endswith('.so'):
                continue
            if original.read(name) != repacked.read(name):
                raise ValueError('Official repack changed non-native APK content: ' + name)


def repack_release(source: Path, apk: Path) -> None:
    source = source.resolve(strict=True)
    apk = apk.resolve(strict=True)
    release = source / 'manager/app/build/outputs/apk/release'
    if not apk.is_relative_to(release) or apk.suffix != '.apk':
        raise ValueError('Expected the selected source release APK')
    abis = official_abis(source)
    verify_apk(source, apk)
    upstream = upstream_repacker(source)
    strip = upstream.find_strip_tool()
    if strip is None:
        raise ValueError('Android NDK llvm-strip is required by the official release repack')
    daemons = upstream.find_ksud_binaries_by_arch('release', list(abis))
    if set(daemons) != set(abis) or any(not Path(path).is_file() for path in daemons.values()):
        raise ValueError('Official repack requires the same-source daemon for every official ABI')
    before = apk.stat().st_size
    with tempfile.TemporaryDirectory(prefix='gki-release-repack-', dir=apk.parent) as directory:
        result = Path(directory) / apk.name
        # This is the same function used by upstream's single/universal APK
        # release driver. Its signing CLI is intentionally outside this call;
        # the existing workflow aligns and signs the result independently.
        upstream.repack_apk(apk, result, list(abis), daemons, strip)
        upstream.assert_required_libs(result, list(abis))
        verify_contents(apk, result)
        verify_apk(source, result)
        shutil.copyfile(result, apk)
    print(f'Official release repack: {before} -> {apk.stat().st_size} bytes; ABIs={",".join(abis)}', flush=True)
