"""Apply the frozen upstream release repacker before independent APK signing."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import zipfile

from manager_full_native import publication_abis, verify_apk


def upstream_repacker(source: Path):
    path = source / 'repack_apk.py'
    original = subprocess.check_output(['git', '-C', str(source), 'show', 'HEAD:repack_apk.py'])
    if path.is_symlink() or not path.is_file() or path.read_bytes() != original:
        raise ValueError('The official release repacker differs from the selected source revision')
    spec = importlib.util.spec_from_file_location('_gki_official_release_repacker', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_contents(before: Path, after: Path, abis: tuple[str, ...]) -> None:
    """Upstream may strip native ELF files; all other release content stays intact."""
    with zipfile.ZipFile(before) as original, zipfile.ZipFile(after) as repacked:
        retained = {name for name in original.namelist()
                    if not name.startswith('lib/') or name.count('/') < 2 or name.split('/')[1] in abis}
        if (retained != set(repacked.namelist())
                or len(original.namelist()) != len(set(original.namelist()))
                or len(repacked.namelist()) != len(set(repacked.namelist()))
                or repacked.testzip() is not None):
            raise ValueError('Official repack removed or added an APK entry')
        for name in retained:
            if name.startswith('lib/') and name.endswith('.so'):
                continue
            if original.read(name) != repacked.read(name):
                raise ValueError('Official repack changed non-native APK content: ' + name)


def split_filename(apk: Path, abis: tuple[str, ...], variant: str) -> Path:
    if variant not in ('SukiSU', 'BakaSU'):
        return apk
    if abis != ('arm64-v8a',):
        raise ValueError('Expected the official ARM64 release split')
    name, count = re.subn(r'(?:-universal|-arm64-v8a)?(-release(?:-unsigned)?\.apk)$',
                          r'-arm64-v8a\1', apk.name)
    if count != 1:
        raise ValueError('Expected an official release APK filename for the ARM64 split')
    return apk.with_name(name)


def repack_release(source: Path, apk: Path, variant: str) -> Path:
    source = source.resolve(strict=True)
    apk = apk.resolve(strict=True)
    release = source / 'manager/app/build/outputs/apk/release'
    if not apk.is_relative_to(release) or apk.suffix != '.apk':
        raise ValueError('Expected the selected source release APK')
    abis = publication_abis(source, variant)
    verify_apk(source, apk)
    target = split_filename(apk, abis, variant)
    if target.is_symlink():
        raise ValueError('Refusing a linked published APK destination')
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
        verify_contents(apk, result, abis)
        verify_apk(source, result, expected_abis=abis)
        shutil.copyfile(result, target)
    print(f'Official release repack: {before} -> {target.stat().st_size} bytes; ABIs={",".join(abis)}', flush=True)
    return target
