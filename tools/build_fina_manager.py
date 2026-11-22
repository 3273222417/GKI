"""Build FinaSU through its own full native packaging driver."""
from __future__ import annotations

import argparse
from collections import deque
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import struct
import subprocess
import tempfile
import time
import zipfile

from apk_manifest import manifest_identity
from manager_lkm_jobs import KMIS
from manager_variants import manager_profile, valid_manager_apk_filename
from prepare_additional_gradle import prepare
from sign_sukisu_manager import redact
from manager_full_native import official_abis, verify_apk
from snapshot_ksu_source import git

BUILD_ALIAS = 'gki-fina-build-only'
GRADLE_RETRY_DELAYS = (30, 60)
DEPENDENCY_HOSTS = (r'(?:repo\.maven\.apache\.org|repo1\.maven\.org|plugins\.gradle\.org|'
                    r'dl\.google\.com|maven\.google\.com)')


def transient_gradle_download(output: str) -> bool:
    """Only retry an explicit temporary dependency error in this failure block."""
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', output)
    sections = text.split('* What went wrong:')
    # Multiple exceptions can mix a download outage with a real build error.
    if len(sections) != 2:
        return False
    failure = sections[1].split('* Try:', 1)[0]
    if not re.search(r'Could not (?:resolve|download)\b', failure):
        return False
    if re.search(r'(?im)\b(?:checksum|verification failed|PKIX|certificate|keystore|signing|'
                 r'compilation (?:error|failed)|unresolved reference|cannot find symbol)\b|'
                 r'^\s*(?:e:|error:)', failure):
        return False
    codes = re.findall(r'Received status code ([0-9]{3}) from server', failure)
    if not codes or any(code not in ('408', '429', '500', '502', '503', '504') for code in codes):
        return False
    return bool(re.search(r'Could not (?:GET|HEAD) [\'\"]https://' + DEPENDENCY_HOSTS
                          + r'/[^\'\"\r\n]+[\'\"][^\r\n]*\r?\n[^\r\n]*'
                            r'Received status code (?:408|429|500|502|503|504) from server', failure))


def run_stage(arguments: list[str], source: Path, environment: dict, password: str,
              *, retry_gradle: bool = False) -> None:
    """Keep a successful stage intact; retry only its transient Gradle fetch."""
    for attempt in range(len(GRADLE_RETRY_DELAYS) + 1):
        tail = deque(maxlen=128)
        with subprocess.Popen(arguments, cwd=source, env=environment, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace') as process:
            for line in process.stdout:
                safe = redact(line.rstrip(), (password,))
                print(safe, flush=True)
                tail.append(safe[-4096:])
            status = process.wait()
        if status == 0:
            return
        if (not retry_gradle or attempt == len(GRADLE_RETRY_DELAYS)
                or not transient_gradle_download('\n'.join(tail))):
            raise ValueError('FinaSU canonical native build/packaging failed')
        delay = GRADLE_RETRY_DELAYS[attempt]
        print(f'FinaSU Gradle dependency download temporarily unavailable; retrying the same stage '
              f'in {delay}s ({attempt + 2}/3)', flush=True)
        time.sleep(delay)


def payload_steps(source: Path) -> list[str]:
    """Follow the selected official driver, including newly added engines."""
    driver = git(source, 'show', 'HEAD:build.sh')
    function = bool(re.search(r'^build_folkzygisk\(\)\s*\{', driver, re.M))
    command = bool(re.search(r'^\s*folkzygisk\)\s*build_folkzygisk\s*;;', driver, re.M))
    if function != command:
        raise ValueError('Review the changed official FinaSU FolkZygisk build entry point')
    return ['nomount', 'sui'] + (['folkzygisk'] if command else []) + ['apk']


def generate_build_key(key: Path, password: str, environment: dict) -> None:
    """The canonical repacker needs a key; never give it the release key."""
    keytool = shutil.which('keytool')
    if not keytool:
        raise ValueError('Java keytool is required for the disposable FinaSU build key')
    result = subprocess.run([keytool, '-genkeypair', '-storetype', 'PKCS12',
        '-keystore', str(key), '-alias', BUILD_ALIAS, '-keyalg', 'RSA', '-keysize', '2048',
        '-dname', 'CN=Disposable FinaSU build key', '-validity', '1', '-noprompt',
        '-storepass:env', 'GKI_FINA_BUILD_PASSWORD', '-keypass:env', 'GKI_FINA_BUILD_PASSWORD'],
        env={**environment, 'GKI_FINA_BUILD_PASSWORD': password}, capture_output=True, timeout=90)
    if result.returncode or not key.is_file():
        raise ValueError('Cannot generate the disposable FinaSU build key')
    key.chmod(0o600)


def build(source: Path, output: Path):
    source = source.resolve(strict=True)
    output.mkdir(parents=True, exist_ok=True)
    output = output.resolve()
    prepare(source, 'FinaSU')
    # Build the vendored engines through their native entry points as well;
    # an APK containing the page alone would silently lose FinaSU features.
    environment = {**{name: value for name, value in os.environ.items()
        if name not in ('SUKISU_APK_KEYSTORE', 'SUKISU_APK_PASSWORD')
        and not name.startswith('ORG_GRADLE_PROJECT_KEY')},
                   'ABIS': ' '.join(official_abis(source)), 'KMIS': ' '.join(KMIS),
                   'CARGO_TARGET_DIR': str(source / 'target'),
                   'OUT_DIR': str(output / 'native-fina'), 'APP_BUILD_TYPE': 'release',
                   'KSUD_BUILD_TYPE': 'release', 'KSU_PACKAGE_NAME': manager_profile('FinaSU')['package']}
    with tempfile.TemporaryDirectory(prefix='gki-fina-signing-', dir=os.environ.get('RUNNER_TEMP')) as directory:
        private = Path(directory)
        key = private / 'signing.jks'
        # The canonical repacker passes this as a separate argparse value.
        # URL-safe randomness can begin with '-' and be read as an option.
        password = secrets.token_hex(32)
        generate_build_key(key, password, environment)
        properties = private / 'keystore.properties'
        properties.write_text('\n'.join(name + '=' + shlex.quote(value) for name, value in {
            'KEYSTORE_FILE': str(key), 'KEYSTORE_PASSWORD': password, 'KEY_ALIAS': BUILD_ALIAS,
            'KEY_PASSWORD': password}.items()) + '\n', encoding='utf-8')
        properties.chmod(0o600)
        environment['KEYSTORE_PROPS'] = str(properties)
        # Paired, certificate-checked KernelSU LKMs are staged by the existing
        # eight-KMI job. Preserve them; build the remaining native dependencies.
        commands = [(['bash', 'build.sh', step], step in ('sui', 'apk'))
                    for step in payload_steps(source)] + [
            (['bash', str(Path(__file__).with_name('build_manager_native.sh')), str(source)], False),
            (['bash', 'build.sh', 'repack'], False),
        ]
        for arguments, retry_gradle in commands:
            run_stage(arguments, source, environment, password, retry_gradle=retry_gradle)
    apks = list((output / 'native-fina').rglob('*.apk'))
    if len(apks) != 1 or apks[0].is_symlink():
        raise ValueError('Expected exactly one canonically repacked full-ABI FinaSU APK')
    apk = apks[0]
    with zipfile.ZipFile(apk) as archive:
        identity = manifest_identity(archive.read('AndroidManifest.xml'))
        names = archive.namelist()
        abis = {name.split('/')[1] for name in names if name.startswith('lib/') and len(name.split('/')) >= 3}
        if abis != set(official_abis(source)) or archive.testzip() is not None:
            raise ValueError('FinaSU APK is missing an official architecture')
        daemon = archive.read('lib/arm64-v8a/libksud.so')
        if (len(daemon) < 64 or daemon[:7] != b'\x7fELF\x02\x01\x01'
                or struct.unpack_from('<H', daemon, 18)[0] != 183):
            raise ValueError('The canonically repacked FinaSU daemon is not ARM64')
        if any((kmi + '_kernelsu.ko').encode() not in daemon for kmi in KMIS):
            raise ValueError('FinaSU is missing paired native KMI modules')
    verify_apk(source, apk)
    if identity['package'] != manager_profile('FinaSU')['package']:
        raise ValueError('FinaSU package differs from the official application ID')
    final_name = apk.name.removesuffix('-unsigned.apk') + '.apk' if apk.name.endswith('-unsigned.apk') else apk.name
    if not valid_manager_apk_filename(final_name, 'FinaSU'):
        raise ValueError('Unexpected canonical FinaSU release filename')
    metadata = {'source_apk_filename': apk.name, 'apk_filename': final_name,
                'manager_package': identity['package'], 'manager_version_name': identity['version_name'],
                'manager_version_code': identity['version_code']}
    shutil.copyfile(apk, output / 'manager-unsigned.apk')
    (output / 'manager-build-metadata.json').write_text(json.dumps(metadata, sort_keys=True) + '\n', encoding='utf-8')
    if os.environ.get('GITHUB_OUTPUT'):
        with Path(os.environ['GITHUB_OUTPUT']).open('a', encoding='utf-8') as stream:
            for name, value in metadata.items():
                stream.write(f'{name}={value}\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    build(args.source, args.output)
