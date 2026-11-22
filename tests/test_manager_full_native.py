import json
from pathlib import Path
import shutil
import struct
import sys
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import test_manager_lkm as fixtures
import manager_full_native as native
import prepare_manager_lkm as lkm
from prepare_manager_lkm import locked_ddk


class FullNativeTests(unittest.TestCase):
    def test_container_drivers_use_linux_line_endings(self):
        for path in (ROOT / 'tools').glob('build_manager_*.sh'):
            self.assertNotIn(b'\r', path.read_bytes(), str(path))

    def setUp(self):
        self.fixture = fixtures.ManagerLkmTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.cleanup)
        self.f = self.fixture
        self.source = self.f.source
        (self.source / 'manager/build.gradle.kts').write_text('// Official root project\n')
        with (self.source / 'manager/app/build.gradle.kts').open('a', encoding='utf-8') as stream:
            stream.write('android { defaultConfig { ndk { abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64", "riscv64") } } }\n')
        (self.source / 'kernel/susfs').mkdir()
        (self.source / 'kernel/susfs/Makefile').write_text('obj-m += susfs_guard_lkm.o\n')
        self.f.git('add', 'manager', 'kernel/susfs')
        self.f.git('commit', '--amend', '--no-edit', '--quiet')
        self.f.reference = self.f.git('rev-parse', 'HEAD')
        self.addCleanup(mock.patch.stopall)
        mock.patch.dict('os.environ', {'KSU_VARIANT': 'SukiSU'}).start()
        self.kmi = 'android13-5.15'

    def extras(self):
        directory = self.f.artifacts / self.kmi / 'extras'
        directory.mkdir(parents=True)
        for arch, kind, name in native.extra_components(self.source, self.kmi):
            info = ('name=' + kind + '\0vermagic=' + locked_ddk(self.kmi)['kernel_release']
                    + ' SMP\0gki_extra_source_revision=' + self.f.reference + '\0').encode()
            fixture = self.f.module(self.kmi, machine=62 if arch == 'x86_64' else 183, modinfo=info)
            target = directory / arch / name
            target.parent.mkdir()
            target.write_bytes(fixture.read_bytes())
        native.record_extras(self.source, directory, self.kmi, self.f.identity_file,
                             self.f.reference, locked_ddk(self.kmi)['image'])
        return directory

    def test_frozen_official_abis_cannot_be_replaced_by_worktree_trimming(self):
        (self.source / 'manager/app/build.gradle.kts').write_text('abiFilters("arm64-v8a")')
        self.assertEqual(tuple(native.ABIS), native.official_abis(self.source))

    def test_publication_uses_arm64_only_for_the_official_phone_manager_splits(self):
        for variant in ('SukiSU', 'BakaSU'):
            with self.subTest(variant=variant):
                self.assertEqual(('arm64-v8a',), native.publication_abis(self.source, variant))
        for variant in ('KernelSU', 'KernelSU-Next', 'KowSU', 'FinaSU'):
            with self.subTest(variant=variant):
                self.assertEqual(tuple(native.ABIS), native.publication_abis(self.source, variant))
        # Publication must still validate the source declaration before selecting a split.
        with mock.patch.object(native, 'official_abis', side_effect=ValueError('changed upstream ABI')):
            with self.assertRaisesRegex(ValueError, 'changed upstream ABI'):
                native.publication_abis(self.source, 'SukiSU')

    def test_all_extra_components_are_checked_before_embedding(self):
        self.extras()
        native.stage_extras(self.source, self.f.artifacts, self.f.identity_file, self.f.reference, (self.kmi,))
        for arch, _, name in native.extra_components(self.source, self.kmi):
            self.assertTrue((self.source / 'userspace/ksud/bin' / arch / name).is_file())
        native.check_original_assets(self.source)

    def test_wrong_certificate_rejects_x86_module_before_any_asset_copy(self):
        directory = self.extras()
        identity = dict(self.f.identity, manager_cert_sha256='ab' * 32)
        self.f.identity_file.write_text(json.dumps(identity))
        with self.assertRaises(ValueError):
            native.stage_extras(self.source, self.f.artifacts, self.f.identity_file, self.f.reference, (self.kmi,))
        self.assertFalse((self.source / 'userspace/ksud/bin/x86_64').exists())

    def test_missing_guard_rejects_partial_native_output(self):
        directory = self.extras()
        (directory / 'aarch64' / (self.kmi + '_susfs_guard_lkm.ko')).unlink()
        with self.assertRaisesRegex(ValueError, 'Missing'):
            native.stage_extras(self.source, self.f.artifacts, self.f.identity_file, self.f.reference, (self.kmi,))
        self.assertFalse((self.source / 'userspace/ksud/bin/x86_64').exists())

    def published_cache_hit(self):
        """Restore, verify and publish real files, then remove the cache.

        A zip is the local file boundary standing in for the artifact service;
        both producer and consumer execute the production provenance verifiers.
        The ELF objects remain the existing structural test fixtures.
        """
        self.f.record(self.kmi)
        self.extras()
        pristine = self.f.root / 'pristine-consumer-source'
        shutil.copytree(self.source, pristine)
        service_cache = self.f.root / 'evictable-cache' / self.kmi
        shutil.copytree(self.f.artifacts / self.kmi, service_cache)
        restored = self.f.root / 'producer' / 'manager-lkm'
        shutil.copytree(service_cache, restored / self.kmi)
        # A producer cache hit has to pass both unchanged native checks before
        # publication, just like a freshly compiled module set.
        lkm.stage(self.source, restored / self.kmi, self.f.identity_file,
                  self.f.reference, self.kmi, self.f.root / 'producer-verification.json')
        native.stage_extras(self.source, restored, self.f.identity_file, self.f.reference, (self.kmi,))
        publication = self.f.root / 'published-module-artifact.zip'
        with zipfile.ZipFile(publication, 'w') as archive:
            for path in sorted((restored / self.kmi).rglob('*')):
                if path.is_file():
                    archive.write(path, path.relative_to(restored / self.kmi).as_posix())
        shutil.rmtree(service_cache.parent)
        shutil.rmtree(restored.parent)
        shutil.rmtree(self.f.artifacts)
        self.assertFalse(service_cache.exists())
        self.assertFalse(restored.exists())
        return pristine, publication

    def download_published_files(self, pristine, publication, label):
        source = self.f.root / (label + '-source')
        shutil.copytree(pristine, source)
        downloaded = self.f.root / label / 'manager-lkm'
        destination = downloaded / self.kmi
        destination.mkdir(parents=True)
        with zipfile.ZipFile(publication) as archive:
            archive.extractall(destination)
        identity = self.f.root / (label + '-identity.json')
        shutil.copyfile(self.f.identity_file, identity)
        return source, downloaded, identity

    def accept_published_files(self, source, downloaded, identity, label):
        result = lkm.stage(source, downloaded, identity, self.f.reference, self.kmi,
                           self.f.root / (label + '-verified.json'))
        extras = native.stage_extras(source, downloaded, identity, self.f.reference, (self.kmi,))
        return result, extras

    def test_published_cache_hit_survives_eviction_and_passes_original_consumer_verifiers(self):
        pristine, publication = self.published_cache_hit()
        source, downloaded, identity = self.download_published_files(pristine, publication, 'accepted')
        result, extras = self.accept_published_files(source, downloaded, identity, 'accepted')
        self.assertEqual([self.kmi], result['supported_kmis'])
        self.assertEqual(self.f.reference, result['ksu_ref'])
        self.assertEqual(self.f.identity['manager_cert_sha256'], result['manager_cert_sha256'])
        self.assertEqual(locked_ddk(self.kmi)['image'], result['modules'][0]['ddk_image'])
        self.assertEqual(1, len(extras))
        self.assertEqual(b'original busybox', (source / 'userspace/ksud/bin/aarch64/busybox').read_bytes())
        for relative in (self.kmi + '_kernelsu.ko', 'extras/x86_64/' + self.kmi + '_kernelsu.ko',
                         'extras/aarch64/' + self.kmi + '_susfs_guard_lkm.ko'):
            original = downloaded / self.kmi / relative
            arch = relative.split('/')[1] if relative.startswith('extras/') else 'aarch64'
            staged = source / 'userspace/ksud/bin' / arch / original.name
            self.assertEqual(original.read_bytes(), staged.read_bytes())

    def test_published_files_still_reject_tampering_wrong_certificate_or_incomplete_modules(self):
        pristine, publication = self.published_cache_hit()
        for change in ('module-bytes', 'certificate', 'missing-module', 'source-ref', 'ddk-image',
                       'kmi', 'extra-bytes', 'missing-extra'):
            with self.subTest(change=change):
                source, downloaded, identity = self.download_published_files(pristine, publication, change)
                module = downloaded / self.kmi / (self.kmi + '_kernelsu.ko')
                manifest = downloaded / self.kmi / 'module.json'
                extra = downloaded / self.kmi / 'extras/x86_64' / module.name
                if change == 'module-bytes':
                    module.write_bytes(module.read_bytes() + b'tampered')
                elif change == 'certificate':
                    identity.write_text(json.dumps({**self.f.identity, 'manager_cert_sha256': 'ab' * 32}))
                elif change == 'missing-module':
                    module.unlink()
                elif change in ('source-ref', 'ddk-image', 'kmi'):
                    document = json.loads(manifest.read_text())
                    field, value = {'source-ref': ('ksu_ref', 'f' * 40),
                                    'ddk-image': ('ddk_image', locked_ddk('android14-6.1')['image']),
                                    'kmi': ('kmi', 'android14-6.1')}[change]
                    document[field] = value
                    manifest.write_text(json.dumps(document))
                elif change == 'extra-bytes':
                    extra.write_bytes(extra.read_bytes() + b'tampered')
                else:
                    extra.unlink()
                with self.assertRaises(ValueError):
                    self.accept_published_files(source, downloaded, identity, change)
                # A rejected full component set is never accepted as a partial
                # x86 payload merely because its artifact download succeeded.
                self.assertFalse((source / 'userspace/ksud/bin/x86_64').exists())

    def apk(self, missing=None, *, abis=None):
        # Small structural ELF fixtures; these are never exported as binaries.
        path = self.f.root / 'fixture.apk'
        with zipfile.ZipFile(path, 'w') as archive:
            for abi, (arch, _, machine) in native.ABIS.items():
                if abi == missing or (abis is not None and abi not in abis):
                    continue
                raw = bytearray(b'\x7fELF\x02\x01\x01' + b'\0' * 57)
                if arch == 'arm':
                    raw[4] = 1
                struct.pack_into('<H', raw, 16, 3)
                struct.pack_into('<H', raw, 18, machine)
                archive.writestr('lib/' + abi + '/libkernelsu.so', raw)
                archive.writestr('lib/' + abi + '/libksud.so', raw + b'busybox\0')
        return path

    def test_full_apk_keeps_every_original_architecture(self):
        self.assertEqual(list(native.ABIS), native.verify_apk(self.source, self.apk())['abis'])
        with self.assertRaisesRegex(ValueError, 'architecture'):
            native.verify_apk(self.source, self.apk(missing='riscv64'))

    def test_explicit_arm64_split_is_verified_without_weakening_the_full_default(self):
        apk = self.apk(abis=('arm64-v8a',))
        with self.assertRaisesRegex(ValueError, 'architecture'):
            native.verify_apk(self.source, apk)
        verified = native.verify_apk(self.source, apk, expected_abis=('arm64-v8a',))
        self.assertEqual(['arm64-v8a'], verified['abis'])
        self.assertEqual(['arm64-v8a'], [row['abi'] for row in verified['native_components']])
        with self.assertRaisesRegex(ValueError, 'architecture'):
            native.verify_apk(self.source, self.apk(), expected_abis=('arm64-v8a',))

    def test_published_abi_selection_requires_a_nonempty_declared_unique_arm64_set(self):
        for abis in ((), ('x86_64',), ('arm64-v8a', 'arm64-v8a'), ('arm64-v8a', 'mips64')):
            with self.subTest(abis=abis), self.assertRaisesRegex(ValueError, 'declared'):
                native.verify_apk(self.source, self.apk(), expected_abis=abis)
        with mock.patch.object(native, 'official_abis', return_value=('arm64-v8a',)):
            with self.assertRaisesRegex(ValueError, 'declared'):
                native.verify_apk(self.source, self.apk(), expected_abis=('arm64-v8a', 'riscv64'))

    def test_replacing_official_busybox_is_rejected(self):
        (self.source / 'userspace/ksud/bin/aarch64/busybox').write_bytes(b'trimmed')
        with self.assertRaisesRegex(ValueError, 'removed or changed'):
            native.verify_apk(self.source, self.apk())


if __name__ == '__main__':
    unittest.main()
