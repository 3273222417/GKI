"""Release packing preserves official native splits and all non-native content."""
from pathlib import Path
import shutil
import tempfile
import types
import unittest
from unittest.mock import patch
import zipfile

import repack_manager_release as builder


class ManagerReleaseRepackTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.source = Path(temporary.name).resolve()
        self.apk = self.source / 'manager/app/build/outputs/apk/release/manager-release.apk'
        self.apk.parent.mkdir(parents=True)
        self.abis = ('arm64-v8a', 'armeabi-v7a', 'x86_64', 'riscv64')
        self.daemons = {}
        for abi in self.abis:
            path = self.source / abi
            path.write_bytes(b'native-daemon')
            self.daemons[abi] = path
        with zipfile.ZipFile(self.apk, 'w') as archive:
            archive.writestr('AndroidManifest.xml', b'original-manifest')
            archive.writestr('classes.dex', b'original-code')
            archive.writestr('classes2.dex', b'original-extra-code')
            archive.writestr('resources.arsc', b'original-resource-table')
            archive.writestr('res/layout/main.xml', b'original-layout')
            archive.writestr('assets/kpm/loader', b'original-embedded-asset')
            archive.writestr('assets/lib/x86_64/retained.bin', b'not-an-apk-native-library')
            archive.writestr('META-INF/version-control-info.textproto', b'original-provenance')
            for abi in self.abis:
                archive.writestr('lib/' + abi + '/libksud.so', b'native-daemon')
                archive.writestr('lib/' + abi + '/libkernelsu.so', b'original-jni')
                archive.writestr('lib/' + abi + '/libadbroot.so', b'original-extra-jni')
                archive.writestr('lib/' + abi + '/native-data.bin', b'original-native-sidecar')
        self.original = self.apk.read_bytes()
        self.upstream = types.SimpleNamespace(
            find_strip_tool=lambda: Path('llvm-strip'),
            find_ksud_binaries_by_arch=lambda profile, abis: {abi: self.daemons[abi] for abi in abis},
            repack_apk=self.repack,
            assert_required_libs=lambda apk, abis: None)
        self.enter = lambda abis=None: (patch.object(builder, 'publication_abis', return_value=abis or self.abis),
                             patch.object(builder, 'verify_apk'),
                             patch.object(builder, 'upstream_repacker', return_value=self.upstream))

    @staticmethod
    def repack(src, dst, abis, *_):
        with zipfile.ZipFile(src) as before, zipfile.ZipFile(dst, 'w') as after:
            for info in before.infolist():
                if info.filename.startswith('lib/') and info.filename.count('/') >= 2:
                    if info.filename.split('/')[1] not in abis:
                        continue
                after.writestr(info, before.read(info.filename))

    def test_upstream_receives_full_official_abi_set_and_release_daemons(self):
        calls = []
        def repack(src, dst, abis, daemons, strip):
            calls.append((src, abis, daemons, strip))
            shutil.copyfile(src, dst)
        self.upstream.repack_apk = repack
        one, two, three = self.enter()
        with one, two as verify, three:
            published = builder.repack_release(self.source, self.apk, 'KernelSU')
        self.assertEqual([(self.apk, list(self.abis), self.daemons, Path('llvm-strip'))], calls)
        self.assertEqual(self.apk, published)
        self.assertEqual(self.original, self.apk.read_bytes())
        self.assertEqual((self.source, self.apk), verify.call_args_list[0].args)
        self.assertEqual({}, verify.call_args_list[0].kwargs)
        self.assertEqual({'expected_abis': self.abis}, verify.call_args_list[1].kwargs)

    def test_phone_managers_publish_the_official_arm64_split_and_keep_the_full_input(self):
        for variant in ('SukiSU', 'BakaSU'):
            with self.subTest(variant=variant):
                one, two, three = self.enter(('arm64-v8a',))
                with one as selection, two as verify, three:
                    published = builder.repack_release(self.source, self.apk, variant)
                self.assertEqual(self.apk.with_name('manager-arm64-v8a-release.apk'), published)
                selection.assert_called_once_with(self.source, variant)
                self.assertEqual({'expected_abis': ('arm64-v8a',)}, verify.call_args_list[1].kwargs)
                self.assertEqual(self.original, self.apk.read_bytes())
                with zipfile.ZipFile(self.apk) as before, zipfile.ZipFile(published) as after:
                    retained = {name for name in before.namelist() if not name.startswith('lib/')
                                or name.startswith('lib/arm64-v8a/')}
                    self.assertEqual(retained, set(after.namelist()))
                    for name in retained:
                        self.assertEqual(before.read(name), after.read(name), name)

    def test_arm64_filename_replaces_universal_and_does_not_repeat_existing_abi(self):
        for filename, expected in (
                ('BakaSU_v4_35252-universal-release-unsigned.apk', 'BakaSU_v4_35252-arm64-v8a-release-unsigned.apk'),
                ('SukiSU_Nova_v3_30000-release-unsigned.apk', 'SukiSU_Nova_v3_30000-arm64-v8a-release-unsigned.apk'),
                ('BakaSU_v4_35252-arm64-v8a-release.apk', 'BakaSU_v4_35252-arm64-v8a-release.apk')):
            with self.subTest(filename=filename):
                self.assertEqual(Path(expected), builder.split_filename(Path(filename), ('arm64-v8a',), 'BakaSU'))
        with self.assertRaisesRegex(ValueError, 'filename'):
            builder.split_filename(Path('manager.apk'), ('arm64-v8a',), 'SukiSU')
        with self.assertRaisesRegex(ValueError, 'ARM64'):
            builder.split_filename(Path('manager-release.apk'), self.abis, 'SukiSU')

    def test_arm64_repack_may_strip_elf_but_cannot_delete_native_components_or_change_other_content(self):
        for damage in ('drop-code', 'change-resource', 'change-asset', 'drop-native',
                       'change-sidecar', 'add-entry', 'retain-other-abi'):
            def repack(src, dst, abis, *_):
                self.repack(src, dst, abis)
                with zipfile.ZipFile(dst) as archive:
                    contents = {name: archive.read(name) for name in archive.namelist()}
                if damage == 'drop-code':
                    del contents['classes2.dex']
                elif damage == 'change-resource':
                    contents['resources.arsc'] = b'changed'
                elif damage == 'change-asset':
                    contents['assets/kpm/loader'] = b'changed'
                elif damage == 'drop-native':
                    del contents['lib/arm64-v8a/libadbroot.so']
                elif damage == 'change-sidecar':
                    contents['lib/arm64-v8a/native-data.bin'] = b'changed'
                elif damage == 'add-entry':
                    contents['unexpected.txt'] = b'added'
                else:
                    contents['lib/x86_64/libksud.so'] = b'retained'
                with zipfile.ZipFile(dst, 'w') as archive:
                    for name, raw in contents.items():
                        archive.writestr(name, raw)
            self.upstream.repack_apk = repack
            one, two, three = self.enter(('arm64-v8a',))
            with self.subTest(damage=damage), one, two, three, self.assertRaises(ValueError):
                builder.repack_release(self.source, self.apk, 'SukiSU')
            self.assertEqual(self.original, self.apk.read_bytes())
            self.assertFalse(self.apk.with_name('manager-arm64-v8a-release.apk').exists())

    def test_only_native_elf_bytes_may_change_during_official_stripping(self):
        def repack(src, dst, abis, *_):
            self.repack(src, dst, abis)
            with zipfile.ZipFile(dst) as archive:
                contents = {name: archive.read(name) for name in archive.namelist()}
            with zipfile.ZipFile(dst, 'w') as archive:
                for name, raw in contents.items():
                    archive.writestr(name, b'stripped-elf' if name.startswith('lib/') and name.endswith('.so') else raw)
        self.upstream.repack_apk = repack
        one, two, three = self.enter(('arm64-v8a',))
        with one, two, three:
            published = builder.repack_release(self.source, self.apk, 'SukiSU')
        with zipfile.ZipFile(published) as archive:
            self.assertEqual(b'stripped-elf', archive.read('lib/arm64-v8a/libksud.so'))
            self.assertEqual(b'original-native-sidecar', archive.read('lib/arm64-v8a/native-data.bin'))

    def test_missing_official_daemon_or_strip_tool_does_not_modify_input(self):
        for missing in ('daemon', 'strip'):
            with self.subTest(missing=missing):
                one, two, three = self.enter()
                self.upstream.find_ksud_binaries_by_arch = lambda profile, abis: {abi: self.daemons[abi] for abi in abis}
                self.upstream.find_strip_tool = lambda: Path('llvm-strip')
                if missing == 'daemon':
                    self.upstream.find_ksud_binaries_by_arch = lambda *_: {'arm64-v8a': self.daemons['arm64-v8a']}
                else:
                    self.upstream.find_strip_tool = lambda: None
                with one, two, three, self.assertRaises(ValueError):
                    builder.repack_release(self.source, self.apk, 'KernelSU')
                self.assertEqual(self.original, self.apk.read_bytes())

    def test_failed_packaging_cannot_replace_the_original_apk(self):
        for damage in ('drop', 'change'):
            def repack(src, dst, *_):
                with zipfile.ZipFile(src) as before, zipfile.ZipFile(dst, 'w') as after:
                    for name in before.namelist():
                        if damage == 'drop' and name.startswith('lib/riscv64/'):
                            continue
                        after.writestr(name, b'changed-code' if name == 'classes.dex' and damage == 'change' else before.read(name))
            self.upstream.repack_apk = repack
            one, two, three = self.enter()
            with self.subTest(damage=damage), one, two, three, self.assertRaises(ValueError):
                builder.repack_release(self.source, self.apk, 'KernelSU')
            self.assertEqual(self.original, self.apk.read_bytes())

    def test_repacker_must_be_the_unchanged_selected_source_blob(self):
        (self.source / 'repack_apk.py').write_text('changed repacker', encoding='utf-8')
        with patch.object(builder.subprocess, 'check_output', return_value=b'original repacker'):
            with self.assertRaisesRegex(ValueError, 'differs'):
                builder.upstream_repacker(self.source)


if __name__ == '__main__':
    unittest.main()
