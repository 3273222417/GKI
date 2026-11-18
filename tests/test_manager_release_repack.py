"""Release packing keeps all ABIs, APK content, and signing boundaries intact."""
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
            for abi in self.abis:
                archive.writestr('lib/' + abi + '/libksud.so', b'native-daemon')
        self.original = self.apk.read_bytes()
        self.upstream = types.SimpleNamespace(
            find_strip_tool=lambda: Path('llvm-strip'),
            find_ksud_binaries_by_arch=lambda profile, abis: self.daemons,
            repack_apk=lambda src, dst, abis, daemons, strip: shutil.copyfile(src, dst),
            assert_required_libs=lambda apk, abis: None)
        self.enter = lambda: (patch.object(builder, 'official_abis', return_value=self.abis),
                             patch.object(builder, 'verify_apk'),
                             patch.object(builder, 'upstream_repacker', return_value=self.upstream))

    def test_upstream_receives_full_official_abi_set_and_release_daemons(self):
        calls = []
        def repack(src, dst, abis, daemons, strip):
            calls.append((src, abis, daemons, strip))
            shutil.copyfile(src, dst)
        self.upstream.repack_apk = repack
        one, two, three = self.enter()
        with one, two, three:
            builder.repack_release(self.source, self.apk)
        self.assertEqual([(self.apk, list(self.abis), self.daemons, Path('llvm-strip'))], calls)
        self.assertEqual(self.original, self.apk.read_bytes())

    def test_missing_official_daemon_or_strip_tool_does_not_modify_input(self):
        for missing in ('daemon', 'strip'):
            with self.subTest(missing=missing):
                one, two, three = self.enter()
                if missing == 'daemon':
                    self.upstream.find_ksud_binaries_by_arch = lambda *_: {'arm64-v8a': self.daemons['arm64-v8a']}
                else:
                    self.upstream.find_strip_tool = lambda: None
                with one, two, three, self.assertRaises(ValueError):
                    builder.repack_release(self.source, self.apk)
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
                builder.repack_release(self.source, self.apk)
            self.assertEqual(self.original, self.apk.read_bytes())

    def test_repacker_must_be_the_unchanged_selected_source_blob(self):
        (self.source / 'repack_apk.py').write_text('changed repacker', encoding='utf-8')
        with patch.object(builder.subprocess, 'check_output', return_value=b'original repacker'):
            with self.assertRaisesRegex(ValueError, 'differs'):
                builder.upstream_repacker(self.source)


if __name__ == '__main__':
    unittest.main()
