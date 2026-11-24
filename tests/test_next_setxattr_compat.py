"""Replay the native Next inode-label update through the real reviewed patch."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from next_setxattr_compat import (BASE_SHA256, NATIVE_SHA256, PATH, native_update, resolve_setxattr)
from oplus_compat import function_text
from susfs_setprocattr_compat import resolve_setprocattr


@unittest.skipUnless(shutil.which('git'), 'Git is required for the actual forward/reverse port')
class NativeInodeLabelPortTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='next-inode-port-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        self.file = self.source / PATH
        self.file.parent.mkdir(parents=True)
        fixture = ROOT / 'tests/fixtures/next-setxattr'
        raw = (fixture / 'selinux_hide.c').read_bytes()
        provenance = json.loads((fixture / 'provenance.json').read_text())
        self.assertEqual(NATIVE_SHA256, provenance['sha256'])
        self.assertEqual(NATIVE_SHA256, hashlib.sha256(raw).hexdigest())
        self.official = raw.decode()
        self.file.write_bytes(raw)
        self.git('init')
        self.git('config', 'core.autocrlf', 'false')
        self.git('config', 'merge.conflictStyle', 'diff3')
        self.git('config', 'user.name', 'Fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.git('add', '--', PATH)
        self.git('commit', '-m', 'Pinned official inode-label source')
        patches = ROOT / 'tools/patches'
        base = (patches / 'next-susfs23-base' / (BASE_SHA256 + '.source')).read_bytes()
        self.git('hash-object', '-w', '--stdin', input=base)
        original = (patches / 'next-susfs23.patch').read_text(encoding='utf-8')
        begin = original.index('diff --git a/' + PATH + ' b/' + PATH + '\n')
        end = original.index('\ndiff --git ', begin + 1)
        self.patch = self.root / 'reviewed.patch'
        self.patch.write_text(original[begin:end] + '\n', encoding='utf-8', newline='\n')

    def git(self, *arguments, input=None, success=True):
        result = subprocess.run(['git', '-C', str(self.source), *arguments], input=input,
                                capture_output=True, timeout=30)
        if success:
            self.assertEqual(0, result.returncode, result.stderr.decode(errors='replace'))
        return result

    def apply(self, *, reverse=False):
        arguments = ['apply', '--3way', str(self.patch)]
        if reverse:
            arguments.insert(1, '--reverse')
        result = self.git(*arguments, success=False)
        self.assertEqual(1, result.returncode)
        self.assertIn(b'<<<<<<<', self.file.read_bytes())

    def test_complete_native_checks_survive_forward_and_exact_reverse(self):
        self.apply()
        self.assertTrue(resolve_setprocattr(self.source))
        ported = self.file.read_text(encoding='utf-8')
        _, helper = native_update(self.official)
        self.assertIn(helper.replace('backup_rc = security_context_to_sid_with_policy(',
                                    'backup_rc = __security_context_to_sid_with_policy('), ported)
        for callback in ('security_context_to_sid_live', 'string_to_context_struct'):
            self.assertEqual(function_text(self.official, callback), function_text(ported, callback))
        enable = function_text(ported, 'ksu_selinux_hide_enable')
        self.assertIn('ret = selinux_hide_init_setxattr();', enable)
        self.assertIn('ret = ksu_lsm_hook(&selinux_inode_setxattr_hook);', enable)
        self.assertIn('unhook:\n    ksu_selinux_hide_unhook();', enable)
        self.assertLess(enable.index('ksu_selinux_hide_keep_backup = true;'),
                        enable.index('ret = ksu_lsm_hook(&selinux_inode_setxattr_hook);'))
        unhook = function_text(ported, 'ksu_selinux_hide_unhook')
        self.assertLess(unhook.index('ksu_lsm_unhook(&selinux_inode_setxattr_hook);'),
                        unhook.index('ksu_samsung_device_detected()'))
        self.assertIn('if (!ksu_selinux_hide_keep_backup && backup_sepolicy)', ported)
        self.apply(reverse=True)
        self.assertTrue(resolve_setprocattr(self.source, reverse=True))
        self.assertEqual(self.official, self.file.read_text(encoding='utf-8'))
        self.git('diff', '--quiet', 'HEAD', '--', PATH)

    def test_unreviewed_original_and_mutated_worktree_are_rejected(self):
        self.apply()
        conflict = self.file.read_text(encoding='utf-8')
        self.assertIsNone(resolve_setxattr(self.source, conflict, self.official + '\n', reverse=False))
        self.file.write_text(conflict + '/* unrelated edit */\n', encoding='utf-8', newline='\n')
        self.assertFalse(resolve_setprocattr(self.source))

    def test_reverse_rejects_changed_registered_hook_or_permission_checks(self):
        for before, after in (('CAP_MAC_ADMIN', 'CAP_SYS_ADMIN'),
                              ('ret = ksu_lsm_hook(&selinux_inode_setxattr_hook);', 'ret = 0;')):
            with self.subTest(before=before):
                self.git('reset', '--hard', 'HEAD')
                self.apply()
                self.assertTrue(resolve_setprocattr(self.source))
                ported = self.file.read_text(encoding='utf-8').replace(before, after, 1)
                self.file.write_text(ported, encoding='utf-8', newline='\n')
                self.git('add', '--', PATH)
                self.apply(reverse=True)
                self.assertFalse(resolve_setprocattr(self.source, reverse=True))


if __name__ == '__main__':
    unittest.main()
