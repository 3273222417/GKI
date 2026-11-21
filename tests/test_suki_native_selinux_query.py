import shutil
import subprocess
import sys
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import suki_baka_susfs24 as compat

FIXTURES = ROOT / 'tests/fixtures/suki-native-selinux-query'
ULTRA = (FIXTURES / 'ultra-645ef986.c').read_text('utf-8')
NOVA_HELPER = (FIXTURES / 'nova-c60f21b9-context-helper.c').read_text('utf-8').rstrip()


def direct_port(native):
    """Only the callback changes present in the reviewed SUSFS port."""
    result = native
    for kind in ('context', 'access'):
        result = result.replace('static ssize_t my_write_' + kind + '(', 'ssize_t my_write_' + kind + '(')
        result = result.replace('    // apply to all app uids\n'
                                '    if (likely(current_uid().val < 10000)) {\n'
                                '        return orig_' + kind + '_write(file, buf, size);\n'
                                '    }\n', '')
    return result


class NativeSelinuxQueryTests(unittest.TestCase):
    def setUp(self):
        self.root = ROOT / 'tests' / ('.native-selinux-query-' + uuid.uuid4().hex)
        (self.root / 'kernel/feature').mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.root)
        (self.root / 'kernel/Kbuild').write_text('kernelsu-objs += feature/selinux_hide.o\n', encoding='utf-8')

    def verify(self, current, native=ULTRA):
        receipt = subprocess.CompletedProcess([], 0, native, '')
        with patch.object(compat, 'source_git', return_value=receipt):
            compat.verify_native_selinux_query(self.root, current)

    def test_actual_ultra_and_nova_native_providers_pass_without_modification(self):
        helper = compat.query_implementation(ULTRA, 'security_context_to_sid_with_policy', is_static=True)
        nova = ULTRA.replace(helper, NOVA_HELPER)
        for native in (ULTRA, nova):
            with self.subTest(nova=native == nova):
                current = direct_port(native)
                self.verify(current, native)
                self.verify(current, native)
                self.assertNotIn('orig_access_write', current)
                self.assertNotIn('orig_context_write', current)
                self.assertIn('backup_sepolicy', current)

    def test_capability_is_hidden_builtin_only_and_idempotent(self):
        original = 'config KSU_SUSFS\n\tbool\n'
        updated = compat.configure(original, modern=True, native_query=True)
        self.assertIn('config KSU_SUSFS_NATIVE_SELINUX_QUERY\n\tbool\n'
                      '\tdepends on KSU=y && KSU_SUSFS\n\tdefault y\n', updated)
        self.assertEqual(updated, compat.configure(updated, modern=True, native_query=True))
        self.assertNotIn(compat.NATIVE_QUERY, compat.configure(original, modern=True))
        with self.assertRaisesRegex(ValueError, 'existing SUSFS configuration'):
            compat.configure(updated, modern=True, native_query=False)
        with self.assertRaisesRegex(ValueError, 'exact hidden builtin-only configuration'):
            compat.configure(updated + '\tbool "Expose native queries"\n', modern=True, native_query=True)

    def test_missing_static_conditional_or_changed_declaration_fails_closed(self):
        current = direct_port(ULTRA)
        callback = compat.query_implementation(current, 'my_write_access', is_static=False)
        mutations = [
            current.replace(callback, ''),
            current.replace('ssize_t my_write_access(', 'static ssize_t my_write_access('),
            current.replace('ssize_t my_write_access(', 'int my_write_access('),
            current.replace('char *buf, size_t size)', 'const char *buf, size_t size)', 1),
            current.replace(callback, '#if 0\n' + callback + '\n#endif'),
            current + '\n#define my_write_access other_provider\n',
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutations.index(mutation)):
                with self.assertRaises(ValueError):
                    self.verify(mutation)

    def test_permission_backup_error_and_return_protocol_changes_fail_closed(self):
        current = direct_port(ULTRA)
        mutations = [
            current.replace('ksu_avc_has_perm_compat(current_sid(), SECINITSID_SECURITY, SECCLASS_SECURITY, '
                            'SECURITY__COMPUTE_AV, NULL)', '0'),
            current.replace('backup_sepolicy, scon', 'selinux_state.policy, scon'),
            current.replace('    if (length)\n        goto out;', '', 1),
            current.replace('return length;', 'return 0;', 1),
            current.replace('"%x %x %x %x %u %x"', '"%x %x %x %x %x"'),
            current.replace('security_compute_av_user_with_policy(backup_sepolicy, ssid, tsid, tclass, &avd);', ''),
            current.replace('avd.allowed, 0xffffffff, avd.auditallow', '0xffffffff, 0xffffffff, avd.auditallow'),
            current.replace('#define ksu_avc_has_perm_compat(...) avc_has_perm(__VA_ARGS__)',
                            '#define ksu_avc_has_perm_compat(...) 0'),
            current.replace('    return length;', '    return orig_access_write(file, buf, size);', 1),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutations.index(mutation)):
                with self.assertRaises(ValueError):
                    self.verify(mutation)

    def test_unsafe_callback_does_not_gain_trust_from_matching_head(self):
        native = ULTRA.replace('return length;', 'return 0;', 1)
        with self.assertRaisesRegex(ValueError, 'permissions, backup policy and return protocol'):
            self.verify(direct_port(native), native)

    def test_helpers_are_selected_source_bound_without_revision_whitelist(self):
        current = direct_port(ULTRA)
        helper = compat.query_implementation(current, 'security_sid_to_context_with_policy', is_static=True)
        with self.assertRaisesRegex(ValueError, 'differs from selected HEAD'):
            self.verify(current.replace(helper, helper.replace('sidtab_search_entry(sidtab, sid)', 'NULL')))
        # A newly selected helper revision is preserved exactly. The full port
        # and native-integration preflight still run before this capability.
        native = ULTRA.replace('entry = sidtab_search_entry(sidtab, sid);',
                               'barrier();\n    entry = sidtab_search_entry(sidtab, sid);')
        self.verify(direct_port(native), native)

    def test_missing_link_and_unreadable_selected_source_fail_closed(self):
        (self.root / 'kernel/Kbuild').write_text('# kernelsu-objs += feature/selinux_hide.o\n', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'linked in Kbuild'):
            self.verify(direct_port(ULTRA))
        with patch.object(compat, 'source_git', return_value=subprocess.CompletedProcess([], 1, '', '')):
            with self.assertRaisesRegex(ValueError, 'selected manager source'):
                compat.verify_native_selinux_query(self.root, direct_port(ULTRA))

    def test_only_suki_integration_emits_capability_after_provider_validation(self):
        current = (direct_port(ULTRA) + '\nvoid ksu_selinux_hide_handle_second_stage() {}\n'
                   'void ksu_selinux_hide_handle_post_fs_data() {}\n')
        for relative, text in {compat.DISPATCH: '', compat.OBSERVER: '', compat.POLICY: '',
                               compat.CORE_INIT: '', compat.RUNTIME: '', compat.HIDE: current,
                               compat.KCONFIG: 'config KSU_SUSFS\n\tbool\n'}.items():
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding='utf-8')
        with patch.object(compat, 'validate_dependency'), patch.object(compat, 'apply_reviewed_port'), \
                patch.object(compat, 'verify_integration'), patch.object(compat, 'native_preinit', return_value=True), \
                patch.object(compat, 'dispatch_with_priority', side_effect=lambda source, text, variant: text), \
                patch.object(compat, 'observer_with_priority', side_effect=lambda text, variant: text), \
                patch.object(compat, 'policy_hooks', side_effect=lambda text, **kwargs: text), \
                patch.object(compat, 'source_git', return_value=subprocess.CompletedProcess([], 0, ULTRA, '')):
            compat.integrate(self.root, self.root, 'BakaSU')
            self.assertNotIn(compat.NATIVE_QUERY, (self.root / compat.KCONFIG).read_text('utf-8'))
            (self.root / compat.HIDE).write_text(current.replace('return length;', 'return 0;', 1), encoding='utf-8')
            with self.assertRaises(ValueError):
                compat.integrate(self.root, self.root, 'SukiSU')
            self.assertNotIn(compat.NATIVE_QUERY, (self.root / compat.KCONFIG).read_text('utf-8'))
            (self.root / compat.HIDE).write_text(current, encoding='utf-8')
            compat.integrate(self.root, self.root, 'SukiSU')
            self.assertIn(compat.NATIVE_QUERY_CONFIG, (self.root / compat.KCONFIG).read_text('utf-8'))
            self.assertEqual((), compat.integrate(self.root, self.root, 'SukiSU'))
            self.assertEqual(current, (self.root / compat.HIDE).read_text('utf-8'))


if __name__ == '__main__':
    unittest.main()
