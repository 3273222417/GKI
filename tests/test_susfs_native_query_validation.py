"""Validate the actual generated query bridge against manager capabilities."""
import hashlib
from pathlib import Path
import shutil
import sys
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from susfs24_kernel_patch import bridge_native_selinux_queries
import validate_susfs_hooks as hooks
from test_susfs24_native_query_bridge import SOURCE


CAPABILITY = 'KSU_SUSFS_NATIVE_SELINUX_QUERY'
CALLBACKS = {'my_write_context', 'my_write_access'}
GENERATED = bridge_native_selinux_queries(SOURCE)


class NativeQueryValidationTests(unittest.TestCase):
    def setUp(self):
        self.root = ROOT / 'tests' / ('.query-validation-' + uuid.uuid4().hex)
        self.root.mkdir()
        self.addCleanup(shutil.rmtree, self.root)
        self.selinux = self.source('common/security/selinux/selinuxfs.c', GENERATED)
        self.kconfig = self.source('KernelSU/kernel/Kconfig', 'config KSU_SUSFS\n\tbool\n')

    def source(self, relative, content):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding='utf-8')
        return path.resolve()

    def test_absent_capability_masks_only_generated_calls_for_every_manager(self):
        # The old raw scan reproduces both reported missing providers.
        calls, _ = hooks.inspect_c_source(self.selinux, GENERATED)
        self.assertEqual(CALLBACKS, {symbol for symbol, _ in calls})
        for variant in hooks.MANAGERS:
            with self.subTest(variant=variant):
                result = hooks.validate_hooks(self.root, variant=variant)
                self.assertTrue(result.ok, result.missing)
                self.assertFalse(result.calls)

    def test_missing_kconfig_or_unknown_manager_tree_does_not_exempt_calls(self):
        self.kconfig.unlink()
        self.assertEqual(CALLBACKS, set(hooks.validate_hooks(self.root).missing))
        shutil.rmtree(self.kconfig.parent)
        self.assertEqual(CALLBACKS, set(hooks.validate_hooks(self.root).missing))

    def test_config_and_menuconfig_declarations_keep_real_provider_checking(self):
        for declaration in ('config', 'menuconfig', '  config', '\tmenuconfig'):
            with self.subTest(declaration=declaration):
                self.kconfig.write_text(f'{declaration} {CAPABILITY}\n\tbool\n', encoding='utf-8')
                result = hooks.validate_hooks(self.root)
                self.assertEqual(CALLBACKS, set(result.missing))
                self.assertEqual(CALLBACKS, set(result.calls))

    def test_capable_source_requires_global_definitions_not_prototypes_or_static(self):
        self.kconfig.write_text(f'config {CAPABILITY}\n\tbool\n', encoding='utf-8')
        bodies = (
            ('prototypes', ''.join(f'ssize_t {name}(struct file *, char *, size_t);\n' for name in CALLBACKS)),
            ('static', ''.join(f'static ssize_t {name}(struct file *f, char *b, size_t s) {{ return s; }}\n'
                               for name in CALLBACKS)),
            ('global', ''.join(f'ssize_t {name}(struct file *f, char *b, size_t s) {{ return s; }}\n'
                               for name in CALLBACKS)),
        )
        for kind, body in bodies:
            with self.subTest(kind=kind):
                self.source('KernelSU/kernel/native.c', body)
                result = hooks.validate_hooks(self.root)
                self.assertEqual(set() if kind == 'global' else CALLBACKS, set(result.missing))

    def test_unconditional_calls_after_bridge_remain_checked_with_original_line(self):
        source = GENERATED + '\nvoid required(void) { my_write_access(); my_setprocattr(); }\n'
        self.selinux.write_text(source, encoding='utf-8')
        result = hooks.validate_hooks(self.root)
        self.assertEqual({'my_write_access', 'my_setprocattr'}, set(result.missing))
        expected_line = source.count('\n', 0, source.index('void required')) + 1
        for locations in result.missing.values():
            self.assertEqual([expected_line], [location.line for location in locations])

    def test_unconditional_calls_before_bridge_and_in_another_file_remain_checked(self):
        self.selinux.write_text('void required(void) { my_write_context(); }\n' + GENERATED, encoding='utf-8')
        other = self.source('common/fs/required.c', 'void required(void) { my_write_access(); }\n')
        result = hooks.validate_hooks(self.root)
        self.assertEqual(CALLBACKS, set(result.missing))
        self.assertEqual([(self.selinux, 1)], [(loc.path, loc.line) for loc in result.missing['my_write_context']])
        self.assertEqual([(other, 1)], [(loc.path, loc.line) for loc in result.missing['my_write_access']])

    def test_same_source_at_another_path_is_not_a_reviewed_bridge(self):
        self.selinux.write_text('', encoding='utf-8')
        self.source('common/security/selinux/unreviewed.c', GENERATED)
        self.assertEqual(CALLBACKS, set(hooks.validate_hooks(self.root).missing))

    def test_changed_gate_or_body_is_not_masked(self):
        changes = (
            ('current_uid().val >= 10000', 'current_uid().val >= 9999'),
            ('&& ksu_selinux_hide_running', '|| ksu_selinux_hide_running'),
            ('if (IS_ENABLED(CONFIG_' + CAPABILITY + '))', 'if (1)'),
            ('return my_write_context(file, buf, size);', 'return my_write_context(file, buf, size + 1);'),
            ('return susfs_sel_write_context(file, buf, size);', 'return sel_write_context(file, buf, size);'),
        )
        for original, changed in changes:
            with self.subTest(changed=changed):
                self.selinux.write_text(GENERATED.replace(original, changed), encoding='utf-8')
                self.assertIn('my_write_context', hooks.validate_hooks(self.root).missing)

    def test_source_macro_override_or_duplicate_handler_refuses_exemption(self):
        overrides = (
            f'#define CONFIG_{CAPABILITY} 1\n',
            f'#define CONFIG_{CAPABILITY}_MODULE 1\n',
            f'#undef CONFIG_{CAPABILITY}\n',
            '#define IS_ENABLED(x) 1\n',
            'static ssize_t handle_sel_write_context(struct file *file, char *buf, size_t size)\n'
            '{ return my_write_context(file, buf, size); }\n',
        )
        for extra in overrides:
            with self.subTest(extra=extra):
                self.selinux.write_text(extra + GENERATED, encoding='utf-8')
                self.assertIn('my_write_context', hooks.validate_hooks(self.root).missing)

    def test_comments_and_literals_cannot_qualify_an_unreviewed_handler(self):
        source = ('/*\n' + GENERATED + '\n*/\n'
                  'const char *quoted = "my_write_access(file, buf, size)";\n'
                  'void required(void) { my_write_context(); }\n')
        self.selinux.write_text(source, encoding='utf-8')
        self.assertEqual({'my_write_context'}, set(hooks.validate_hooks(self.root).missing))

    def test_only_exact_capability_declaration_counts(self):
        self.kconfig.write_text(f'# config {CAPABILITY}\nconfig {CAPABILITY}_OTHER\n\tbool\n', encoding='utf-8')
        self.assertTrue(hooks.validate_hooks(self.root).ok)

    def test_mask_and_validation_are_read_only_and_preserve_offsets(self):
        masked = hooks.inactive_native_query_calls(GENERATED)
        self.assertEqual(len(GENERATED), len(masked))
        self.assertEqual([i for i, char in enumerate(GENERATED) if char in '\r\n'],
                         [i for i, char in enumerate(masked) if char in '\r\n'])
        for kind in ('context', 'access'):
            unchanged = f'return susfs_sel_write_{kind}(file, buf, size);'
            self.assertEqual(GENERATED.index(unchanged), masked.index(unchanged))
        before = {path: (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns)
                  for path in self.root.rglob('*') if path.is_file()}
        self.assertTrue(hooks.validate_hooks(self.root).ok)
        after = {path: (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns)
                 for path in self.root.rglob('*') if path.is_file()}
        self.assertEqual(before, after)


if __name__ == '__main__':
    unittest.main()
