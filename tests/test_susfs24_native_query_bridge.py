"""Compile the produced SELinux dispatchers without changing real policy epochs."""
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from oplus_compat import function_text
from susfs24_kernel_patch import (EXPORTS, NATIVE_QUERY_HEADER, SELINUX_FS,
                                  apply_susfs24, bridge_native_selinux_queries,
                                  restore_native_selinux_queries)


# Exact reviewed handler bodies from the five pinned official 2.4 patches.
HANDLERS = '''static ssize_t handle_sel_write_context(struct file *file, char *buf, size_t size) {
\tif ((likely(current_uid().val >= 10000 && ksu_selinux_hide_running)))
\t\treturn susfs_sel_write_context(file, buf, size);
\treturn sel_write_context(file, buf, size);
}

static ssize_t handle_sel_write_access(struct file *file, char *buf, size_t size)
{
\tif ((likely(current_uid().val >= 10000 && ksu_selinux_hide_running)))
\t\treturn susfs_sel_write_access(file, buf, size);
\treturn sel_write_access(file, buf, size);
}
'''
PROVIDERS = ''.join(
    f'static ssize_t {name}(struct file *file, char *buf, size_t size)\n'
    '{\n\treturn original_provider(file, buf, size);\n}\n'
    for name in ('sel_write_context', 'sel_write_access', 'susfs_sel_write_context', 'susfs_sel_write_access'))
SOURCE = (NATIVE_QUERY_HEADER + '#endif // #ifdef CONFIG_KSU_SUSFS\n\n' + PROVIDERS + HANDLERS)


def compiler():
    value = os.environ.get('GKI_TEST_CC')
    if value:
        return json.loads(value) if value.startswith('[') else shlex.split(value)
    path = next((shutil.which(name) for name in ('clang', 'gcc', 'cc') if shutil.which(name)), None)
    return [path] if path else None


class NativeQueryBridgeTests(unittest.TestCase):
    def test_providers_and_original_uid_hide_gates_are_preserved(self):
        result = bridge_native_selinux_queries(SOURCE)
        for name in ('sel_write_context', 'sel_write_access', 'susfs_sel_write_context', 'susfs_sel_write_access'):
            self.assertEqual(function_text(SOURCE, name), function_text(result, name))
        for kind in ('context', 'access'):
            body = function_text(result, 'handle_sel_write_' + kind)
            self.assertIn('current_uid().val >= 10000 && ksu_selinux_hide_running', body)
            self.assertIn('IS_ENABLED(CONFIG_KSU_SUSFS_NATIVE_SELINUX_QUERY)', body)
            self.assertIn(f'return my_write_{kind}(file, buf, size);', body)
            self.assertIn(f'return susfs_sel_write_{kind}(file, buf, size);', body)
            self.assertTrue(body.endswith(f'return sel_write_{kind}(file, buf, size);\n}}'))
        self.assertNotIn('latest_granting', result)
        self.assertNotIn('avc_ss_reset', result)
        self.assertNotIn('seqno =', result)

    def test_changed_or_partial_official_dispatchers_fail_before_file_changes(self):
        variants = (
            SOURCE.replace('current_uid().val >= 10000', 'current_uid().val >= 9999', 1),
            SOURCE.replace('&& ksu_selinux_hide_running', '|| ksu_selinux_hide_running', 1),
            SOURCE.replace('return susfs_sel_write_access(file, buf, size);', 'return 0;', 1),
            SOURCE.replace('size_t size)\n{\n\tif ((likely', 'unsigned size)\n{\n\tif ((likely', 1),
            SOURCE + HANDLERS,
            SOURCE.replace('extern bool ksu_selinux_hide_running', 'extern bool other_running'),
            SOURCE + 'extern ssize_t my_write_access(struct file *, char *, size_t);\n',
            bridge_native_selinux_queries(SOURCE),
        )
        with tempfile.TemporaryDirectory(dir=ROOT / 'tests', prefix='.selinux-query-') as directory:
            common = Path(directory)
            path = common / SELINUX_FS
            path.parent.mkdir(parents=True)
            for original in variants:
                with self.subTest(original=original[-100:]):
                    path.write_bytes(original.encode())
                    with self.assertRaises(ValueError):
                        restore_native_selinux_queries(common)
                    self.assertEqual(original.encode(), path.read_bytes())

    def setup_kernel(self, directory):
        root = Path(directory)
        common = root / 'common'
        upstream = root / 'susfs/kernel_patches'
        paths = ('fs/exec.c', 'fs/notify/fdinfo.c', 'block/ioprio.c',
                 'security/selinux/status.c', SELINUX_FS)
        for relative in paths:
            target = common / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b'original kernel source\n')
        for relative in EXPORTS:
            target = upstream / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b'#define SUSFS_VERSION "v2.4.0"\n' if relative.endswith('/susfs.h') else b'export\n')
        preinit = '+#ifndef KSU_NO_PREINIT\n+\tksu_preinit();\n+#endif // #ifndef KSU_NO_PREINIT\n'
        patch = ''.join(f'diff --git a/{name} b/{name}\n--- a/{name}\n+++ b/{name}\n'
                        '@@ -1,1 +1,1 @@\n-old\n+new\n' + (preinit * 4 if name == 'fs/exec.c' else '')
                        for name in paths)
        (upstream / '50_add_susfs_in_gki-android14-6.1.patch').write_bytes(patch.encode('utf-8'))
        return common, upstream.parent, paths

    def test_bridge_rejection_cannot_publish_other_staged_kernel_patches_or_exports(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'tests', prefix='.selinux-query-atomic-') as directory:
            common, upstream, paths = self.setup_kernel(directory)

            def prepare(stage, patch):
                for name in paths:
                    (stage / name).write_bytes(b'patched source\n')
                (stage / SELINUX_FS).write_bytes(SOURCE.replace('return susfs_sel_write_access(file, buf, size);',
                                                              'return 0;', 1).encode('utf-8'))

            with self.assertRaisesRegex(ValueError, 'query gate'):
                apply_susfs24(common, upstream, 'android14-6.1', apply_patch=prepare)
            for name in paths:
                self.assertEqual(b'original kernel source\n', (common / name).read_bytes())
            self.assertFalse(any((common / name).exists() for name in EXPORTS))

    def test_successful_transaction_publishes_both_dispatchers_together(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'tests', prefix='.selinux-query-publish-') as directory:
            common, upstream, paths = self.setup_kernel(directory)

            def prepare(stage, patch):
                for name in paths:
                    (stage / name).write_bytes(b'patched source\n')
                (stage / SELINUX_FS).write_bytes(SOURCE.encode('utf-8'))

            apply_susfs24(common, upstream, 'android14-6.1', apply_patch=prepare)
            result = (common / SELINUX_FS).read_text(encoding='utf-8')
            self.assertEqual(bridge_native_selinux_queries(SOURCE), result)
            for name in EXPORTS:
                self.assertTrue((common / name).is_file())

    @unittest.skipUnless(compiler(), 'A host C compiler is needed for real dispatch/link validation')
    def test_compiled_dispatch_flag_uid_hide_and_error_boundaries_without_epoch_mutation(self):
        result = bridge_native_selinux_queries(SOURCE)
        declarations = '\n'.join(line for line in result.splitlines() if line.startswith('extern ssize_t my_write_'))
        produced = '\n\n'.join(function_text(result, 'handle_sel_write_' + kind) for kind in ('context', 'access'))
        harness = r'''
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
typedef int64_t ssize_t;
struct file { int marker; };
struct uid_value { unsigned val; };
static unsigned test_uid;
static bool ksu_selinux_hide_running;
#define current_uid() ((struct uid_value){test_uid})
#define likely(x) (x)
#define __ARG_PLACEHOLDER_1 0,
#define __take_second_arg(__ignored, val, ...) val
#define __is_defined(x) ___is_defined(x)
#define ___is_defined(val) ____is_defined(__ARG_PLACEHOLDER_##val)
#define ____is_defined(arg1_or_junk) __take_second_arg(arg1_or_junk 1, 0)
#define IS_ENABLED(option) (__is_defined(option) || __is_defined(option##_MODULE))
static struct file fixture = {71};
static unsigned calls[3][2];
static unsigned last_query_epoch;
static unsigned real_policy_epoch = 17, avc_notified_epoch = 123, enforcing = 1;
static ssize_t record(unsigned path, unsigned kind, struct file *f, char *buf, size_t size)
{
    assert(f == &fixture && size == strlen(buf));
    ++calls[path][kind];
    last_query_epoch = path == 2 ? 17 : 123;
    if (path == 2 && !strcmp(buf, "invalid")) return -22;
    return (ssize_t)(100 * path + 10 * kind + size);
}
static ssize_t sel_write_context(struct file *f, char *b, size_t n) { return record(0, 0, f, b, n); }
static ssize_t sel_write_access(struct file *f, char *b, size_t n) { return record(0, 1, f, b, n); }
static ssize_t susfs_sel_write_context(struct file *f, char *b, size_t n) { return record(1, 0, f, b, n); }
static ssize_t susfs_sel_write_access(struct file *f, char *b, size_t n) { return record(1, 1, f, b, n); }
__DECLARATIONS__
#if TEST_NATIVE
ssize_t my_write_context(struct file *f, char *b, size_t n) { return record(2, 0, f, b, n); }
ssize_t my_write_access(struct file *f, char *b, size_t n) { return record(2, 1, f, b, n); }
#endif
__PRODUCED__
int main(void)
{
    const unsigned uids[] = {0, 9999, 10000, 101234};
    const char *inputs[] = {"valid", "invalid"};
    for (unsigned u = 0; u < sizeof(uids) / sizeof(uids[0]); ++u)
      for (unsigned hide = 0; hide < 2; ++hide)
        for (unsigned input = 0; input < 2; ++input)
          for (unsigned kind = 0; kind < 2; ++kind) {
            test_uid = uids[u]; ksu_selinux_hide_running = hide != 0;
            memset(calls, 0, sizeof(calls));
            unsigned expected = test_uid >= 10000 && hide ? (TEST_NATIVE ? 2 : 1) : 0;
            char buffer[16]; strcpy(buffer, inputs[input]); size_t size = strlen(buffer);
            ssize_t got = kind ? handle_sel_write_access(&fixture, buffer, size)
                               : handle_sel_write_context(&fixture, buffer, size);
            ssize_t wanted = expected == 2 && input == 1 ? -22 : (ssize_t)(100 * expected + 10 * kind + size);
            assert(got == wanted);
            for (unsigned path = 0; path < 3; ++path)
              for (unsigned k = 0; k < 2; ++k)
                assert(calls[path][k] == (unsigned)(path == expected && k == kind));
            assert(last_query_epoch == (expected == 2 ? 17 : 123));
            assert(real_policy_epoch == 17 && avc_notified_epoch == 123 && enforcing == 1);
          }
    puts("native query dispatch/link/epoch boundaries passed");
    return 0;
}
'''.replace('__DECLARATIONS__', declarations).replace('__PRODUCED__', produced)
        with tempfile.TemporaryDirectory(dir=ROOT / 'tests', prefix='.selinux-query-compile-') as directory:
            path = Path(directory)
            source = path / 'dispatch.c'
            source.write_text(harness, encoding='utf-8')
            binary = path / ('dispatch.exe' if os.name == 'nt' else 'dispatch')
            for optimization in ('-O0', '-O2'):
                for flag in ('undefined', '0', '1'):
                    with self.subTest(optimization=optimization, flag=flag):
                        options = ['-DTEST_NATIVE=' + ('1' if flag == '1' else '0')]
                        if flag != 'undefined':
                            options.append('-DCONFIG_KSU_SUSFS_NATIVE_SELINUX_QUERY=' + flag)
                        built = subprocess.run(compiler() + ['-std=c11', '-Wall', '-Wextra', '-Werror', optimization,
                                                            *options, str(source), '-o', str(binary)],
                                               capture_output=True, text=True, timeout=180)
                        self.assertEqual(0, built.returncode, built.stdout + built.stderr)
                        run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
                        self.assertEqual(0, run.returncode, run.stdout + run.stderr)
                        self.assertIn('boundaries passed', run.stdout)


if __name__ == '__main__':
    unittest.main()
