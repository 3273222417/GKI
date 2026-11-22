"""Replay the native resolver against symbols extracted from real AK3 Images."""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from nova_symbol_variants import RESOLVER, OLD_BOUNDARY, HASH_BOUNDARY, complete_symbol_variants
from oplus_compat import function_text
import suki_baka_susfs24 as integration

FIXTURE = ROOT / 'tests/fixtures/nova-symbol-variants'
NATIVE = (FIXTURE / 'symbol-resolver-1439545.c').read_text('utf-8')
INIT = (FIXTURE / 'selinux-init-1439545.c').read_text('utf-8')
OBSERVED = json.loads((FIXTURE / 'observed-symbols.json').read_text('utf-8'))


def compiler():
    value = os.environ.get('GKI_TEST_CC')
    if value:
        return json.loads(value) if value.startswith('[') else shlex.split(value)
    found = next((shutil.which(name) for name in ('clang', 'gcc', 'cc') if shutil.which(name)), None)
    return [found] if found else None


class NovaSymbolVariantsTests(unittest.TestCase):
    def test_fixtures_are_bound_to_selected_official_sources(self):
        manifest = json.loads((FIXTURE / 'provenance.json').read_text('utf-8'))
        for name, identity in manifest.items():
            self.assertEqual('1439545f12bffe0263690ba862139b70ee5f20cf', identity['ref'])
            self.assertEqual(identity['fixture_sha256'], hashlib.sha256((FIXTURE / name).read_bytes()).hexdigest())

    def test_only_variant_delimiter_changes_and_completion_is_idempotent(self):
        completed = complete_symbol_variants(NATIVE, NATIVE)
        self.assertEqual(NATIVE.replace(OLD_BOUNDARY, HASH_BOUNDARY, 1), completed)
        self.assertEqual(completed, complete_symbol_variants(NATIVE, completed))
        self.assertEqual(completed, complete_symbol_variants(completed, completed))
        for name in ('ksu_symbol_has_suffix', 'resolve_symbol_variant', 'ksu_resolve_symbol_for_functable_hook'):
            self.assertEqual(function_text(NATIVE, name), function_text(completed, name))

    def test_changed_source_or_changed_boundary_is_rejected(self):
        for current in (NATIVE + '\n/* local edit */\n', NATIVE.replace('return ctx.match;', 'return NULL;', 1)):
            with self.subTest(current=current[-60:]):
                with self.assertRaisesRegex(ValueError, 'differs from the selected source'):
                    complete_symbol_variants(NATIVE, current)
        for native in (NATIVE.replace(OLD_BOUNDARY, 'false)'), NATIVE.replace(OLD_BOUNDARY, "name[ctx->symbol_len] != '_')")):
            with self.assertRaisesRegex(ValueError, 'boundary'):
                complete_symbol_variants(native, native)

    def test_pair_integration_only_adapts_nova_with_native_inode_hook(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'tests', prefix='.nova-symbol-integration-') as temporary:
            source = Path(temporary)
            hide = (INIT + '\nvoid ksu_selinux_hide_handle_second_stage() {}\n'
                    'void ksu_selinux_hide_handle_post_fs_data() {}\n')
            files = {integration.DISPATCH: '', integration.OBSERVER: '', integration.POLICY: '',
                     integration.CORE_INIT: '', integration.RUNTIME: '', integration.HIDE: hide,
                     integration.KCONFIG: 'config KSU_SUSFS\n\tbool\n',
                     'kernel/Kbuild': 'kernelsu-objs += hook/lsm_hook.o\n', RESOLVER: NATIVE}
            for relative, text in files.items():
                target = source / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text, encoding='utf-8')
            with ExitStack() as stack:
                for name in ('validate_dependency', 'apply_reviewed_port', 'verify_integration', 'verify_native_selinux_query'):
                    stack.enter_context(patch.object(integration, name))
                stack.enter_context(patch.object(integration, 'native_preinit', return_value=True))
                stack.enter_context(patch.object(integration, 'source_git', return_value=subprocess.CompletedProcess([], 0, NATIVE, '')))
                stack.enter_context(patch.object(integration, 'dispatch_with_priority', side_effect=lambda source, text, variant: text))
                stack.enter_context(patch.object(integration, 'observer_with_priority', side_effect=lambda text, variant: text))
                stack.enter_context(patch.object(integration, 'policy_hooks', side_effect=lambda text, **kwargs: text))
                integration.integrate(source, source, 'BakaSU')
                self.assertEqual(NATIVE, (source / RESOLVER).read_text('utf-8'))
                changed = integration.integrate(source, source, 'SukiSU')
                self.assertIn(source / RESOLVER, changed)
                self.assertEqual(complete_symbol_variants(NATIVE, NATIVE), (source / RESOLVER).read_text('utf-8'))
                self.assertEqual((), integration.integrate(source, source, 'SukiSU'))
                (source / RESOLVER).write_text(NATIVE + '\n/* unreviewed change */\n', encoding='utf-8')
                before = {p: p.read_bytes() for p in source.rglob('*') if p.is_file()}
                with self.assertRaises(ValueError):
                    integration.integrate(source, source, 'SukiSU')
                self.assertEqual(before, {p: p.read_bytes() for p in source.rglob('*') if p.is_file()})

    @unittest.skipUnless(compiler(), 'A C compiler is needed to replay native symbol selection')
    def test_native_c_reproduces_minus_two_and_resolves_real_hashed_cfi_entry(self):
        arrays = []
        for index, case in enumerate(OBSERVED):
            entries = ',\n'.join('{' + json.dumps(item['name']) + ', UINT64_C(' + item['address'] + ')}'
                                  for item in case['symbols'] if item['name'] != 'inode_doinit_with_dentry_fn')
            arrays.append('static const struct symbol fixture' + str(index) + '[] = {\n' + entries + '\n};\n')
        prelude = r'''
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define KERNEL_VERSION(a,b,c) (((a)<<16)|((b)<<8)|(c))
#define USE_KCFI (LINUX_VERSION_CODE >= KERNEL_VERSION(6,1,0))
#define ALWAYS_HAVE_ON_EACH_SYMBOL (LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0))
#define KSYM_NAME_LEN 256
#define __nocfi
#define pr_info(...) ((void)0)
#define ENOENT 2
struct module { int unused; };
struct inode { int unused; };
struct dentry { int unused; };
struct symbol { const char *name; uintptr_t addr; };
struct ksu_lookup_symbol_ctx { const char *symbol_name; size_t symbol_len; void *match; };
static const struct symbol *table;
static size_t table_count;
static int superblock_result;
static struct { void *original; } selinux_inode_setxattr_hook;
static int (*inode_doinit_with_dentry_fn)(struct inode *, struct dentry *);
static int ksu_selinux_superblock_init(void) { return superblock_result; }
static unsigned long find_kernel_symbol_exact(const char *name)
{
    for (size_t i=0; i<table_count; ++i) if (!strcmp(table[i].name,name)) return table[i].addr;
    return 0;
}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
typedef int (*callback_t)(void *, const char *, unsigned long);
#else
typedef int (*callback_t)(void *, const char *, struct module *, unsigned long);
#endif
static int iterate_symbols(callback_t callback, void *data)
{
    for (size_t i=0; i<table_count; ++i) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
        int ret = callback(data,table[i].name,table[i].addr);
#else
        int ret = callback(data,table[i].name,NULL,table[i].addr);
#endif
        if (ret) return ret;
    }
    return 0;
}
#if !ALWAYS_HAVE_ON_EACH_SYMBOL
static int (*kallsyms_on_each_symbol_fn)(callback_t,void *) = iterate_symbols;
#endif
#define kallsyms_on_each_symbol iterate_symbols
#if !USE_KCFI
static const char cfi_suffix[] = ".cfi_jt";
static const size_t cfi_suffix_len = sizeof(cfi_suffix)-1;
#endif
'''
        main = r'''
static void choose(const struct symbol *values, size_t count) { table=values; table_count=count; }
int main(void)
{
    assert(ksu_symbol_has_suffix("x.cfi_jt",8,".cfi_jt",7));
    choose(fixture0,sizeof(fixture0)/sizeof(fixture0[0]));
    int ret = selinux_hide_init_setxattr();
#if EXPECT_HASH
    assert(ret == 0);
    assert((uintptr_t)inode_doinit_with_dentry_fn == UINT64_C(0xffffffc0086694ec));
    assert((uintptr_t)selinux_inode_setxattr_hook.original ==
           (USE_KCFI ? UINT64_C(0xffffffc00866d40c) : UINT64_C(0xffffffc009208050)));
#else
    assert(ret == -ENOENT);
#endif
    choose(fixture1,sizeof(fixture1)/sizeof(fixture1[0]));
    assert(selinux_hide_init_setxattr() == 0);
    assert((uintptr_t)selinux_inode_setxattr_hook.original == UINT64_C(0xffffffc080644aac));
    const struct symbol legacy[] = {{"selinux_inode_setxattr.llvm.123",100},
        {"selinux_inode_setxattr.llvm.123.cfi_jt",200}};
    choose(legacy,2);
    assert((uintptr_t)ksu_resolve_symbol_for_functable_hook("selinux_inode_setxattr") == (USE_KCFI ? 100u : 200u));
    const struct symbol wrong[] = {{"selinux_inode_setxattr_other$hash.cfi_jt",100},
        {"selinux_inode_setxattr_extra",200},{"inode_doinit_with_dentry",300}};
    choose(wrong,3);
    assert(ksu_resolve_symbol_for_functable_hook("selinux_inode_setxattr") == NULL);
    assert(selinux_hide_init_setxattr() == -ENOENT);
    assert(ksu_resolve_symbol_for_functable_hook("") == NULL);
    assert(ksu_resolve_symbol_for_functable_hook(NULL) == NULL);
    superblock_result = -12;
    assert(selinux_hide_init_setxattr() == -12);
    puts("native symbol selection and SELinux-init error boundaries passed");
    return 0;
}
'''
        with tempfile.TemporaryDirectory(dir=ROOT / 'tests', prefix='.nova-symbol-compile-') as temporary:
            directory = Path(temporary)
            source = directory / 'resolver.c'
            binary = directory / ('resolver.exe' if os.name == 'nt' else 'resolver')
            for expect_hash in (False, True):
                selected = complete_symbol_variants(NATIVE, NATIVE) if expect_hash else NATIVE
                callback = '#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)\n' + function_text(selected, 'lookup_symbol_variant_cb')
                functions = '\n'.join((function_text(selected, 'ksu_symbol_has_suffix'), callback,
                                        function_text(selected, 'resolve_symbol_variant'),
                                        function_text(selected, 'ksu_resolve_symbol_for_functable_hook'), INIT))
                generated = prelude + '\n' + functions + '\n' + ''.join(arrays) + main
                # Windows uses LLP64, while the real ARM64 kernel is LP64.
                # Preserve the kernel's word-sized addresses on this host.
                if os.name == 'nt':
                    generated = generated.replace('unsigned long', 'uintptr_t')
                source.write_text(generated, encoding='utf-8')
                for version in ((5,10,0),(5,15,0),(6,1,0),(6,6,0),(6,12,0)):
                    for optimization in ('-O0','-O2'):
                        with self.subTest(fixed=expect_hash, version=version, optimization=optimization):
                            code = (version[0]<<16)|(version[1]<<8)|version[2]
                            compiled = subprocess.run(compiler() + ['-std=c11','-Wall','-Wextra','-Werror','-Wno-unused-parameter',
                                optimization,'-DLINUX_VERSION_CODE='+str(code),'-DEXPECT_HASH='+str(int(expect_hash)),
                                str(source),'-o',str(binary)], capture_output=True, text=True, timeout=180)
                            self.assertEqual(0, compiled.returncode, compiled.stdout+compiled.stderr)
                            executed = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
                            self.assertEqual(0, executed.returncode, executed.stdout+executed.stderr)


if __name__ == '__main__':
    unittest.main()
