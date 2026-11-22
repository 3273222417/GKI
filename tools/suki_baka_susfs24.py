#!/usr/bin/env python3
"""Connect the official SUSFS 2.4 APIs to the selected SukiSU or BakaSU source."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re

from additional_susfs24 import policy_hooks
from apply_susfs23 import PATCH_PATH, apply_reviewed_port, git as source_git, verify_integration
from ensure_susfs_headers import without_comments
from ensure_susfs_priority import CONFIG as PRIORITY_CONFIG, OPTION, priority_api
from nova_symbol_variants import RESOLVER, complete_symbol_variants
from validate_susfs_hooks import inspect_c_source, strip_comments_and_literals


SUSFS_VERSION = 'v2.4.0'
PREINIT = 'KSU_SUSFS_NATIVE_PREINIT'
PREINIT_CONFIG = f'''
config {PREINIT}
\tbool
\tdepends on KSU_SUSFS
\tdefault y
'''
NATIVE_QUERY = 'KSU_SUSFS_NATIVE_SELINUX_QUERY'
NATIVE_QUERY_CONFIG = f'''
config {NATIVE_QUERY}
\tbool
\tdepends on KSU=y && KSU_SUSFS
\tdefault y
'''
# Full C token identities of the existing native implementations, after the
# reviewed direct-hook port. These two protocol contracts lock permission
# failures, backup-policy calls, output format and return lengths together.
# A changed upstream callback must fail the normal sync preflight for review;
# its policy helpers remain source-bound without a version/hash whitelist.
# Observed callback contracts: Ultra 645ef986 and Nova c60f21b9.
NATIVE_QUERY_IDENTITIES = {
    'my_write_context': {'2ee611ac5640692fa0550f139dde572eb785d32884e12f0387e57f129d3a34e4'},
    'my_write_access': {'45d4d7a3b1810d8613ebf133f8d13f99abb8c2e94facc89903577c5f935e0ff5'},
}
NATIVE_QUERY_HELPERS = ('security_context_to_sid_with_policy', 'security_sid_to_context_with_policy',
                        'security_compute_av_user_with_policy')
GUARD = f'#ifdef CONFIG_{OPTION}\n'
END_GUARD = f'#endif // CONFIG_{OPTION}\n'
SETTER = 'susfs_set_priority_uid_filter'
PARSER = 'susfs_parse_priority_app_strings'
COMMAND = 'CMD_SUSFS_SET_PRIORITY_UID_FILTER'
CORE_INIT = 'kernel/core/init.c'
DISPATCH = 'kernel/supercall/dispatch.c'
HIDE = 'kernel/feature/selinux_hide.c'
OBSERVER = 'kernel/manager/pkg_observer.c'
KCONFIG = 'kernel/Kconfig'
POLICY = 'kernel/selinux/sepolicy.c'
RUNTIME = 'kernel/runtime/ksud_integration.c'
PROVIDERS = ('ksu_setup_preinit_file', 'ksu_preinit_handle_post_execveat')
PREINIT_SIGNATURES = (
    r'int\s+ksu_setup_preinit_file\(\s*struct filename\s*\*\*\s*\w+,\s*'
    r'struct user_arg_ptr\s*\*\s*\w+\s*\)\s*\{',
    r'int\s+ksu_preinit_handle_post_execveat\(\s*int\s*\*\s*\w+,\s*'
    r'struct filename\s*\*\*\s*\w+,\s*void\s*\*\s*\w+,\s*void\s*\*\s*\w+,\s*'
    r'int\s*\*\s*\w+,\s*int\s*\*\s*\w+,\s*int\s*\*\s*\w+\s*\)\s*\{',
)


def read(root: Path, relative: str) -> str:
    path = root / relative
    if (path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root)
            or path.stat().st_size > 512 * 1024):
        raise ValueError('Missing or invalid SUSFS integration source: ' + relative)
    return path.read_text(encoding='utf-8')


def validate_dependency(dependency: Path) -> None:
    root = dependency.resolve(strict=True)
    header = read(root, 'kernel_patches/include/linux/susfs.h')
    defs = read(root, 'kernel_patches/include/linux/susfs_def.h')
    implementation = read(root, 'kernel_patches/fs/susfs.c')
    if re.findall(r'(?m)^\s*#\s*define\s+SUSFS_VERSION\s+"([^"\n]+)"\s*$',
                  without_comments(header)) != [SUSFS_VERSION]:
        raise ValueError('SukiSU/BakaSU 2.4 integration requires the verified SUSFS v2.4.0 tree')
    if not re.search(r'(?m)^#define\s+' + COMMAND + r'\s+0x60030\s*$', without_comments(defs)):
        raise ValueError('SUSFS v2.4.0 priority UID command does not match its native ABI')
    if (priority_api(header, implementation) != 'conditional'
            or not re.search(r'(?m)^int susfs_add_sus_avd_allowed_by_type\(u32 s_type, u32 t_type, u32 c_type, '
                             r'u32 orig_avd_allowed\)\s*\{', implementation)
            or not re.search(r'(?m)^int susfs_add_sus_type\(const char \*secctx, u32 type_value\)\s*\{', implementation)):
        raise ValueError('SUSFS v2.4.0 does not provide the reviewed priority and SELinux policy APIs')


def dispatch_with_priority(source: Path, text: str, variant: str) -> str:
    code = strip_comments_and_literals(text)
    avc = re.compile(r'(?m)^([ \t]+)case CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING:[ \t]*\{?[ \t]*\n'
                     r'([ \t]+)susfs_set_avc_log_spoofing\(arg\);')
    matches = list(avc.finditer(code))
    if len(matches) != 1:
        raise ValueError('Review the changed native SUSFS command dispatcher')
    anchor = matches[0]
    before = code[:anchor.start()]
    if variant == 'SukiSU':
        gate = re.search(r'if\s*\(magic2\s*==\s*SUSFS_MAGIC\s*&&\s*current_uid\(\)\.val\s*==\s*0\)'
                         r'\s*\{\s*switch\s*\(cmd\)\s*\{', before)
        if not gate or not in_switch(before[gate.end():]):
            raise ValueError('SukiSU no longer routes SUSFS commands through its native root gate')
    else:
        supercall = strip_comments_and_literals(read(source, 'kernel/supercall/supercall.c'))
        route = re.search(r'if\s*\(magic2\s*==\s*SUSFS_MAGIC\)\s*\{\s*return ksu_handle_susfs_cmd\(cmd, arg\);',
                          supercall)
        switch = re.search(r'int\s+ksu_handle_susfs_cmd\(unsigned int cmd, void __user \*\*arg\)'
                           r'\s*\{\s*switch\s*\(cmd\)\s*\{', before)
        if (not route or not re.search(r'if\s*\(ksu_get_uid_t\(current_uid\(\)\)\s*!=\s*0\)\s*return 0;',
                                       supercall[:route.start()])
                or not switch or not in_switch(before[switch.end():])):
            raise ValueError('BakaSU no longer routes SUSFS commands through its native root gate')
    # A plain switch case works for both managers and the shared optional-API
    # guard verifier. Keep it beside the existing privileged SUSFS commands.
    label, body = anchor.groups()
    addition = (GUARD + f'{label}case {COMMAND}:\n{body}{SETTER}(arg);\n'
                + f'{body}return 0;\n' + END_GUARD)
    count = len(re.findall(r'\b(?:' + COMMAND + '|' + SETTER + r')\b', code))
    if count:
        if count == 2 and text[:anchor.start()].endswith(addition):
            return text
        raise ValueError('Review the existing SUSFS priority UID command route')
    return text[:anchor.start()] + addition + text[anchor.start():]


def in_switch(before: str) -> bool:
    """Reject a marker after a closed switch, even if another block follows."""
    depth = 0
    for character in before:
        depth += (character == '{') - (character == '}')
        if depth < 0:
            return False
    return depth == 0


def observer_with_priority(text: str, variant: str) -> str:
    code = strip_comments_and_literals(text)
    anchors = list(re.finditer(r'(?m)^([ \t]+)track_throne\((false|0|TRACK_THRONE_FORCE_SYNCHRONOUS)\);\n', code))
    calls = tuple(anchor[2] for anchor in anchors)
    supported = ((('false',),) if variant == 'SukiSU'
                 else (('0',), ('TRACK_THRONE_FORCE_SYNCHRONOUS',) * 2))
    if calls not in supported or len(re.findall(r'\btrack_throne\s*\(', code)) != len(anchors):
        raise ValueError('Review the changed native package-list refresh callback')
    existing = len(re.findall(r'\b' + PARSER + r'\s*\(', code))
    if existing not in (0, len(anchors)):
        raise ValueError('Incomplete SUSFS priority UID refresh wiring')
    for anchor in reversed(anchors):
        addition = GUARD + f'{anchor[1]}{PARSER}();\n' + END_GUARD
        if existing:
            if not text[anchor.end():].startswith(addition):
                raise ValueError('SUSFS priority UID refresh must follow the native package scan')
        else:
            text = text[:anchor.end()] + addition + text[anchor.end():]
    include = '#include <linux/susfs.h>\n'
    if not re.search(r'(?m)^#include\s+<linux/susfs\.h>\s*$', without_comments(text)):
        anchor = re.search(r'(?m)^#include "klog\.h".*\n', text)
        if not anchor:
            raise ValueError('Cannot locate the native package observer header block')
        text = text[:anchor.start()] + GUARD + include + END_GUARD + text[anchor.start():]
    return text


def native_preinit(source: Path, variant: str) -> bool:
    path = source / 'kernel/preinit/preinit.c'
    if path.exists() or path.is_symlink():
        implementation = read(source, 'kernel/preinit/preinit.c')
        _, definitions = inspect_c_source(path, implementation, symbols=PROVIDERS)
        code = strip_comments_and_literals(implementation)
        if ({item.symbol for item in definitions if not item.is_static} != set(PROVIDERS)
                or any(len(re.findall(signature, code)) != 1 for signature in PREINIT_SIGNATURES)):
            raise ValueError('Selected SUSFS source has incomplete native preinit providers')
        # Verify that both providers are actually linked. BakaSU declares its
        # preinit object in the native runner makefile, included by Kbuild.
        kbuild = read(source, 'kernel/Kbuild')
        linked = r'(?m)^kernelsu-objs\s*\+=\s*preinit/preinit\.o\s*$'
        if not re.search(linked, kbuild):
            code_generation = 'tools/code_generation/code_generation.mk'
            rule = 'tools/code_generation/preinit_runner/preinit_runner.mk'
            if (code_generation not in kbuild or rule not in read(source, 'kernel/' + code_generation)
                    or not re.search(linked, read(source, 'kernel/' + rule))
                    or '#elif defined(CONFIG_KSU_SUSFS)' not in implementation):
                raise ValueError('The native SUSFS preinit provider is not linked in this hook mode')
        return True
    if variant == 'BakaSU':
        legacy = (('kernel/feature/sucompat.c', 'ksu_handle_execveat'),
                  ('kernel/runtime/ksud_integration.c', 'ksu_handle_input_handle_event'))
        for relative, symbol in legacy:
            _, definitions = inspect_c_source(source / relative, read(source, relative), symbols=(symbol,))
            if not any(item.symbol == symbol and not item.is_static for item in definitions):
                raise ValueError('BakaSU legacy SUSFS hook provider is missing: ' + symbol)
        return False
    raise ValueError('SukiSU SUSFS v2.4.0 requires the reviewed native preinit providers')


def query_tokens(text: str) -> tuple[str, ...]:
    return tuple(re.findall(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[A-Za-z_]\w*|[0-9][A-Za-z_0-9.]*|\S',
                            without_comments(text)))


def query_implementation(text: str, symbol: str, *, is_static: bool) -> str:
    """Extract exactly one real, unconditional function and its declarator."""
    code = strip_comments_and_literals(text)
    clean = without_comments(text)
    _, definitions = inspect_c_source(Path(HIDE), text, symbols=(symbol,))
    found = [item for item in definitions if item.symbol == symbol]
    signature = (r'(?m)^' + (r'static\s+' if is_static else '')
                 + (r'ssize_t\s+' if symbol.startswith('my_write_') else r'(?:int|void)\s+(?:__nocfi\s+)?')
                 + re.escape(symbol) + r'\s*\([^;{}]*\)\s*\{')
    matches = list(re.finditer(signature, code))
    if len(found) != 1 or found[0].is_static != is_static or len(matches) != 1:
        raise ValueError('Missing real native SELinux query provider: ' + symbol)
    match = matches[0]
    depth = 0
    for directive in re.findall(r'(?m)^\s*#\s*(if|ifdef|ifndef|endif)\b', clean[:match.start()]):
        depth += -1 if directive == 'endif' else 1
        if depth < 0:
            raise ValueError('Unbalanced native SELinux query preprocessor guards')
    if depth:
        raise ValueError('Native SELinux query provider must be unconditional: ' + symbol)
    end, braces = match.end(), 1
    while end < len(code) and braces:
        braces += (code[end] == '{') - (code[end] == '}')
        end += 1
    implementation = text[match.start():end]
    if braces or re.search(r'(?m)^\s*#', without_comments(implementation)):
        raise ValueError('Review the native SELinux query body: ' + symbol)
    return implementation


def verify_native_selinux_query(source: Path, text: str) -> None:
    """Preserve selected-HEAD query logic and prove its reviewed direct ABI."""
    code = strip_comments_and_literals(text)
    clean = without_comments(text)
    native = source_git(source, 'show', 'HEAD:' + HIDE)
    if native.returncode:
        raise ValueError('Cannot bind native SELinux queries to the selected manager source')
    if not re.search(r'(?m)^kernelsu-objs\s*\+=\s*feature/selinux_hide\.o\s*$',
                     read(source, 'kernel/Kbuild')):
        raise ValueError('Native SELinux query providers must be linked in Kbuild')
    if re.search(r'\borig_(?:context|access)_write\b', code):
        raise ValueError('Native SELinux queries must not retain the legacy orig_* detour')
    permission_macros = re.findall(r'(?m)^\s*#\s*define\s+ksu_avc_has_perm_compat\([^\n]*', clean)
    if [re.sub(r'\s+', '', item) for item in permission_macros] != [
            '#defineksu_avc_has_perm_compat(...)avc_has_perm(__VA_ARGS__)',
            '#defineksu_avc_has_perm_compat(...)avc_has_perm(&selinux_state,__VA_ARGS__)']:
        raise ValueError('Native SELinux queries require their real AVC permission helper')
    protected = tuple(NATIVE_QUERY_IDENTITIES) + NATIVE_QUERY_HELPERS + ('backup_sepolicy',)
    if re.search(r'(?m)^\s*#\s*(?:define|undef)\s+(?:' + '|'.join(protected) + r')\b', clean):
        raise ValueError('Native SELinux query providers must not be replaced by macros')
    for symbol in protected[:-1]:
        callback = symbol in NATIVE_QUERY_IDENTITIES
        implementation = query_implementation(text, symbol, is_static=not callback)
        original = query_implementation(native.stdout, symbol, is_static=True)
        if callback:
            # The reviewed port makes the callback global and removes only
            # the module detour. App-UID/hide-running gates live in selinuxfs.
            original = re.sub(r'^static\s+', '', without_comments(original), count=1)
            kind = 'context' if symbol == 'my_write_context' else 'access'
            detour = (r'\s*if\s*\(likely\(current_uid\(\)\.val\s*<\s*10000\)\)\s*\{\s*'
                      r'return\s+orig_' + kind + r'_write\(file,\s*buf,\s*size\);\s*\}')
            original, count = re.subn(detour, '', original)
            if count != 1:
                raise ValueError('Review the selected native SELinux query detour: ' + symbol)
        if query_tokens(implementation) != query_tokens(original):
            raise ValueError('Native SELinux query differs from selected HEAD: ' + symbol)
        identity = hashlib.sha256('\0'.join(query_tokens(implementation)).encode()).hexdigest()
        if callback and identity not in NATIVE_QUERY_IDENTITIES[symbol]:
            raise ValueError('Review the native SELinux query permissions, backup policy and return protocol: ' + symbol)


def configure(text: str, modern: bool, *, native_query: bool = False) -> str:
    if len(re.findall(r'(?m)^config KSU_SUSFS\s*$', text)) != 1:
        raise ValueError('SUSFS integration requires the native KSU_SUSFS configuration')
    for name, definition, enabled in ((OPTION, PRIORITY_CONFIG, True), (PREINIT, PREINIT_CONFIG, modern),
                                      (NATIVE_QUERY, NATIVE_QUERY_CONFIG, native_query)):
        count = len(re.findall(r'(?m)^config ' + name + r'\s*$', text))
        if count:
            if not enabled or count != 1 or definition.strip() not in text:
                raise ValueError('Review the existing SUSFS configuration for ' + name)
            if name == NATIVE_QUERY:
                block = re.search(r'(?ms)^config ' + name + r'\n.*?(?=^(?:config|menuconfig|menu|endmenu|'
                                  r'if|endif|choice|endchoice|comment)\b|\Z)', text)
                if block is None or block[0].strip() != definition.strip():
                    raise ValueError('Native SELinux query capability requires its exact hidden builtin-only configuration')
        elif enabled:
            text = text.rstrip() + '\n' + definition
    return text


def remove_unlinked_lsm_init(text: str) -> str:
    """Drop the stray lifecycle call left by one reviewed direct-hook port."""
    code = strip_comments_and_literals(text)
    calls = re.findall(r'\bksu_lsm_hook_(?:init|exit)\s*\(', code)
    if not calls:
        return text
    anchor = '    ksu_feature_init();\n\n    ksu_lsm_hook_init();\n    ksu_avc_spoof_init();\n'
    if calls != ['ksu_lsm_hook_init('] or code.count(anchor) != 1:
        raise ValueError('Review the changed SukiSU direct-hook lifecycle')
    return text.replace(anchor, anchor.replace('    ksu_lsm_hook_init();\n', ''), 1)


def remove_unlinked_input_work(text: str) -> str:
    """Keep direct input hooks and drop the stray legacy kprobe work from fstat."""
    code = strip_comments_and_literals(text)
    references = re.findall(r'\b(?:input_hook_stopped|stop_input_hook_work)\b', code)
    if not references:
        return text
    fstat = re.search(r'(?ms)^void ksu_handle_vfs_fstat\(int fd, loff_t \*kstat_size_ptr\)\n\{\n(.*?)^\}', code)
    tail = '    input_hook_stopped = true;\n    schedule_work(&stop_input_hook_work);\n'
    if references != ['input_hook_stopped', 'stop_input_hook_work'] or fstat is None or not fstat[1].endswith(tail):
        raise ValueError('Review the changed SukiSU direct input-hook lifecycle')
    return text[:fstat.end(1) - len(tail)] + text[fstat.end(1):]


def restore_selinux_lifecycle_boundary(text: str) -> str:
    """Keep the second-stage and post-fs-data callbacks at file scope."""
    symbols = ('ksu_selinux_hide_handle_second_stage', 'ksu_selinux_hide_handle_post_fs_data')
    _, definitions = inspect_c_source(Path(HIDE), text, symbols=symbols)
    names = tuple(item.symbol for item in definitions if not item.is_static)
    if names == symbols:
        return text
    anchor = ('        pr_warn("selinux_hide: fake status need late initialization\\\\n");\n'
              '\nvoid ksu_selinux_hide_handle_post_fs_data()\n{\n')
    if names != symbols[:1] or text.count(anchor) != 1:
        raise ValueError('Review the changed SukiSU SELinux hide callbacks')
    updated = text.replace(anchor, anchor.replace('\n\nvoid ', '\n}\n\nvoid '), 1)
    _, definitions = inspect_c_source(Path(HIDE), updated, symbols=symbols)
    if tuple(item.symbol for item in definitions if not item.is_static) != symbols:
        raise ValueError('SukiSU SELinux hide callbacks must both be defined at file scope')
    return updated


def integrate(source: Path, dependency: Path, variant: str) -> tuple[Path, ...]:
    """Apply 2.4 wiring after snapshot preparation and any BakaSU KPM restoration."""
    if variant not in ('SukiSU', 'BakaSU'):
        raise ValueError('Unsupported SukiSU/BakaSU SUSFS integration variant')
    validate_dependency(dependency)
    source = source.resolve(strict=True)
    if variant == 'SukiSU':
        if re.search(r'(?m)^config ' + PREINIT + r'\s*$', read(source, KCONFIG)):
            verify_integration(source)
        else:
            apply_reviewed_port(source, PATCH_PATH, allow_variants=True)
    original = {relative: read(source, relative) for relative in (DISPATCH, OBSERVER, KCONFIG, POLICY)}
    updated = {
        DISPATCH: dispatch_with_priority(source, original[DISPATCH], variant),
        OBSERVER: observer_with_priority(original[OBSERVER], variant),
        POLICY: policy_hooks(original[POLICY], baka_layout=variant == 'BakaSU'),
    }
    if variant == 'SukiSU':
        # Nova keeps the reviewed LSM provider for its separate inode label hook.
        original[CORE_INIT] = read(source, CORE_INIT)
        if not re.search(r'(?m)^kernelsu-objs\s*\+=\s*hook/lsm_hook\.o\s*$', read(source, 'kernel/Kbuild')):
            updated[CORE_INIT] = remove_unlinked_lsm_init(original[CORE_INIT])
        original[RUNTIME] = read(source, RUNTIME)
        updated[RUNTIME] = remove_unlinked_input_work(original[RUNTIME])
        original[HIDE] = read(source, HIDE)
        updated[HIDE] = restore_selinux_lifecycle_boundary(original[HIDE])
        verify_native_selinux_query(source, updated[HIDE])
        if re.search(r'\bselinux_hide_init_setxattr\s*\(', strip_comments_and_literals(updated[HIDE])):
            # Nova retains its native inode-label hook. Its CFI resolver must
            # recognize Android Clang's $hash variant as well as .llvm names.
            native_resolver = source_git(source, 'show', 'HEAD:' + RESOLVER)
            if native_resolver.returncode:
                raise ValueError('Cannot bind Nova symbol variants to the selected manager source')
            original[RESOLVER] = read(source, RESOLVER)
            updated[RESOLVER] = complete_symbol_variants(native_resolver.stdout, original[RESOLVER])
    updated[KCONFIG] = configure(original[KCONFIG], native_preinit(source, variant), native_query=variant == 'SukiSU')
    changed = []
    for relative, text in updated.items():
        if text != original[relative]:
            target = source / relative
            target.write_text(text, encoding='utf-8', newline='\n')
            changed.append(target)
    return tuple(changed)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--dependency', type=Path, required=True)
    parser.add_argument('--variant', choices=('SukiSU', 'BakaSU'), required=True)
    args = parser.parse_args()
    print(f'{args.variant} SUSFS {SUSFS_VERSION}: {len(integrate(args.source, args.dependency, args.variant))} files updated')
