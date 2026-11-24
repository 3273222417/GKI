"""Rebase the reviewed Next port across its native inode-label lifecycle update."""
from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import tempfile


PATH = 'kernel/feature/selinux_hide.c'
NATIVE_SHA256 = '30de2610ada01233cd9ab4521716416951be623e710863e8c9bdcbd9e6e69dfb'
BASE_SHA256 = 'b7a6d74a64d49a11552a10595f284d2340d36d55defcf49f0ccdc9f5896c9ee2'
PORT_SHA256 = 'b8733090001948e211f9e45b92c9acb185bed998dc9c2f421ee19283f6cfc818'
HEADERS = '#include <linux/security.h>\n#include <linux/xattr.h>\n'
KEEP = 'static bool ksu_selinux_hide_keep_backup __read_mostly = false;\n'
INITIALIZE = '''    ret = selinux_hide_init_setxattr();
    if (ret) {
        pr_err("selinux_hide: init: setxattr helpers err: %d\\n", ret);
        return ret;
    }
'''
RETAIN = '''    // Keep backup once hooks may run, including failed enable attempts
    ksu_selinux_hide_keep_backup = true;
'''
REGISTER = '''    ret = ksu_lsm_hook(&selinux_inode_setxattr_hook);
    if (ret) {
        pr_err("selinux_hide: init: selinux_inode_setxattr_hook err: %d\\n", ret);
        goto unhook;
    }

'''
UNREGISTER = '    ksu_lsm_unhook(&selinux_inode_setxattr_hook);\n'


def replace_once(text: str, before: str, after: str) -> str:
    if text.count(before) != 1:
        raise ValueError('Review changed native Next inode-label lifecycle')
    return text.replace(before, after, 1)


def native_update(official: str) -> tuple[str, str]:
    """Separate the exact upstream additions while retaining its parser fixes."""
    if hashlib.sha256(official.encode()).hexdigest() != NATIVE_SHA256:
        raise ValueError('Unreviewed native Next inode-label source')
    begin = official.index('static int (*inode_doinit_with_dentry_fn)')
    end = official.index('static DEFINE_STATIC_KEY_FALSE(fake_status_initialize_key);')
    helper = official[begin:end]
    normalized = official
    for addition in (HEADERS, KEEP, helper, INITIALIZE, RETAIN, REGISTER, UNREGISTER):
        normalized = replace_once(normalized, addition, '')
    return normalized, helper


def restore_update(ported: str, helper: str) -> str:
    """Keep native permission/audit checks and their matched register/unregister."""
    ported = replace_once(ported, '#include <linux/mutex.h>\n', '#include <linux/mutex.h>\n' + HEADERS)
    running = 'bool ksu_selinux_hide_running __read_mostly = false;\n'
    ported = replace_once(ported, running, running + KEEP)
    # The existing SUSFS ABI exposes a six-argument service on 6.6+, while
    # this native fallback retains its original eight-argument dual parse.
    helper = replace_once(helper, 'backup_rc = security_context_to_sid_with_policy(',
                          'backup_rc = __security_context_to_sid_with_policy(')
    status = 'DEFINE_STATIC_KEY_FALSE(fake_status_initialize_key);\n'
    ported = replace_once(ported, status, helper + status)
    opening = 'static int ksu_selinux_hide_enable()\n{\n'
    ported = replace_once(ported, opening, opening + '    int ret;\n')
    ported = replace_once(ported, '#ifndef CONFIG_KSU_SUSFS\n    int ret;\n', '#ifndef CONFIG_KSU_SUSFS\n')
    boundary = '''        return -EAGAIN;
    }
    security_dump_masked_av_fn ='''
    ported = replace_once(ported, boundary, boundary.replace('    security_dump_masked_av_fn =',
                                                           INITIALIZE + '    security_dump_masked_av_fn ='))
    slot = '    orig_context_write = *context_write;\n'
    ported = replace_once(ported, slot, slot + RETAIN)
    status_hook = '#ifndef CONFIG_KSU_SUSFS\n    hook_selinux_status_open();\n#endif\n\n    return 0;\n'
    ported = replace_once(ported, status_hook, RETAIN + REGISTER + status_hook)
    # The new hook is active in either build mode, so its rollback must be
    # available in either mode and also run before a Samsung early return.
    unhook = 'static void ksu_selinux_hide_unhook()\n{\n'
    ported = replace_once(ported, unhook, unhook + UNREGISTER)
    rollback = '''#ifndef CONFIG_KSU_SUSFS
unhook:
    ksu_selinux_hide_unhook();
    return -ENOSYS;
#endif
'''
    ported = replace_once(ported, rollback, rollback.removeprefix('#ifndef CONFIG_KSU_SUSFS\n').removesuffix('#endif\n'))
    return ported


def merge(directory: Path, ours: str, base: str, theirs: str) -> str:
    for name, value in (('ours', ours), ('base', base), ('theirs', theirs)):
        (directory / name).write_text(value, encoding='utf-8', newline='\n')
    process = subprocess.run(['git', 'merge-file', '-p', '--diff3', '-L', 'ours', '-L', 'base', '-L', 'theirs',
                              'ours', 'base', 'theirs'], cwd=directory, capture_output=True, timeout=30)
    if not 0 <= process.returncode <= 127:
        raise ValueError('Cannot review the native Next inode-label merge')
    return process.stdout.decode('utf-8')


def resolve_setxattr(source: Path, conflicted: str, official: str, *, reverse: bool) -> str | None:
    if hashlib.sha256(official.encode()).hexdigest() != NATIVE_SHA256:
        return None
    stages = [subprocess.check_output(['git', '-C', str(source), 'show', f':{index}:{PATH}'], timeout=30)
              .decode('utf-8') for index in (1, 2, 3)]
    base, ours, theirs = stages
    if reverse:
        base, theirs = theirs, base
    if (hashlib.sha256(base.encode()).hexdigest() != BASE_SHA256
            or hashlib.sha256(theirs.encode()).hexdigest() != PORT_SHA256):
        return None
    normalized, helper = native_update(official)
    from susfs_setprocattr_compat import resolved_text
    with tempfile.TemporaryDirectory(prefix='next-inode-label-') as temporary:
        directory = Path(temporary)
        merged = merge(directory, normalized, base, theirs)
        ported = resolved_text(merged, normalized, reverse=False)
        if ported is None:
            return None
        expected = restore_update(ported, helper)
        if ours != (expected if reverse else official):
            return None
        original = merge(directory, stages[1], stages[0], stages[2])
        if conflicted != original:
            return None
    return official if reverse else expected
