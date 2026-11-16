#!/usr/bin/env python3
"""Quietly gate SukiSU's native KPM page before its work scope and refresh."""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys

from manager_variants import manager_source_package

MARKER = 'GKI_SUKISU_KPM_AUTHORIZATION_V1'
ENTRY = 'fun KpmScreen(bottomInnerPadding: Dp = 0.dp) {\n'
AUTHORIZATION = '''try {{
    {namespace}.Natives.isManager &&
        {namespace}.Natives.isFullFeatured() &&
        {namespace}.ui.util.rootAvailable()
}} catch (cancelled: CancellationException) {{
    throw cancelled
}} catch (_: Exception) {{
    false
}}'''
NOVA_EXTENSION_LOAD = '        Result.success(withContext(Dispatchers.IO) { repo.probeAll().map(::toItem) })\n'
NOVA_EXTENSION_LOAD_GUARDED = '''        Result.success(withContext(Dispatchers.IO) {{
            repo.probeAll().filter {{
                // GKI_SUKISU_KPM_AUTHORIZATION_V1
                it.wireName != "kpm" || {authorization}
            }}.map(::toItem)
        }})
'''


def authorization(namespace: str, indent: int) -> str:
    return AUTHORIZATION.format(namespace=namespace).replace('\n', '\n' + ' ' * indent)


def authorization_guard(namespace: str) -> str:
    return (f'    // {MARKER}\n'
            f'    val kpmAuthorized = {authorization(namespace, 4)}\n'
            '    if (!kpmAuthorized) return\n\n')


def read_source(root: Path, relative: str) -> tuple[Path, bytes, str, str]:
    path = root / relative
    for component in (path, *path.parents):
        if component == root:
            break
        if component.is_symlink() or (hasattr(component, 'is_junction') and component.is_junction()):
            raise ValueError('SukiSU KPM sources must not contain linked paths')
    if not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError('Review changed native SukiSU KPM source layout')
    raw = path.read_bytes()
    text = raw.decode('utf-8')
    newline = '\r\n' if '\r\n' in text else '\n'
    text = text.replace('\r\n', '\n')
    if '\r' in text or (newline == '\r\n' and raw.count(b'\n') != raw.count(b'\r\n')):
        raise ValueError('Review mixed native SukiSU KPM source newlines')
    return path, raw, text, newline


def verify_native_entry(text: str, namespace: str) -> None:
    # Keep the real native Material/Miuix screens, module operations and polling.
    # Refuse a moved entry or work placed before the known first context read.
    expected = (
        'package ' + namespace + '.ui.screen.kpm\n',
        'import kotlinx.coroutines.CancellationException\n',
        ENTRY + '    val context = LocalContext.current\n',
        '    val scope = rememberCoroutineScope()\n',
        '    val viewModel = viewModel<KpmViewModel>()\n',
        '    LaunchedEffect(lifecycleOwner, viewModel) {\n',
        'lifecycleOwner.lifecycle.repeatOnLifecycle(Lifecycle.State.RESUMED)',
        'viewModel.fetchModuleList(silent = true)',
        'UiMode.Miuix -> KpmMiuix(viewModel, actions, bottomInnerPadding)',
        'UiMode.Material -> KpmMaterial(viewModel, actions, bottomInnerPadding)',
    )
    if any(text.count(marker) != 1 for marker in expected) or text.count(ENTRY) != 1:
        raise ValueError('Review changed native SukiSU KPM entry before applying authorization')
    if 'kpmAuthorized' in text or MARKER in text:
        raise ValueError('Review an unrecognized native SukiSU KPM authorization guard')


def configure(source: Path) -> bool:
    if source.is_symlink() or (hasattr(source, 'is_junction') and source.is_junction()) or not source.is_dir():
        raise ValueError('Expected an independent SukiSU source directory')
    root = source.resolve(strict=True)
    namespace = manager_source_package('SukiSU', root)
    java = 'manager/app/src/main/java/' + namespace.replace('.', '/')
    guard = authorization_guard(namespace)
    _, _, natives, _ = read_source(root, java + '/Natives.kt')
    if (not re.search(r'(?m)^package ' + re.escape(namespace) + r'\s*$', natives)
            or not re.search(r'\bval\s+isManager\s*:\s*Boolean\s+external\s+get\b', natives)
            or not re.search(r'\bfun\s+isFullFeatured\s*\(\s*\)\s*:\s*Boolean\b', natives)):
        raise ValueError('Review changed native SukiSU authorization APIs')
    _, _, cli, _ = read_source(root, java + '/ui/util/KsuCli.kt')
    if (not re.search(r'(?m)^package ' + re.escape(namespace) + r'\.ui\.util\s*$', cli)
            or len(re.findall(r'\bfun\s+rootAvailable\s*\(\s*\)\s*:\s*Boolean\b', cli)) != 1):
        raise ValueError('Review changed native SukiSU root availability API')
    path, original, text, newline = read_source(root, java + '/ui/screen/kpm/KpmScreen.kt')
    configured = MARKER in text
    if configured:
        if text.count(MARKER) != 1 or text.count(ENTRY + guard) != 1:
            raise ValueError('Review an altered native SukiSU KPM authorization guard')
        baseline = text.replace(guard, '', 1)
    else:
        baseline = text
    verify_native_entry(baseline, namespace)
    updated = baseline.replace(ENTRY, ENTRY + guard, 1).replace('\n', newline).encode('utf-8')
    # This single-file change inserts only the gate. No native theme, command,
    # dialog, root implementation, package identity or ABI is rewritten.
    if not configured and updated.replace(guard.replace('\n', newline).encode('utf-8'), b'', 1) != original:
        raise ValueError('Native SukiSU KPM authorization changed unrelated source bytes')
    outputs = {path: updated} if not configured else {}
    if namespace == 'com.sukisu.nova':
        catalog_path, _, catalog, catalog_newline = read_source(root, java + '/ui/viewmodel/ExtensionsViewModel.kt')
        guarded = NOVA_EXTENSION_LOAD_GUARDED.format(authorization=authorization(namespace, 16))
        if 'import kotlinx.coroutines.CancellationException\n' not in catalog:
            raise ValueError('Review changed Nova extension screen authorization APIs')
        if catalog.count(guarded) == catalog.count(MARKER) == 1 and NOVA_EXTENSION_LOAD not in catalog:
            pass  # Same native extension probe, with the reviewed KPM filter already applied.
        elif MARKER not in catalog and catalog.count(NOVA_EXTENSION_LOAD) == 1:
            limited = catalog.replace(NOVA_EXTENSION_LOAD, guarded, 1)
            outputs[catalog_path] = limited.replace('\n', catalog_newline).encode('utf-8')
        else:
            raise ValueError('Review changed Nova KPM extension card entry')
    for output, data in outputs.items():
        output.write_bytes(data)
    return bool(outputs)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        changed = configure(args.source)
    except (OSError, ValueError, UnicodeError) as error:
        print('SukiSU KPM UI configuration failed: ' + str(error), file=sys.stderr)
        return 1
    print('SukiSU native KPM authorization: ' + ('configured' if changed else 'already configured'))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
