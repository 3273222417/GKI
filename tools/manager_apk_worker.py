"""Build preselected official APKs inside the scheduled upstream check."""
from __future__ import annotations

import copy
import re

from manager_lkm_jobs import KMIS, lkm_cache_key
from manager_prebuild import CHANNELS, slot_for
from manager_variants import MANAGERS
from reuse_manager_jobs import expression


PREPARE = 'prebuild-manager-sources'
NATIVE = 'prebuild-manager-native'
MANAGER = 'prebuild-manager-apks'
DISCOVERY = 'needs.check-upstream.outputs.manager_prebuild_'
SLOTS = tuple(slot_for(variant, tier) for variant in MANAGERS for tier in CHANNELS)
SUBSTITUTIONS = {
    'inputs.kernelsu_variant': 'matrix.variant',
    'inputs.kernelsu_branch': 'matrix.tier',
    'inputs.operation': "'仅编译管理器安装包'",
    'inputs.enable_susfs': 'false',
    "github.event_name == 'workflow_dispatch'": 'true',
}


def substitute(value):
    if isinstance(value, str):
        for before, after in SUBSTITUTIONS.items():
            value = value.replace(before, after)
        value = re.sub(r'needs\.prepare-matrix\.outputs\.(\w+)',
                       lambda match: f"needs.{PREPARE}.outputs[format('{{0}}_{match[1]}', matrix.slot)]", value)
        value = value.replace('prepare-matrix', PREPARE).replace('build-sukisu-lkm', NATIVE)
    elif isinstance(value, list):
        value = [substitute(item) for item in value]
    elif isinstance(value, dict):
        value = {key: substitute(item) for key, item in value.items()}
    return value


def matrix_job(job, matrix, maximum):
    job['strategy'] = {'fail-fast': False, 'max-parallel': maximum,
                       'matrix': expression('fromJSON(' + DISCOVERY + matrix + ')')}


def use_native_cache(native, manager):
    """Transfer verified native inputs through caches, with a local rebuild on misses."""
    upload = next(step for step in native['steps'] if step.get('with', {}).get('name', '')
                  .startswith('internal-manager-native-'))
    native['steps'].remove(upload)
    downloads = [step for step in manager['steps'] if step.get('with', {}).get('name', '')
                 .startswith('internal-manager-native-')]
    if len(downloads) != len(KMIS):
        raise ValueError('Expected one native transfer per official manager KMI')
    position = manager['steps'].index(downloads[0])
    condition = downloads[0]['if']
    if (manager['steps'][position:position + len(KMIS)] != downloads
            or any(step.get('if') != condition for step in downloads)):
        raise ValueError('Prebuild native transfers must share one cold-build condition')

    compile_step = next(step for step in native['steps'] if step['name'] == '编译并核实同版本原生模块')
    extras = next(step for step in native['steps'] if step['name'] == '补齐官方 x86 模块和原生 SUSFS 组件')
    restore = []
    env = {key: value for key, value in compile_step['env'].items() if key not in ('KMI', 'DDK_IMAGE')}
    for index, (download, kmi) in enumerate(zip(downloads, KMIS)):
        cache_id = f'prebuild-kmi-{index}'
        ddk = f'fromJSON(needs.prepare-matrix.outputs.ddk_matrix).include[{index}].ddk_short'
        restore.append({'name': '从缓存读取已核实的原生模块 ' + kmi, 'id': cache_id,
                        'uses': 'actions/cache/restore@v5', 'if': condition,
                        'timeout-minutes': 3, 'continue-on-error': True,
                        'env': {'SEGMENT_DOWNLOAD_TIMEOUT_MINS': '2'},
                        'with': {'path': download['with']['path'], 'key': lkm_cache_key(repr(kmi), ddk)}})
        env[f'PREBUILD_KMI_{index}'] = expression(f'steps.{cache_id}.outputs.cache-hit')
    env['PREPARED_DDK'] = expression('needs.prepare-matrix.outputs.ddk_matrix')
    rebuild = '''set -euo pipefail
python3 - <<'PY' > "$RUNNER_TEMP/prebuild-native-misses"
import json
import os
from pathlib import Path
import sys
sys.path.insert(0, 'tools')
from manager_lkm_jobs import load_ddk_matrix

entries = load_ddk_matrix(Path.cwd())
if json.loads(os.environ['PREPARED_DDK']) != {'include': entries}:
    raise SystemExit('The prepared DDK matrix does not match the fixed inputs')
for index, entry in enumerate(entries):
    if os.environ.get(f'PREBUILD_KMI_{index}') != 'true':
        print(entry['kmi'] + '\\t' + entry['image'])
PY
while IFS=$'\\t' read -r KMI DDK_IMAGE; do
    echo "原生模块缓存未命中，重新编译 $KMI"
    scratch="$(mktemp -d "$RUNNER_TEMP/prebuild-native.XXXXXXXX")"
    trap 'sudo rm -rf -- "$scratch"' EXIT
    cp -a tools config ksu-source-bundle "$scratch/"
    cp -- "$RUNNER_TEMP/manager-public-certificate.json" "$scratch/"
    (
        export GITHUB_WORKSPACE="$scratch" KMI DDK_IMAGE
        cd "$scratch"
        python3 tools/checkout_ksu_snapshot.py --input ksu-source-bundle \\
          --output manager-source --expected-ref "$KSU_REF"
        git config --global --add safe.directory "$scratch/manager-source"
''' + compile_step['run'] + extras['run'] + '''
    )
    python3 - "$KMI" <<'PY'
from pathlib import Path
import sys
sys.path.insert(0, 'tools')
from manager_lkm_jobs import clear_partial_native_output
clear_partial_native_output(Path.cwd(), sys.argv[1])
PY
    mkdir -p manager-lkm
    mv -- "$scratch/manager-lkm/$KMI" "manager-lkm/$KMI"
    sudo rm -rf -- "$scratch"
    trap - EXIT
done < "$RUNNER_TEMP/prebuild-native-misses"
'''
    manager['steps'][position:position + len(KMIS)] = restore + [
        {'name': '在本次 APK 作业补编缺失的原生模块', 'if': condition,
         'env': env, 'run': rebuild}]
    manager['timeout-minutes'] = max(manager['timeout-minutes'], 90)


def create_jobs(base):
    ids = ('prepare-matrix', 'build-sukisu-lkm', 'build-sukisu-manager')
    prepare, native, manager = (copy.deepcopy(base['jobs'][name]) for name in ids)
    prepare['name'] = '${{ matrix.variant }} · ${{ matrix.channels }} · 固定 APK 源码与签名'
    for key in ('matrix', 'count', 'full_catalog', 'max_parallel', 'susfs_sources'):
        prepare['outputs'].pop(key, None)
    omit = {'检查并生成矩阵', '校验旧版内核 SUSFS 映射兼容性', '验证共享源码还原及原生符号接口',
            '矩阵展开前统一下载并固定 SUSFS', '自动删除已成功的清理记录', '上传原始配套 APK'}
    prepare['steps'] = [step for step in prepare['steps'] if step.get('name') not in omit]
    source = next(step for step in prepare['steps'] if step.get('id') == 'sources')
    source['env'].pop('GH_TOKEN')
    source['env'].pop('CUSTOM_REF')
    source['env'].update(EXPECTED_REF='${{ matrix.reference }}', EXPECTED_SOURCE_BRANCH='${{ matrix.source_branch }}')
    source['run'] = '''set -euo pipefail
python3 tools/resolve_build_sources.py --variant "$KSU_VARIANT" --tier "$KSU_TIER" --susfs false \\
  --fixed-ref "$EXPECTED_REF" --fixed-source-branch "$EXPECTED_SOURCE_BRANCH"
'''
    prepare['needs'] = ['check-upstream']
    prepare['if'] = f"needs.check-upstream.result == 'success' && {DISCOVERY}pending == 'true'"
    matrix_job(prepare, 'matrix', 6)
    prepare['outputs'] = {
        slot + '_' + field: expression(f"matrix.slot == '{slot}' && ({value[4:-3]}) || ''")
        for slot in SLOTS for field, value in prepare['outputs'].items() if value
    }
    native['needs'] = ['check-upstream', 'prepare-matrix']
    native['if'] = ("!cancelled() && needs.prepare-matrix.result == 'success' && ("
                    + ' || '.join(f"(contains(fromJSON({DISCOVERY}matrix).include.*.slot, '{slot}') && "
                                  f"needs.{PREPARE}.outputs['{slot}_manager_adoption'] == '')" for slot in SLOTS)
                    + ')')
    matrix_job(native, 'lkm_matrix', 24)
    manager['name'] = '${{ matrix.variant }} · ${{ matrix.channels }} · 预编译管理器 APK'
    manager['needs'] = ['check-upstream', 'prepare-matrix', 'build-sukisu-lkm']
    manager['if'] = ("always() && !cancelled() && needs.prepare-matrix.result == 'success' && "
                     "(needs.build-sukisu-lkm.result == 'success' || needs.build-sukisu-lkm.result == 'skipped')")
    matrix_job(manager, 'matrix', len(SLOTS))
    manager['steps'] = [step for step in manager['steps'] if step.get('id') != 'manager-producer']
    manager.pop('outputs', None)
    use_native_cache(native, manager)
    return dict(zip((PREPARE, NATIVE, MANAGER), substitute([prepare, native, manager])))
