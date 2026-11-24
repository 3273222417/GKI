"""Reuse signed management APKs before expensive native and Android builds."""
from __future__ import annotations

from additional_manager_jobs import ALL_IF


CACHE_PATH = 'manager-apk-cache'
APK_FIELDS = ('manager_package', 'manager_cert_size', 'manager_cert_sha256', 'apk_sha256',
              'manager_version_name', 'manager_version_code', 'apk_filename')
ADOPTION = 'needs.prepare-matrix.outputs.manager_adoption'
SAVE_KEY = "format('{0}-{1}-{2}', needs.prepare-matrix.outputs.apk_cache_key, github.run_id, github.run_attempt)"
ELIGIBLE = ("(steps.sources.outputs.effective_ksu_branch == 'Stable(标准)' || "
            "steps.sources.outputs.effective_ksu_branch == 'Latest(最新)')")
VERSION_KEY = 'steps.apk-cache-key.outputs.apk_version_cache_key'
LEGACY_KEY = 'steps.apk-cache-key.outputs.apk_cache_key'
PREPARE_KEY = f"format('{{0}}-{{1}}-{{2}}', {VERSION_KEY} || {LEGACY_KEY}, github.run_id, github.run_attempt)"
INDEX_ADOPTED = (f"steps.adopt-apk.outputs.manager_apk_reused == 'true' && {VERSION_KEY} != '' && "
                 f"!startsWith(steps.apk-cache.outputs.cache-matched-key, format('{{0}}-', {VERSION_KEY}))")
ARGS = '''--variant "$KSU_VARIANT" --channel "$KSU_BRANCH" --ksu-ref "$KSU_REF" \\
  --cert-size "$MANAGER_CERT_SIZE" --cert-sha256 "$MANAGER_CERT_SHA256" \\
  --source-identity "$MANAGER_SOURCE_IDENTITY"'''


def expression(value):
    return '${{ ' + value + ' }}'


def gate(step, condition):
    previous = step.get('if')
    step['if'] = '(' + previous + ') && ' + condition if previous else condition


def configure(workflow):
    prepare = workflow['jobs']['prepare-matrix']
    prepare['permissions'].setdefault('actions', 'read')
    lkm = workflow['jobs']['build-sukisu-lkm']
    manager = workflow['jobs']['build-sukisu-manager']
    identity_env = {
        'KSU_BRANCH': expression('steps.sources.outputs.effective_ksu_branch'),
        'KSU_REF': expression('steps.sources.outputs.ksu_ref'),
        'KSU_PACKAGE_NAME': expression('steps.certificate.outputs.package'),
        'MANAGER_CERT_SIZE': expression('steps.certificate.outputs.cert_size'),
        'MANAGER_CERT_SHA256': expression('steps.certificate.outputs.cert_sha256'),
        'MANAGER_SOURCE_IDENTITY': expression('steps.source-identity.outputs.source_identity'),
    }
    index = next(i for i, step in enumerate(prepare['steps']) if step.get('id') == 'source-identity') + 1
    prepare['steps'][index:index] = [
        {'name': '按管理器版本定位已编译 APK', 'id': 'apk-cache-key', 'if': ALL_IF + ' && ' + ELIGIBLE,
         'env': identity_env, 'run': 'set -euo pipefail\npython3 tools/reusable_manager_apk.py key ' + ARGS
                + '\npython3 tools/restore_prebuilt_manager_apk.py --write-version-key ' + ARGS
                + ' --source-dir ksu-snapshot-source'},
        {'name': '直接读取匹配版本的已编译 APK', 'id': 'apk-cache', 'uses': 'actions/cache/restore@v5',
         'if': "steps.apk-cache-key.outputs.apk_cache_key != ''", 'timeout-minutes': 2,
         'continue-on-error': True,
         'with': {'path': CACHE_PATH,
                  'key': expression(PREPARE_KEY),
                  'restore-keys': expression(f"{VERSION_KEY} != '' && format('{{0}}-', {VERSION_KEY}) || ''")
                                  + '\n' + expression(f"format('{{0}}-', {LEGACY_KEY})")}},
        {'name': '核验已编译 APK 并保留原始编译记录', 'id': 'adopt-apk',
         'if': "steps.apk-cache-key.outputs.apk_cache_key != ''", 'timeout-minutes': 4,
         'continue-on-error': True,
         'env': {**identity_env, 'GH_TOKEN': '${{ github.token }}',
                 'DEFAULT_BRANCH': '${{ github.event.repository.default_branch }}'},
         'run': "python3 -c 'import cryptography' || python3 -m pip install --break-system-packages --disable-pip-version-check cryptography\n"
                'python3 tools/restore_prebuilt_manager_apk.py ' + ARGS
                + ' --cache-dir ' + CACHE_PATH + ' --output-dir manager-artifact'
                  ' --source-dir ksu-snapshot-source --branch "$DEFAULT_BRANCH"'},
        {'name': '上传原始配套 APK', 'uses': 'actions/upload-artifact@v7',
         'if': "steps.adopt-apk.outputs.manager_apk_reused == 'true'",
         'with': {'path': 'manager-artifact/${{ steps.adopt-apk.outputs.apk_filename }}',
                  'archive': False, 'if-no-files-found': 'error', 'overwrite': True}},
        {'name': '整理已核验的 APK 以便下次按版本读取', 'if': INDEX_ADOPTED, 'continue-on-error': True,
         'env': {'APK_FILENAME': expression('steps.adopt-apk.outputs.apk_filename')},
         'run': 'set -euo pipefail\nrm -rf -- ' + CACHE_PATH + '\nmkdir -p ' + CACHE_PATH
                + '\ncp -- "manager-artifact/$APK_FILENAME" ' + CACHE_PATH + '/\n'},
        {'name': '保存已核验 APK 的版本缓存', 'uses': 'actions/cache/save@v5', 'if': INDEX_ADOPTED,
         'continue-on-error': True, 'timeout-minutes': 2,
         'with': {'path': CACHE_PATH, 'key': expression(PREPARE_KEY)}},
    ]
    prepare['outputs']['manager_recipe_sha256'] = expression('steps.apk-cache-key.outputs.manager_recipe_sha256')
    prepare['outputs']['apk_cache_key'] = expression(f'{VERSION_KEY} || {LEGACY_KEY}')
    prepare['outputs']['manager_adoption'] = expression('steps.adopt-apk.outputs.manager_adoption')
    for field in APK_FIELDS:
        prepare['outputs']['reused_' + field] = expression('steps.adopt-apk.outputs.' + field)
        manager['outputs'][field] = expression('steps.sign.outputs.' + field + ' || needs.prepare-matrix.outputs.reused_' + field)
    manager['outputs']['manager_metadata'] = expression(ADOPTION)
    cold = ADOPTION + " == ''"
    lkm['if'] = '(' + lkm['if'] + ') && ' + cold
    lkm_success = "needs.build-sukisu-lkm.result == 'success'"
    manager['if'] = manager['if'].replace(lkm_success,
        '(' + lkm_success + ' || (' + ADOPTION + " != '' && needs.build-sukisu-lkm.result == 'skipped'))")
    for step in lkm['steps']:
        gate(step, cold)
    for step in manager['steps']:
        if step.get('id') != 'manager-producer' and step.get('uses') != 'actions/checkout@v6':
            gate(step, cold)
    sign = next(step for step in manager['steps'] if step.get('id') == 'sign')
    sign['env']['MANAGER_RECIPE_SHA256'] = expression('needs.prepare-matrix.outputs.manager_recipe_sha256')
    sign['env']['MANAGER_SOURCE_IDENTITY'] = expression('needs.prepare-matrix.outputs.source_identity')
    sign['run'] = '''set -euo pipefail
proof=()
if [ -n "$MANAGER_RECIPE_SHA256" ]; then
  proof+=(--manager-recipe-sha256 "$MANAGER_RECIPE_SHA256"
    --source-identity "$MANAGER_SOURCE_IDENTITY"
    --module-report "$RUNNER_TEMP/manager-lkm-stage.json"
    --boot-report "$RUNNER_TEMP/manager-boot-patch-check/verification.json")
fi
''' + sign['run'].rstrip() + ' "${proof[@]}"\n'
    upload = next(i for i, step in enumerate(manager['steps']) if step.get('name') == '上传管理器安装包') + 1
    cache_needed = "steps.sign.outcome == 'success' && needs.prepare-matrix.outputs.apk_cache_key != ''"
    manager['steps'][upload:upload] = [
        {'name': '暂存本次验证通过的原始 APK', 'if': cache_needed,
         'env': {'APK_FILENAME': '${{ steps.sign.outputs.apk_filename }}'},
         'run': 'set -euo pipefail\nmkdir -p ' + CACHE_PATH + '\ncp -- "manager-artifact/$APK_FILENAME" ' + CACHE_PATH + '/\n'},
        {'name': '保存可供后续内核构建复用的 APK', 'uses': 'actions/cache/save@v5', 'if': cache_needed,
         'continue-on-error': True, 'timeout-minutes': 2,
         'with': {'path': CACHE_PATH, 'key': expression(SAVE_KEY)}},
    ]
    return workflow
