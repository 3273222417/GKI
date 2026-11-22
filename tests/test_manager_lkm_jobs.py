"""Validate pinned DDK selection, cache acceleration and artifact handoff."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import sys
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import manager_lkm_jobs as jobs


def github_exact_file_hash(root: Path, paths: list[str]) -> str:
    """The hashFiles algorithm for this key's two exact paths, in argument order.

    @actions/glob hashes each matched file, then SHA256s those binary digests:
    https://github.com/actions/toolkit/blob/main/packages/glob/src/internal-hash-files.ts
    No wildcard/ancestor traversal is involved in these two production inputs.
    """
    combined, matches = hashlib.sha256(), 0
    seen = set()
    for relative in dict.fromkeys(paths):
        for path in sorted(root.glob(relative)):
            if not path.is_file() or path in seen:
                continue
            seen.add(path)
            combined.update(hashlib.sha256(path.read_bytes()).digest())
            matches += 1
    return combined.hexdigest() if matches else ''


def render_key(template, *, root=ROOT, **changes):
    values = {'runner.os': 'Linux', 'runner.arch': 'X64',
              'needs.prepare-matrix.outputs.ksu_ref': 'a' * 40,
              'needs.prepare-matrix.outputs.native_source_version': 'd' * 16,
              'needs.prepare-matrix.outputs.manager_package': 'com.sukisu.ultra',
              'needs.prepare-matrix.outputs.manager_cert_size': '730',
              'needs.prepare-matrix.outputs.manager_cert_sha256': 'b' * 64,
              'matrix.kmi': 'android12-5.10', 'matrix.ddk_short': 'c' * 16,
              'inputs.kernelsu_variant': 'SukiSU'}
    values.update(changes)
    def replace(match):
        expression = match[1].strip()
        native = re.fullmatch(r"format\('-native-\{0\}', hashFiles\((.*?)\)\)", expression)
        if native:
            return '-native-' + github_exact_file_hash(Path(root), re.findall(r"'([^']+)'", native[1]))
        port = re.fullmatch(r"inputs\.kernelsu_variant == 'BakaSU' && "
                            r"format\('-kpm-\{0\}', hashFiles\((.*?)\)\) \|\| ''", expression)
        if port:
            paths = re.findall(r"'([^']+)'", port[1])
            if ', '.join(repr(path) for path in paths) != port[1]:
                raise ValueError('Unsupported hashFiles path expression in the actual cache key')
            return ('-kpm-' + github_exact_file_hash(Path(root), paths)
                    if values['inputs.kernelsu_variant'] == 'BakaSU' else '')
        extra = re.fullmatch(r"inputs\.kernelsu_variant != 'SukiSU' && inputs\.kernelsu_variant != 'BakaSU' && "
                             r"format\('-kpm-\{0\}', hashFiles\((.*?)\)\) \|\| ''", expression)
        if extra:
            paths = re.findall(r"'([^']+)'", extra[1])
            if ', '.join(repr(path) for path in paths) != extra[1]:
                raise ValueError('Unsupported additional port hash expression')
            return ('-kpm-' + github_exact_file_hash(Path(root), paths)
                    if values['inputs.kernelsu_variant'] not in ('SukiSU', 'BakaSU') else '')
        return expression[1:-1] if expression.startswith("'") and expression.endswith("'") else values[expression]
    return re.sub(r'\$\{\{(.*?)\}\}', replace, template)


class ManagerLkmJobTests(unittest.TestCase):
    def setUp(self):
        self.directory = ROOT / 'tests' / ('.lkm-jobs-' + uuid.uuid4().hex)
        (self.directory / 'config').mkdir(parents=True)
        (self.directory / 'tools').mkdir()
        for name in ('build_manager_extras.sh', 'build_manager_extras_container.sh', 'manager_full_native.py'):
            shutil.copyfile(ROOT / 'tools' / name, self.directory / 'tools' / name)
        self.addCleanup(shutil.rmtree, self.directory)
        self.lock = {'schema_version': 1, 'images': [
            {'kmi': kmi, 'tag': f'ghcr.io/ylarod/ddk-min:{kmi}-20260828',
             'image': 'ghcr.io/ylarod/ddk-min@sha256:' + str(index) * 64,
             'kernel_release': kmi.split('-')[1] + '.123-dirty'}
            for index, kmi in enumerate(jobs.KMIS, 1)]}
        self.path = self.directory / 'config' / 'manager-ddk-images.json'

    def write_lock(self, document=None):
        self.path.write_text(json.dumps(self.lock if document is None else document), encoding='utf-8')

    def test_partial_native_cache_cleanup_removes_only_selected_kmi_before_rebuild(self):
        parent = self.directory / 'manager-lkm'
        partial = parent / jobs.KMIS[0]
        (partial / 'extras/x86_64').mkdir(parents=True)
        (partial / 'module.json').write_bytes(b'{incomplete cache manifest')
        (partial / (jobs.KMIS[0] + '_kernelsu.ko')).write_bytes(b'partial module')
        (partial / 'extras/x86_64/partial.ko').write_bytes(b'partial extra')
        sibling = parent / jobs.KMIS[1]
        sibling.mkdir()
        (sibling / 'module.json').write_bytes(b'preserve sibling metadata')
        (sibling / 'complete.ko').write_bytes(b'preserve sibling module')
        before = {p.relative_to(sibling): p.read_bytes() for p in sibling.rglob('*') if p.is_file()}

        jobs.clear_partial_native_output(self.directory, jobs.KMIS[0])

        self.assertFalse(partial.exists())
        self.assertEqual(before, {p.relative_to(sibling): p.read_bytes() for p in sibling.rglob('*') if p.is_file()})
        self.assertTrue((self.directory / 'tools/build_manager_extras.sh').is_file())

    def test_partial_native_cache_cleanup_is_harmless_when_output_is_absent(self):
        jobs.clear_partial_native_output(self.directory, jobs.KMIS[0])
        self.assertFalse((self.directory / 'manager-lkm').exists())
        parent = self.directory / 'manager-lkm'
        parent.mkdir()
        marker = parent / 'untouched.txt'
        marker.write_bytes(b'keep')
        jobs.clear_partial_native_output(self.directory, jobs.KMIS[0])
        self.assertEqual(b'keep', marker.read_bytes())

    def test_partial_native_cache_cleanup_rejects_illegal_kmis_and_regular_file_targets(self):
        marker = self.directory / 'do-not-delete'
        marker.write_bytes(b'caller-owned')
        external = self.directory.parent / ('.lkm-keep-external-' + uuid.uuid4().hex)
        external.write_bytes(b'external caller-owned')
        self.addCleanup(external.unlink, missing_ok=True)
        for kmi in ('', '..', '../do-not-delete', 'android99-99.99', jobs.KMIS[0] + '/..',
                    jobs.KMIS[0] + '\n', str(external), '../../' + external.name, None):
            with self.subTest(kmi=kmi), self.assertRaises(ValueError):
                jobs.clear_partial_native_output(self.directory, kmi)
            self.assertEqual(b'caller-owned', marker.read_bytes())
            self.assertEqual(b'external caller-owned', external.read_bytes())
        target = self.directory / 'manager-lkm' / jobs.KMIS[0]
        target.parent.mkdir()
        target.write_bytes(b'not a directory')
        with self.assertRaisesRegex(ValueError, 'not a directory'):
            jobs.clear_partial_native_output(self.directory, jobs.KMIS[0])
        self.assertEqual(b'not a directory', target.read_bytes())

    def linked_native_output(self, *, parent_link):
        outside = self.directory.parent / ('.lkm-external-' + uuid.uuid4().hex)
        outside.mkdir()
        self.addCleanup(shutil.rmtree, outside)
        (outside / jobs.KMIS[0]).mkdir()
        marker = outside / jobs.KMIS[0] / 'outside.ko'
        marker.write_bytes(b'external module must survive')
        parent = self.directory / 'manager-lkm'
        if parent_link:
            link, destination = parent, outside
        else:
            parent.mkdir()
            link, destination = parent / jobs.KMIS[0], outside / jobs.KMIS[0]
        try:
            link.symlink_to(destination, target_is_directory=True)
        except (OSError, NotImplementedError) as error:
            self.skipTest('Directory symlinks are unavailable on this platform: ' + type(error).__name__)
        self.addCleanup(link.unlink, missing_ok=True)
        self.assertFalse((parent / jobs.KMIS[0]).resolve().is_relative_to(self.directory.resolve()))
        with self.assertRaisesRegex(ValueError, 'linked'):
            jobs.clear_partial_native_output(self.directory, jobs.KMIS[0])
        self.assertTrue(link.is_symlink())
        self.assertEqual(b'external module must survive', marker.read_bytes())

    def test_partial_native_cache_cleanup_rejects_target_symlink_without_deleting_external_files(self):
        self.linked_native_output(parent_link=False)

    def test_partial_native_cache_cleanup_rejects_parent_symlink_without_deleting_external_files(self):
        self.linked_native_output(parent_link=True)

    def test_partial_cleanup_runs_only_on_cache_miss_before_compilation_or_recording(self):
        steps = jobs.manager_lkm_job('true')['steps']
        build = next(step for step in steps if 'docker run' in step.get('run', ''))
        hit = next(step for step in steps if step['name'] == '核实已缓存的原生模块')
        self.assertIn("cache-hit != 'true'", build['if'])
        self.assertIn("cache-hit == 'true'", hit['if'])
        self.assertNotIn('clear_partial_native_output', hit['run'])
        self.assertNotIn('continue-on-error', hit)
        self.assertLess(build['run'].index('clear_partial_native_output(Path.cwd()'),
                        build['run'].index('prepare_manager_lkm.py version-code'))
        self.assertLess(build['run'].index('clear_partial_native_output(Path.cwd()'),
                        build['run'].index('prepare_manager_lkm.py record'))

    def test_loader_preserves_all_eight_official_kmis_and_derives_digest_from_image(self):
        self.lock['images'].reverse()
        self.write_lock()
        matrix = jobs.load_ddk_matrix(self.directory)
        self.assertEqual(jobs.KMIS, tuple(row['kmi'] for row in matrix))
        for row in matrix:
            self.assertEqual({'kmi', 'image', 'ddk_short', 'kernel_release'}, set(row))
            self.assertEqual(row['image'].split('@sha256:')[1][:16], row['ddk_short'])
        # The actual checked-in lock is also usable without unpinned tag lookups.
        self.assertEqual(8, len(jobs.load_ddk_matrix(ROOT)))

    def test_loader_refuses_incomplete_duplicate_unknown_or_mutable_images(self):
        examples = []
        incomplete = copy.deepcopy(self.lock)
        incomplete['images'].pop()
        examples.append(incomplete)
        duplicate = copy.deepcopy(self.lock)
        duplicate['images'][1] = duplicate['images'][0]
        examples.append(duplicate)
        for field, value in (
            ('kmi', 'android99-99.99'), ('image', 'ghcr.io/ylarod/ddk-min:latest'),
            ('image', 'evil.example/ddk-min@sha256:' + 'a' * 64),
            ('image', 'ghcr.io/ylarod/ddk-min@sha256:' + 'a' * 63),
            ('image', 'ghcr.io/ylarod/ddk-min@sha256:' + 'A' * 64),
            ('image', 'ghcr.io/ylarod/ddk-min@sha256:' + 'a' * 64 + '\n'),
            ('tag', 'ghcr.io/ylarod/ddk-min:android15-6.6-20260828'),
            ('ddk_short', 'wrong-image-key'), ('unexpected', 'ignored configuration'),
            ('kernel_release', ''), ('kernel_release', None), ('kernel_release', '5.15.123'),
            ('kernel_release', '5.10.123 SMP'), ('kernel_release', '5.10.123\n'),
            ('kernel_release', '5.10.123/unsafe'), ('kernel_release', '5.10.123-' + 'a' * 64),
        ):
            document = copy.deepcopy(self.lock)
            document['images'][0][field] = value
            examples.append(document)
        for document in examples:
            with self.subTest(document=document):
                self.write_lock(document)
                with self.assertRaises(ValueError):
                    jobs.load_ddk_matrix(self.directory)

    def test_loader_refuses_unknown_schema_missing_or_unbounded_lock(self):
        with self.assertRaises(ValueError):
            jobs.load_ddk_matrix(self.directory)
        for document in ([], {'schema_version': True, 'images': []},
                         {'schema_version': 2, 'images': []}, {'schema_version': 1, 'images': {}}):
            self.write_lock(document)
            with self.assertRaises(ValueError):
                jobs.load_ddk_matrix(self.directory)
        self.path.write_text('x' * 32769)
        with self.assertRaises(ValueError):
            jobs.load_ddk_matrix(self.directory)

    def test_cache_key_matches_fixed_consumer_and_changes_with_every_native_identity(self):
        template = jobs.lkm_cache_key('matrix.kmi', 'matrix.ddk_short')
        baseline = render_key(template)
        self.assertTrue(baseline.startswith('gki-sukisu-lkm-v3-full-'))
        fixed = jobs.lkm_cache_key("'android12-5.10'", "'" + 'c' * 16 + "'")
        self.assertEqual(baseline, render_key(fixed))
        self.assertLess(len(baseline), 512)
        for field, value in (
            ('needs.prepare-matrix.outputs.ksu_ref', 'd' * 40),
            ('needs.prepare-matrix.outputs.native_source_version', 'e' * 16),
            ('needs.prepare-matrix.outputs.manager_package', 'com.example.changed'),
            ('needs.prepare-matrix.outputs.manager_cert_size', '731'),
            ('needs.prepare-matrix.outputs.manager_cert_sha256', 'e' * 64),
            ('matrix.kmi', 'android13-5.15'), ('matrix.ddk_short', 'f' * 16),
            ('runner.arch', 'ARM64'), ('runner.os', 'Windows'),
        ):
            with self.subTest(field=field):
                self.assertNotEqual(baseline, render_key(template, **{field: value}))
        for bad in ('', '${{ matrix.kmi }}', 'matrix.kmi\nignored'):
            with self.assertRaises(ValueError):
                jobs.lkm_cache_key(bad, 'matrix.ddk_short')

    def test_full_sukisu_cache_requires_native_builder_identity_without_a_baka_port(self):
        template = jobs.lkm_cache_key('matrix.kmi', 'matrix.ddk_short')
        expected = ('gki-sukisu-lkm-v3-full-Linux-X64-' + 'a' * 40 + '-' + 'd' * 16 + '-com.sukisu.ultra-730-'
                    + 'b' * 64 + '-android12-5.10-' + 'c' * 16)
        native = github_exact_file_hash(ROOT, ['tools/build_manager_extras*.sh', 'tools/manager_full_native.py'])
        self.assertEqual(expected + '-native-' + native, render_key(template))

    def test_bakasu_port_bytes_invalidate_its_old_cache_without_changing_source_or_cert(self):
        patch_file = self.directory / 'tools/patches/bakasu-kpm.patch'
        patch_file.parent.mkdir(parents=True)
        port_lock = self.directory / 'config/bakasu-kpm-port.json'
        patch_file.write_bytes(b'audited-port-patch-A\n')
        port_lock.write_bytes(b'{"reviewed_port": 1}\n')
        identity = {'inputs.kernelsu_variant': 'BakaSU',
                    'needs.prepare-matrix.outputs.manager_package': 'com.resukisu.resukisu'}
        template = jobs.lkm_cache_key('matrix.kmi', 'matrix.ddk_short')
        fixed = jobs.lkm_cache_key("'android12-5.10'", "'" + 'c' * 16 + "'")
        old = ('gki-sukisu-lkm-v3-full-Linux-X64-' + 'a' * 40 + '-' + 'd' * 16 + '-com.resukisu.resukisu-730-'
               + 'b' * 64 + '-android12-5.10-' + 'c' * 16)
        digest = hashlib.sha256(hashlib.sha256(patch_file.read_bytes()).digest()
                                + hashlib.sha256(port_lock.read_bytes()).digest()).hexdigest()
        baseline = render_key(template, root=self.directory, **identity)
        native = github_exact_file_hash(ROOT, ['tools/build_manager_extras*.sh', 'tools/manager_full_native.py'])
        self.assertEqual(old + '-native-' + native + '-kpm-' + digest, baseline)
        self.assertEqual(baseline, render_key(fixed, root=self.directory, **identity))
        self.assertNotEqual(old, baseline)
        for path in (patch_file, port_lock):
            before = path.read_bytes()
            path.write_bytes(before + b'changed')
            with self.subTest(path=path.name):
                self.assertNotEqual(baseline, render_key(template, root=self.directory, **identity))
                self.assertEqual(render_key(template), render_key(template, root=self.directory))
            path.write_bytes(before)

    def test_port_key_retains_all_native_identities_and_stays_within_cache_byte_limit(self):
        template = jobs.lkm_cache_key('matrix.kmi', 'matrix.ddk_short')
        for variant, package in (('SukiSU', 'com.sukisu.ultra'), ('BakaSU', 'com.resukisu.resukisu')):
            identity = {'inputs.kernelsu_variant': variant,
                        'needs.prepare-matrix.outputs.manager_package': package,
                        'needs.prepare-matrix.outputs.manager_cert_size': '4096',
                        'runner.os': 'Windows', 'runner.arch': 'ARM64'}
            baseline = render_key(template, **identity)
            for field, value in (('needs.prepare-matrix.outputs.ksu_ref', 'd' * 40),
                                 ('needs.prepare-matrix.outputs.manager_cert_sha256', 'e' * 64),
                                 ('needs.prepare-matrix.outputs.manager_cert_size', '730'),
                                 ('matrix.ddk_short', 'f' * 16)):
                with self.subTest(variant=variant, field=field):
                    self.assertNotEqual(baseline, render_key(template, **{**identity, field: value}))
            for kmi in jobs.KMIS:
                value = render_key(template, **{**identity, 'matrix.kmi': kmi})
                self.assertLessEqual(len(value.encode('utf-8')), 512)

    def test_producer_cache_accelerates_verified_same_run_artifact_publication(self):
        job = jobs.manager_lkm_job('supplied-condition')
        self.assertEqual('supplied-condition', job['if'])
        self.assertEqual('prepare-matrix', job['needs'])
        self.assertEqual({'contents': 'read'}, job['permissions'])
        self.assertEqual('ubuntu-24.04', job['runs-on'])
        self.assertNotIn('container', job)
        self.assertEqual(8, job['strategy']['max-parallel'])
        self.assertFalse(job['strategy']['fail-fast'])
        self.assertEqual('${{ fromJSON(needs.prepare-matrix.outputs.ddk_matrix) }}', job['strategy']['matrix'])
        steps = job['steps']
        caches = [step for step in steps if step.get('uses', '').startswith('actions/cache/')
                  and step.get('with', {}).get('path', '').startswith('manager-lkm/')]
        self.assertEqual(['actions/cache/restore@v5', 'actions/cache/save@v5'], [s['uses'] for s in caches])
        for step in caches:
            self.assertTrue(step['continue-on-error'])
            self.assertNotIn('restore-keys', step['with'])
            self.assertNotIn('lookup-only', step['with'])
            self.assertEqual('manager-lkm/${{ matrix.kmi }}', step['with']['path'])
            self.assertEqual(jobs.lkm_cache_key('matrix.kmi', 'matrix.ddk_short'), step['with']['key'])
        publications = [step for step in steps if step.get('uses') == 'actions/upload-artifact@v7']
        self.assertEqual(1, len(publications))
        publication = publications[0]
        self.assertIs(publication, steps[-1])
        self.assertNotIn('if', publication)  # Publish cache hits as well as fresh builds.
        self.assertNotIn('continue-on-error', publication)
        self.assertEqual(jobs.lkm_artifact_name('matrix.kmi', 'matrix.ddk_short'), publication['with']['name'])
        self.assertEqual('manager-lkm/${{ matrix.kmi }}', publication['with']['path'])
        self.assertEqual(1, publication['with']['retention-days'])
        self.assertEqual(1, publication['with']['compression-level'])
        self.assertTrue(publication['with']['overwrite'])
        self.assertEqual('error', publication['with']['if-no-files-found'])
        self.assertTrue(publication['with'].get('archive', True))
        self.assertFalse(any('lkm-published' in step.get('id', '') for step in steps))
        self.assertFalse(steps[0]['with']['persist-credentials'])
        hit = next(step for step in steps if '--expected-kmis "$KMI"' in step.get('run', ''))
        build = next(step for step in steps if 'docker run' in step.get('run', ''))
        extras = next(step for step in steps if 'bash tools/build_manager_extras.sh' in step.get('run', ''))
        self.assertIn("cache-hit == 'true'", hit['if'])
        self.assertIn('prepare_manager_lkm.py stage', hit['run'])
        self.assertIn('manager_full_native.py stage', hit['run'])
        self.assertIn("cache-hit != 'true'", build['if'])
        self.assertIn("cache-hit != 'true'", caches[1]['if'])
        self.assertLess(steps.index(hit), steps.index(publication))
        self.assertLess(steps.index(build), steps.index(extras))
        self.assertLess(steps.index(extras), steps.index(caches[1]))
        self.assertLess(steps.index(caches[1]), steps.index(publication))

    def test_artifact_name_binds_every_native_identity_without_runner_local_fields(self):
        template = jobs.lkm_artifact_name('matrix.kmi', 'matrix.ddk_short')
        baseline = render_key(template)
        self.assertEqual('internal-manager-native-SukiSU-' + 'a' * 40 + '-' + 'd' * 16
                         + '-android12-5.10-' + 'c' * 16 + '-' + 'b' * 64, baseline)
        for field, value in (
            ('inputs.kernelsu_variant', 'KowSU'), ('needs.prepare-matrix.outputs.ksu_ref', 'f' * 40),
            ('needs.prepare-matrix.outputs.native_source_version', 'e' * 16),
            ('matrix.kmi', 'android13-5.15'), ('matrix.ddk_short', 'a' * 16),
            ('needs.prepare-matrix.outputs.manager_cert_sha256', 'c' * 64),
        ):
            with self.subTest(field=field):
                self.assertNotEqual(baseline, render_key(template, **{field: value}))
        self.assertEqual(baseline, render_key(template, **{'runner.os': 'Windows', 'runner.arch': 'ARM64'}))
        for bad in ('', '${{ matrix.kmi }}', 'matrix.kmi\nignored'):
            with self.assertRaises(ValueError):
                jobs.lkm_artifact_name(bad, 'matrix.ddk_short')

    def test_artifact_download_is_exact_same_run_and_fails_closed(self):
        artifact = jobs.lkm_artifact_name("'android12-5.10'", "'" + 'c' * 16 + "'")
        step = jobs.lkm_artifact_download_step(artifact, 'manager-lkm/android12-5.10', name='Read module')
        self.assertEqual('actions/download-artifact@v8', step['uses'])
        self.assertEqual('Read module', step['name'])
        self.assertEqual({'name': artifact, 'path': 'manager-lkm/android12-5.10'}, step['with'])
        self.assertNotIn('if', step)
        self.assertNotIn('continue-on-error', step)
        self.assertNotIn('env', step)
        optional = jobs.lkm_artifact_download_step(artifact, 'manager-lkm/android12-5.10',
                                                 name='Read module', condition='inputs.build_manager')
        self.assertEqual('inputs.build_manager', optional['if'])
        for field in ('github-token', 'run-id', 'pattern', 'merge-multiple'):
            self.assertNotIn(field, step['with'])

    def test_fixed_consumers_and_matrix_producers_select_identical_artifacts(self):
        for variant in ('SukiSU', 'BakaSU', 'KernelSU-Next', 'KernelSU', 'KowSU', 'FinaSU'):
            for row in jobs.load_ddk_matrix(ROOT):
                dynamic = jobs.lkm_artifact_name('matrix.kmi', 'matrix.ddk_short')
                fixed = jobs.lkm_artifact_name(repr(row['kmi']), repr(row['ddk_short']))
                fields = {'inputs.kernelsu_variant': variant, 'matrix.kmi': row['kmi'],
                          'matrix.ddk_short': row['ddk_short']}
                with self.subTest(variant=variant, kmi=row['kmi']):
                    expected = render_key(dynamic, **fields)
                    consumer = jobs.lkm_artifact_download_step(fixed, 'manager-lkm/' + row['kmi'], name='Read module')
                    self.assertEqual(expected, render_key(consumer['with']['name'], **fields))
                    self.assertNotIn('run-id', consumer['with'])

    def test_source_uses_exact_prepared_cache_key_and_never_downloads_an_artifact(self):
        steps = jobs.manager_lkm_job('true')['steps']
        source = next(step for step in steps if step.get('with', {}).get('path') == jobs.SOURCE_BUNDLE_PATH)
        self.assertEqual('actions/cache/restore@v5', source['uses'])
        self.assertEqual('${{ needs.prepare-matrix.outputs.source_cache_key }}', source['with']['key'])
        self.assertFalse(source['with']['fail-on-cache-miss'])
        self.assertNotIn('restore-keys', source['with'])
        self.assertTrue(source['continue-on-error'])
        self.assertNotIn('actions/download-artifact', json.dumps(steps))
        verify = next(step for step in steps if 'transfer_ksu_snapshot.py verify-cache' in step.get('run', ''))
        checkout = next(step for step in steps if 'checkout_ksu_snapshot.py' in step.get('run', ''))
        self.assertLess(steps.index(source), steps.index(verify))
        self.assertLess(steps.index(verify), steps.index(checkout))
        self.assertNotIn('if', verify)
        self.assertNotIn('continue-on-error', verify)
        self.assertEqual('${{ needs.prepare-matrix.outputs.source_identity }}', verify['env']['PREPARED_SOURCE_IDENTITY'])
        self.assertIn('--source "$GITHUB_WORKSPACE/ksu-source-bundle"', verify['run'])
        self.assertIn('--prepared-identity "$PREPARED_SOURCE_IDENTITY"', verify['run'])

    def test_docker_runs_offline_in_native_ddk_context_and_receives_only_public_build_values(self):
        job = jobs.manager_lkm_job('true')
        build = next(step for step in job['steps'] if 'docker run' in step.get('run', ''))
        script = build['run']
        self.assertLess(script.index('docker pull "$DDK_IMAGE"'), script.index('docker run'))
        command = script[script.index('docker run'):script.index('python3 tools/prepare_manager_lkm.py record')]
        arguments = shlex.split(command)
        self.assertEqual('none', arguments[arguments.index('--network') + 1])
        self.assertNotIn('--user', arguments)
        self.assertNotIn('--privileged', arguments)
        self.assertEqual('/bin/bash', arguments[arguments.index('--entrypoint') + 1])
        self.assertEqual('$DDK_IMAGE', arguments[arguments.index('--entrypoint') + 2])
        passed = {arguments[index + 1].split('=', 1)[0] for index, arg in enumerate(arguments) if arg == '--env'}
        self.assertEqual({'HOME', 'KSU_PACKAGE_NAME', 'KSU_MANAGER_PACKAGE', 'KSU_VARIANT',
                          'KSU_EXPECTED_SIZE', 'KSU_EXPECTED_HASH', 'KSU_VERSION', 'MODULE_OUTPUT'}, passed)
        self.assertIn('if [ "$KSU_VARIANT" = BakaSU ]; then', arguments[-1])
        self.assertIn('CONFIG_KSU_MULTI_MANAGER_SUPPORT=y', arguments[-1])
        self.assertIn('CONFIG_KSU_TRACEPOINT_HOOK=y', arguments[-1])
        baka = arguments[-1].split('if [ "$KSU_VARIANT" = BakaSU ]; then', 1)[1].split('    fi', 1)[0]
        self.assertIn('CONFIG_KPM=y', baka)
        self.assertEqual(3, arguments[-1].count('CONFIG_KPM=y'))
        self.assertIn('KSU_NEXT_MANAGER_SIZE="$KSU_EXPECTED_SIZE"', arguments[-1])
        self.assertIn('KSU_NEXT_MANAGER_HASH="$KSU_EXPECTED_HASH"', arguments[-1])
        self.assertIn('KSU_MANAGER_PACKAGE="$KSU_MANAGER_PACKAGE"', arguments[-1])
        self.assertIn('CONFIG_KSU=m CC=clang make -j "$(nproc)"', arguments[-1])
        self.assertIn('KSU_PACKAGE_NAME="$KSU_PACKAGE_NAME"', arguments[-1])
        self.assertIn('KSU_EXPECTED_SIZE="$KSU_EXPECTED_SIZE"', arguments[-1])
        self.assertIn('KSU_EXPECTED_HASH="$KSU_EXPECTED_HASH"', arguments[-1])
        self.assertIn('KSU_VERSION="$KSU_VERSION"', arguments[-1])
        self.assertIn('git config --global --add safe.directory "$(dirname "$PWD")"', arguments[-1])
        self.assertIn('umask 022', arguments[-1])
        self.assertIn('chmod a+r "$MODULE_OUTPUT"', arguments[-1])
        self.assertIn('python3 tools/prepare_manager_lkm.py version-code', script)
        self.assertLess(script.index('prepare_manager_lkm.py version-code'), script.index('docker run'))
        self.assertLess(arguments[-1].index('make -j'), arguments[-1].index('cp kernelsu.ko'))
        self.assertLess(arguments[-1].index('cp kernelsu.ko'), arguments[-1].index('llvm-strip -d'))
        serialized = json.dumps(build)
        for private in ('secrets.', 'GITHUB_TOKEN', 'GH_TOKEN', 'SUKISU_APK_KEYSTORE', 'SUKISU_APK_PASSWORD'):
            self.assertNotIn(private, serialized)
        for private in ('SUKISU_APK_KEYSTORE', 'SUKISU_APK_PASSWORD'):
            self.assertNotIn(private, json.dumps(job))
        fallback = next(step for step in job['steps'] if 'transfer_ksu_snapshot.py restore-official' in step.get('run', ''))
        self.assertEqual(fallback['env']['GH_TOKEN'], '${{ secrets.UPSTREAM_SYNC_TOKEN || github.token }}')
        self.assertNotIn('SOURCE_BACKUP_RELEASE_ID', fallback['env'])
        self.assertNotIn('--release-id', fallback['run'])
        self.assertIn('--expected-ref "$KSU_REF"', fallback['run'])
        self.assertIn('--prepared-identity "$PREPARED_SOURCE_IDENTITY"', fallback['run'])
        self.assertEqual(job['permissions'], {'contents': 'read'})
        self.assertIn('--expected-ref "$KSU_REF"', script)
        self.assertIn('--ddk-image "$DDK_IMAGE"', script)

    def test_public_identity_step_executes_with_exact_canonical_fields_and_rejects_bad_cert(self):
        step = next(step for step in jobs.manager_lkm_job('true')['steps']
                    if step['name'] == '核实管理器公开签名身份')
        script = step['run'].split("python3 - <<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
        environment = {'MANAGER_PACKAGE': 'com.sukisu.ultra',
                       'MANAGER_CERT_SIZE': '730', 'MANAGER_CERT_SHA256': 'b' * 64}
        previous = Path.cwd()
        try:
            os.chdir(self.directory)
            with patch.dict(os.environ, environment):
                exec(compile(script, '<public-identity-step>', 'exec'), {})
            identity = json.loads(Path('manager-public-certificate.json').read_text())
            self.assertEqual({'manager_package': environment['MANAGER_PACKAGE'],
                              'manager_cert_size': '730', 'manager_cert_sha256': 'b' * 64}, identity)
            with patch.dict(os.environ, {**environment, 'MANAGER_CERT_SHA256': 'not-a-certificate-hash'}):
                with self.assertRaisesRegex(ValueError, 'actual manager'):
                    exec(compile(script, '<public-identity-step>', 'exec'), {})
        finally:
            os.chdir(previous)


if __name__ == '__main__':
    unittest.main()
