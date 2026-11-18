"""Keep menu groups explicit while every build worker has one manager."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import manager_variants as variants


class ManagerSelectionTests(unittest.TestCase):
    def test_both_reviewed_groups_expand_in_their_menu_order(self):
        expected = {
            'SukiSU + BakaSU + KernelSU-Next': ('SukiSU', 'BakaSU', 'KernelSU-Next'),
            'KowSU + KernelSU + FinaSU': ('KowSU', 'KernelSU', 'FinaSU'),
        }
        self.assertEqual(expected, variants.COMBINED_GROUPS)
        self.assertEqual(variants.COMBINED_MANAGERS,
                         variants.COMBINED_GROUPS[variants.COMBINED_SELECTION])
        for label, members in expected.items():
            with self.subTest(label=label):
                self.assertEqual(members, variants.selected_managers(label))
                self.assertEqual(3, len(set(members)))
        self.assertEqual(set(variants.MANAGERS), {item for group in expected.values() for item in group})

    def test_menu_retains_all_single_managers_and_appends_the_two_groups(self):
        self.assertEqual(tuple(variants.public_manager_selection(value) for value in
                               (*variants.MANAGERS, *variants.COMBINED_GROUPS)), variants.MANAGER_SELECTIONS)
        self.assertEqual(8, len(set(variants.MANAGER_SELECTIONS)))
        for manager in variants.MANAGERS:
            self.assertEqual((manager,), variants.selected_managers(manager))

    def test_nova_menu_names_preserve_signed_variant_and_group_order(self):
        self.assertIn('SukiSU-Nova', variants.MANAGER_SELECTIONS)
        self.assertNotIn('SukiSU', variants.MANAGER_SELECTIONS)
        self.assertEqual(('SukiSU',), variants.selected_managers('SukiSU-Nova'))
        self.assertEqual(variants.COMBINED_MANAGERS,
                         variants.selected_managers('SukiSU-Nova + BakaSU + KernelSU-Next'))

    def test_arbitrary_groups_reordering_and_invalid_types_are_rejected(self):
        for value in ('', 'KernelSU + KowSU + FinaSU', 'KowSU + KernelSU', 'SukiSU + FinaSU',
                      'KowSU + KernelSU + FinaSU + FinaSU', None, True, 1, [], {}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                variants.selected_managers(value)

    def test_groups_never_become_worker_or_package_identities(self):
        for label in variants.COMBINED_GROUPS:
            with self.subTest(label=label):
                with self.assertRaises(ValueError):
                    variants.manager_profile(label)
                with mock.patch.dict(os.environ, {'KSU_VARIANT': label}), self.assertRaises(ValueError):
                    variants.selected_variant()
        for manager in variants.MANAGERS:
            with mock.patch.dict(os.environ, {'KSU_VARIANT': manager}):
                self.assertEqual(manager, variants.selected_variant())


class NativeSukisuIdentityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.addCleanup(temporary.cleanup)
        self.source = Path(temporary.name)
        self.gradle = self.source / 'manager/app/build.gradle.kts'
        self.gradle.parent.mkdir(parents=True)
        self.kbuild = self.source / 'kernel/Kbuild'
        self.kbuild.parent.mkdir()

    def source_identity(self, package, name):
        self.gradle.write_text(
            f'val defaultManagerPackageName = if (isPrBuild) "{package}.pr" else "{package}"\n'
            'val managerPackageName = project.findProperty("KSU_PACKAGE_NAME")?.toString() ?: defaultManagerPackageName\n'
            f'namespace = "{package}"\napplicationId = managerPackageName\n', encoding='utf-8')
        self.kbuild.write_text('REPO_NAME := ' + name + '\n', encoding='utf-8')

    def test_nova_native_package_accepts_both_official_project_names(self):
        for name in ('SukiSU-Nova', 'SukiSU'):
            with self.subTest(name=name):
                self.source_identity(variants.SUKISU_NOVA_PACKAGE, name)
                self.assertEqual(variants.SUKISU_NOVA_PACKAGE,
                                 variants.manager_source_package('SukiSU', self.source))

    def test_ultra_identity_remains_separate_from_both_nova_names(self):
        self.source_identity(variants.SUKISU_ULTRA_PACKAGE, 'SukiSU-Ultra')
        self.assertEqual(variants.SUKISU_ULTRA_PACKAGE,
                         variants.manager_source_package('SukiSU', self.source))
        for package, name in ((variants.SUKISU_ULTRA_PACKAGE, 'SukiSU'),
                              (variants.SUKISU_ULTRA_PACKAGE, 'SukiSU-Nova'),
                              (variants.SUKISU_NOVA_PACKAGE, 'SukiSU-Ultra'),
                              (variants.SUKISU_NOVA_PACKAGE, 'Unreviewed-SukiSU')):
            with self.subTest(package=package, name=name):
                self.source_identity(package, name)
                with self.assertRaisesRegex(ValueError, 'identity disagree'):
                    variants.manager_source_package('SukiSU', self.source)

    def test_new_project_name_cannot_bypass_package_namespace_or_duplicate_name_checks(self):
        self.source_identity('com.example.manager', 'SukiSU')
        with self.assertRaisesRegex(ValueError, 'Application ID'):
            variants.manager_source_package('SukiSU', self.source)
        self.source_identity(variants.SUKISU_NOVA_PACKAGE, 'SukiSU')
        self.gradle.write_text(self.gradle.read_text().replace('namespace = "com.sukisu.nova"',
                                                              'namespace = "com.sukisu.ultra"'), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'package declarations'):
            variants.manager_source_package('SukiSU', self.source)
        self.source_identity(variants.SUKISU_NOVA_PACKAGE, 'SukiSU')
        self.kbuild.write_text(self.kbuild.read_text() + 'REPO_NAME := SukiSU-Nova\n', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'identity disagree'):
            variants.manager_source_package('SukiSU', self.source)


if __name__ == '__main__':
    unittest.main()
