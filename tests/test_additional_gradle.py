"""Keep native signing and resolve Next plugins through official repositories."""
from pathlib import Path
import shutil
import sys
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from prepare_additional_gradle import next_plugin_repositories, prepare


SETTINGS = '''@file:Suppress("UnstableApiUsage")

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

pluginManagement {
    repositories {
        google()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven("https://jitpack.io")
    }
}

rootProject.name = "KernelSU-Next"
include(":app")
'''
APP = '''plugins {
    alias(libs.plugins.agp.app)
    alias(libs.plugins.lsplugin.apksign)
}
apksign {
    storeFileProperty = "KEYSTORE_FILE"
    storePasswordProperty = "KEYSTORE_PASSWORD"
    keyAliasProperty = "KEY_ALIAS"
    keyPasswordProperty = "KEY_PASSWORD"
}
android {
    buildTypes {
        release {
            isMinifyEnabled = true
        }
    }
    defaultConfig {
        ndk { abiFilters += listOf("arm64-v8a", "x86_64", "riscv64") }
    }
}
'''


class AdditionalGradleTests(unittest.TestCase):
    def setUp(self):
        self.source = ROOT / 'tests' / ('.additional-gradle-' + uuid.uuid4().hex)
        app = self.source / 'manager/app'
        app.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.source)
        self.app = app / 'build.gradle.kts'
        self.app.write_text(APP, encoding='utf-8')
        self.settings = self.source / 'manager/settings.gradle.kts'
        self.settings.write_text(SETTINGS, encoding='utf-8')

    def test_next_keeps_native_package_architectures_and_official_versions(self):
        root_build = self.source / 'manager/build.gradle.kts'
        original_build = 'plugins { id("org.jetbrains.kotlin.android") version "2.2.0" apply false }\n'
        root_build.write_text(original_build, encoding='utf-8')
        prepare(self.source, 'KernelSU-Next')
        self.assertEqual(SETTINGS.replace('        mavenCentral()\n',
                                         '        mavenCentral()\n        gradlePluginPortal()\n', 1),
                         self.settings.read_text(encoding='utf-8'))
        self.assertEqual(original_build, root_build.read_text(encoding='utf-8'))
        actual = self.app.read_text(encoding='utf-8')
        self.assertIn('applicationId = "com.rifsxd.ksunext"', actual)
        self.assertIn('signingConfig = null', actual)
        self.assertIn('abiFilters += listOf("arm64-v8a", "x86_64", "riscv64")', actual)
        self.assertNotIn('lsplugin.apksign', actual)

    def test_existing_portal_is_kept_once_and_dependency_repositories_are_untouched(self):
        updated = next_plugin_repositories(SETTINGS)
        self.assertEqual(updated, next_plugin_repositories(updated))
        self.assertEqual(1, updated.count('gradlePluginPortal()'))
        self.assertEqual(SETTINGS.partition('dependencyResolutionManagement')[2],
                         updated.partition('dependencyResolutionManagement')[2])

    def test_other_native_managers_do_not_require_or_rewrite_next_settings(self):
        for variant in ('KernelSU', 'KowSU'):
            with self.subTest(variant=variant):
                self.app.write_text(APP, encoding='utf-8')
                prepare(self.source, variant)
                self.assertEqual(SETTINGS, self.settings.read_text(encoding='utf-8'))

    def test_changed_plugin_structure_fails_before_signing_rewrite(self):
        for changed in (SETTINGS.replace('pluginManagement', 'futureManagement'),
                        SETTINGS.replace('        mavenCentral()\n', '', 1),
                        SETTINGS.replace('        mavenCentral()\n', '        mavenCentral()\n        mavenCentral()\n', 1)):
            with self.subTest(changed=changed):
                self.settings.write_text(changed, encoding='utf-8')
                with self.assertRaises(ValueError):
                    prepare(self.source, 'KernelSU-Next')
                self.assertEqual(APP, self.app.read_text(encoding='utf-8'))
                self.assertEqual(changed, self.settings.read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
