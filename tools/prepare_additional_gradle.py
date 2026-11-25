"""Keep the full official ABI configuration and native package IDs."""
import argparse
from pathlib import Path
import re
from manager_variants import ADDITIONAL_MANAGERS, manager_profile


def next_plugin_repositories(text: str) -> str:
    """Keep Next's repositories and add the official plugin marker fallback."""
    blocks = list(re.finditer(r'(?m)^pluginManagement[ \t]*\{\n[ \t]+repositories[ \t]*\{\n'
                              r'(?P<repositories>[^{}]*)^[ \t]+\}\n\}', text))
    if len(blocks) != 1:
        raise ValueError('Review changed upstream plugin repository configuration')
    block = blocks[0]
    repositories = block['repositories']
    if re.search(r'(?m)^[ \t]*gradlePluginPortal\(\)[ \t]*$', repositories):
        return text
    central = list(re.finditer(r'(?m)^([ \t]*)mavenCentral\(\)[ \t]*$', repositories))
    if len(central) != 1:
        raise ValueError('Expected one official Maven Central plugin repository')
    position = block.start('repositories') + central[0].end()
    return text[:position] + '\n' + central[0][1] + 'gradlePluginPortal()' + text[position:]


def prepare(source: Path, variant: str):
    if variant not in ADDITIONAL_MANAGERS:
        raise ValueError('Expected one additional source-built manager')
    app = source / 'manager/app/build.gradle.kts'
    text = app.read_text(encoding='utf-8')
    plugin = re.compile(r'^[ \t]*alias\(libs\.plugins\.lsplugin\.apksign\)[ \t]*\n', re.M)
    block = re.compile(r'^apksign\s*\{([^{}]*)\}\s*\n', re.M)
    if len(plugin.findall(text)) != 1 or len(block.findall(text)) != 1:
        raise ValueError('Review changed upstream release signing configuration')
    fields = dict(re.findall(r'(\w+)\s*=\s*"([A-Z_]+)"', block.search(text)[1]))
    if fields != {'storeFileProperty': 'KEYSTORE_FILE', 'storePasswordProperty': 'KEYSTORE_PASSWORD',
                  'keyAliasProperty': 'KEY_ALIAS', 'keyPasswordProperty': 'KEY_PASSWORD'}:
        raise ValueError('Unknown upstream signing configuration')
    text = plugin.sub('', block.sub('', text, count=1), count=1)
    text, count = re.subn(r'(?m)^([ \t]*)release\s*\{', r'\1release {\n\1    signingConfig = null', text)
    if count != 1:
        raise ValueError('Expected one native release build type')
    package = manager_profile(variant)['package']
    text += '\nandroid { defaultConfig { applicationId = "' + package + '" } }\n'
    if variant == 'KernelSU-Next':
        settings = source / 'manager/settings.gradle.kts'
        original_settings = settings.read_text(encoding='utf-8')
        updated_settings = next_plugin_repositories(original_settings)
    app.write_text(text, encoding='utf-8')
    if variant == 'KernelSU-Next' and updated_settings != original_settings:
        settings.write_text(updated_settings, encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--variant', required=True, choices=ADDITIONAL_MANAGERS)
    args = parser.parse_args()
    prepare(args.source, args.variant)
