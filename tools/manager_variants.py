"""Allowlisted manager identities shared by source, signing and packaging tools."""
from __future__ import annotations

import os
from pathlib import Path
import re


LOCAL_MANAGERS = ('SukiSU', 'BakaSU')
ADDITIONAL_MANAGERS = ('KernelSU-Next', 'KernelSU', 'KowSU', 'FinaSU')
MANAGERS = LOCAL_MANAGERS + ADDITIONAL_MANAGERS
COMBINED_SELECTION = 'SukiSU + BakaSU + KernelSU-Next'
COMBINED_MANAGERS = ('SukiSU', 'BakaSU', 'KernelSU-Next')
COMBINED_GROUPS = {
    COMBINED_SELECTION: COMBINED_MANAGERS,
    'KowSU + KernelSU + FinaSU': ('KowSU', 'KernelSU', 'FinaSU'),
}
PUBLIC_SUKISU = 'SukiSU-Nova'
PUBLIC_SELECTIONS = {value: value.replace('SukiSU', PUBLIC_SUKISU)
                     for value in (MANAGERS + tuple(COMBINED_GROUPS))}
MANAGER_SELECTIONS = tuple(PUBLIC_SELECTIONS.values())
SUKISU_ULTRA_PACKAGE = 'com.sukisu.ultra'
SUKISU_NOVA_PACKAGE = 'com.sukisu.nova'
_SUKISU_FILENAMES = {SUKISU_ULTRA_PACKAGE: 'SukiSU', SUKISU_NOVA_PACKAGE: 'SukiSU_Nova'}
_SUKISU_KBUILD_NAMES = {SUKISU_ULTRA_PACKAGE: 'SukiSU-Ultra', SUKISU_NOVA_PACKAGE: 'SukiSU-Nova'}
# Actual Gradle application IDs, not Kotlin namespaces. BakaSU retains its
# upstream ReSukiSU ID; its current Kotlin namespace is org.bakasu.bakasu.
_PROFILES = {
    'SukiSU': {'repository': 'SukiSU-Ultra/SukiSU-Ultra',
               'package': SUKISU_ULTRA_PACKAGE, 'apk_prefixes': tuple(_SUKISU_FILENAMES.values())},
    'BakaSU': {'repository': 'Baka-SU/BakaSU',
               'package': 'com.resukisu.resukisu', 'apk_prefixes': ('BakaSU', 'ReSukiSU')},
    'KernelSU-Next': {'repository': 'KernelSU-Next/KernelSU-Next',
                     'package': 'com.rifsxd.ksunext', 'apk_prefixes': ('KernelSU_Next',)},
    'KernelSU': {'repository': 'tiann/KernelSU',
                 'package': 'me.weishu.kernelsu', 'apk_prefixes': ('KernelSU',)},
    'KowSU': {'repository': 'KOWX712/KernelSU',
              'package': 'com.kowx712.supermanager', 'apk_prefixes': ('KernelSU', 'KowSU', 'SuperManager')},
    'FinaSU': {'repository': 'LyraVoid/FinaSU',
               'package': 'me.yuki.fina', 'apk_prefixes': ('FinaSU',)},
}


def manager_profile(variant: str = 'SukiSU') -> dict:
    if not isinstance(variant, str) or variant not in MANAGERS:
        raise ValueError('Unsupported paired manager variant')
    return dict(_PROFILES[variant])


def selected_variant(variant: str | None = None) -> str:
    selected = os.environ.get('KSU_VARIANT', 'SukiSU') if variant is None else variant
    manager_profile(selected)
    return selected


def allowed_manager_package(variant: str, package: object) -> bool:
    profile = manager_profile(variant)
    if variant == 'SukiSU':
        return isinstance(package, str) and package in _SUKISU_FILENAMES
    return package == profile['package']


def manager_package(variant: str, package: str | None = None) -> str:
    """Validate the workflow's source-bound application ID; keep the legacy default."""
    if package is None:
        return manager_profile(variant)['package']
    if not allowed_manager_package(variant, package):
        raise ValueError('Application ID differs from the selected manager variant')
    return package


def manager_display_name(variant: str | None, package: object) -> str | None:
    return 'SukiSU-Nova' if variant == 'SukiSU' and package == SUKISU_NOVA_PACKAGE else variant


def manager_source_package(variant: str, source: Path) -> str:
    """Read the native regular-release application ID from a selected source checkout."""
    if variant != 'SukiSU':
        return manager_package(variant)
    path = Path(source) / 'manager/app/build.gradle.kts'
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 128 * 1024:
        raise ValueError('SukiSU manager application ID source is missing or unsafe')
    text = path.read_text(encoding='utf-8')
    packages = re.findall(r'^val defaultManagerPackageName[ \t]*=[ \t]*if \(isPrBuild\) "([a-z.]+)" else "([a-z.]+)"[ \t]*$', text, re.M)
    namespaces = re.findall(r'^[ \t]*namespace[ \t]*=[ \t]*"([a-z.]+)"[ \t]*$', text, re.M)
    application_ids = re.findall(r'^[ \t]*applicationId[ \t]*=[ \t]*(\w+)[ \t]*$', text, re.M)
    if (len(packages) != 1 or namespaces != [packages[0][1]] or application_ids != ['managerPackageName']
            or packages[0][0] != packages[0][1] + '.pr'
            or len(re.findall(r'^val managerPackageName[ \t]*=[ \t]*project\.findProperty\("KSU_PACKAGE_NAME"\)\?\.toString\(\)[ \t]*\?:[ \t]*defaultManagerPackageName[ \t]*$', text, re.M)) != 1):
        raise ValueError('SukiSU Gradle package declarations require compatibility review')
    package = manager_package(variant, packages[0][1])
    kbuild = Path(source) / 'kernel/Kbuild'
    if kbuild.is_symlink() or not kbuild.is_file() or not 0 < kbuild.stat().st_size <= 1024 * 1024:
        raise ValueError('SukiSU manager kernel source is missing or unsafe')
    names = re.findall(r'^REPO_NAME[ \t]*:=[ \t]*([A-Za-z0-9-]+)[ \t]*$', kbuild.read_text(encoding='utf-8'), re.M)
    if names != [_SUKISU_KBUILD_NAMES[package]]:
        raise ValueError('SukiSU Gradle package and kernel project identity disagree')
    return package


def selected_managers(selection: str) -> tuple[str, ...]:
    """Expand the menu once; every build still receives exactly one manager."""
    selection = internal_manager_selection(selection)
    if isinstance(selection, str) and selection in COMBINED_GROUPS:
        return COMBINED_GROUPS[selection]
    manager_profile(selection)
    return (selection,)


def public_manager_selection(selection: str) -> str:
    return PUBLIC_SELECTIONS.get(selection, selection)


def internal_manager_selection(selection: str) -> str:
    if isinstance(selection, str):
        return next((key for key, public in PUBLIC_SELECTIONS.items() if public == selection), selection)
    return selection


def valid_manager_apk_filename(name: str, variant: str = 'SukiSU', *,
                               allow_unsigned: bool = False, package: str | None = None) -> bool:
    profile = manager_profile(variant)
    if variant != 'KernelSU-Next' and isinstance(name, str) and name.startswith('KernelSU_Next_'):
        return False
    if (variant == 'SukiSU' and package is not None and isinstance(name, str)
            and name.startswith('SukiSU_Nova_') != (package == SUKISU_NOVA_PACKAGE)):
        return False
    prefixes = '|'.join(re.escape(prefix) for prefix in profile['apk_prefixes'])
    unsigned = r'(?:-unsigned)?' if allow_unsigned else ''
    return (isinstance(name, str) and len(name) <= 250 and '..' not in name
            and re.fullmatch(r'(?:' + prefixes + r')_[A-Za-z0-9][A-Za-z0-9._+-]*-release'
                             + unsigned + r'\.apk', name) is not None)
