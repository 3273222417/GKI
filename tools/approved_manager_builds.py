"""Read the fixed manager channels approved for ordinary builds."""
from __future__ import annotations

import json
from pathlib import Path

from manager_variants import MANAGERS
from resolve_build_sources import SHA, SourceResolutionError, validate_ref


APPROVED_PATH = 'config/validated-manager-builds.json'
STABLE = 'Stable(标准)'
LATEST = 'Latest(最新)'
MAX_BYTES = 16384
ChannelSources = dict[str, dict[str, tuple[str, str]]]


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('已验证管理器版本记录包含重复字段')
        result[key] = value
    return result


def validate_approved(document: object) -> ChannelSources:
    if (not isinstance(document, dict) or set(document) != {'schema_version', 'channels'}
            or type(document['schema_version']) is not int or document['schema_version'] != 1
            or not isinstance(document['channels'], dict) or set(document['channels']) != set(MANAGERS)):
        raise ValueError('无效的已验证管理器版本清单')
    channels = {}
    for variant in MANAGERS:
        selected = document['channels'][variant]
        if not isinstance(selected, dict) or LATEST not in selected or selected.keys() - {STABLE, LATEST}:
            raise ValueError('已验证管理器清单的发布渠道无效：' + variant)
        channels[variant] = {}
        for tier, item in selected.items():
            if not isinstance(item, dict) or set(item) != {'reference', 'source_branch'}:
                raise ValueError('已验证管理器清单的源码记录无效：' + variant)
            ref = item['reference']
            if not isinstance(ref, str) or not SHA.fullmatch(ref) or ref != ref.lower():
                raise ValueError('已验证管理器清单需要完整的小写源码提交 SHA：' + variant)
            try:
                branch = validate_ref(item['source_branch'])
            except SourceResolutionError:
                raise ValueError('已验证管理器清单的源码引用无效：' + variant) from None
            channels[variant][tier] = (ref, branch)
    return channels


def approved_document(channels: ChannelSources) -> dict:
    document = {'schema_version': 1, 'channels': {
        variant: {tier: {'reference': ref, 'source_branch': branch} for tier, (ref, branch) in selected.items()}
        for variant, selected in channels.items()}}
    validate_approved(document)
    return document


def read_approved(root: Path) -> ChannelSources:
    path = root / APPROVED_PATH
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= MAX_BYTES:
        raise ValueError('缺少有效的已验证管理器版本清单：' + APPROVED_PATH)
    with path.open('rb') as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError('已验证管理器版本清单超过大小限制')
    return validate_approved(json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object))
