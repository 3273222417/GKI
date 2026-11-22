"""Retain Nova's native CFI lookup while accepting Android LTO hash names."""
from __future__ import annotations

from oplus_compat import function_text


RESOLVER = 'kernel/infra/symbol_resolver.c'
CALLBACK = 'lookup_symbol_variant_cb'
OLD_BOUNDARY = "name[ctx->symbol_len] != '.')"
HASH_BOUNDARY = "(name[ctx->symbol_len] != '.' && name[ctx->symbol_len] != '$'))"


def complete_symbol_variants(native: str, current: str) -> str:
    """Change only the selected source's variant delimiter, never CFI priority.

    Android Clang 12 may emit ``function$hash.cfi_jt``. The native resolver
    already prefers CFI jump-table entries, but its '.'-only boundary rejects
    these names before it reaches that preference. Bind this mechanical change
    to the selected HEAD and leave the iterator, exact-name lookup, and CFI
    selection logic byte-for-byte intact.
    """
    callback = function_text(native, CALLBACK)
    if native.count(OLD_BOUNDARY) == callback.count(OLD_BOUNDARY) == 1 and HASH_BOUNDARY not in native:
        updated = native.replace(OLD_BOUNDARY, HASH_BOUNDARY, 1)
    elif native.count(HASH_BOUNDARY) == callback.count(HASH_BOUNDARY) == 1 and OLD_BOUNDARY not in native:
        updated = native
    else:
        raise ValueError('Review the selected Nova symbol-variant boundary before adapting it')
    if current not in (native, updated):
        raise ValueError('Nova symbol resolver differs from the selected source and reviewed hash-name adaptation')
    return updated
