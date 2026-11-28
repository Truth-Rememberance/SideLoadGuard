"""Bounded Androguard string-pool and resource-string collection."""

from __future__ import annotations

import hashlib
import re

from androguard.core.apk import APK
from androguard.core.dex import DEX

from sg_analysis.indicators import (
    BOT_TOKEN_PATTERN,
    MAX_INDICATOR_ITEMS,
    MAX_SCAN_CHARS,
    MAX_STRINGS_SCANNED,
)


def _hash_and_redact_tokens(value: str, token_hashes: set[str]) -> tuple[str, bool]:
    """Hash tokens while replacing them in one pass over a string."""
    if ":" not in value:
        return value, False

    tokens_capped = False

    def replace_token(match: re.Match[str]) -> str:
        nonlocal tokens_capped
        token_hash = hashlib.sha256(match.group(0).encode("utf-8")).hexdigest()
        if token_hash not in token_hashes:
            if len(token_hashes) >= MAX_INDICATOR_ITEMS:
                tokens_capped = True
            else:
                token_hashes.add(token_hash)
        return "[redacted]"

    return BOT_TOKEN_PATTERN.sub(replace_token, value), tokens_capped


def collect_strings(apk: APK) -> tuple[list[str], list[str], bool, bool]:
    """Collect sanitized DEX/resource strings, token hashes and cap indicators."""
    strings: set[str] = set()
    token_hashes: set[str] = set()
    strings_capped = False
    tokens_capped = False
    scanned_chars = 0
    scanned_strings = 0

    def retain(raw_value: str) -> bool:
        nonlocal strings_capped, tokens_capped, scanned_chars, scanned_strings
        if scanned_strings >= MAX_STRINGS_SCANNED:
            strings_capped = True
            return False
        scanned_strings += 1
        remaining = MAX_SCAN_CHARS - scanned_chars
        if remaining <= 0:
            strings_capped = True
            return False
        value = raw_value if len(raw_value) <= remaining else raw_value[:remaining]
        scanned_chars += len(value)
        if len(value) < len(raw_value):
            strings_capped = True
        safe_value, was_capped = _hash_and_redact_tokens(value, token_hashes)
        tokens_capped = tokens_capped or was_capped
        strings.add(safe_value)
        return not strings_capped

    for dex_bytes in apk.get_all_dex():
        dex = DEX(dex_bytes)
        for value in dex.get_strings():
            if not retain(value):
                return sorted(strings), sorted(token_hashes), strings_capped, tokens_capped

    resources = apk.get_android_resources()
    if resources is not None:
        package_name = apk.get_package()
        for locale in resources.get_locales(package_name):
            # Androguard's XML helper serializes these same decoded values before reparsing them.
            for _, value in resources.values[package_name][locale].get("string", []):
                if not retain(value):
                    return sorted(strings), sorted(token_hashes), strings_capped, tokens_capped

    return sorted(strings), sorted(token_hashes), strings_capped, tokens_capped
