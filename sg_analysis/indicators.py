"""Pure helpers for extracting safe, deterministic indicators from strings."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections.abc import Iterable
from urllib.parse import urlsplit, urlunsplit


MAX_STRINGS_SCANNED = 1_000_000
MAX_SCAN_CHARS = 50_000_000
MAX_INDICATOR_ITEMS = 500

IGNORED_URL_HOST_PATHS = (
    ("schemas.android.com", ""),
    ("www.w3.org", ""),
    ("w3.org", ""),
    ("www.apache.org", "/licenses"),
    ("apache.org", "/licenses"),
    ("opensource.org", "/licenses"),
    ("www.opensource.org", "/licenses"),
    ("spdx.org", "/licenses"),
    ("creativecommons.org", "/licenses"),
    ("www.creativecommons.org", "/licenses"),
)
CLOUD_HOST_SUFFIXES = (
    "firebaseio.com",
    "firebasedatabase.app",
    "firebaseapp.com",
    "cloudfunctions.net",
    "appspot.com",
    "storage.googleapis.com",
    "s3.amazonaws.com",
    "blob.core.windows.net",
)

BOT_TOKEN_PATTERN = re.compile(r"(?<![A-Za-z0-9_-])\d{5,12}:[A-Za-z0-9_-]{30,}(?![A-Za-z0-9_-])")
URL_PATTERN = re.compile(
    r"""(?i)(?<![A-Za-z0-9+.-])(?:https?|ftp)://[^\s"'<>()[\\]+"""
)
CLOUD_HOST_PATTERN = re.compile(
    r"(?i)(?<![A-Za-z0-9.-])(?:[A-Za-z0-9-]+\.)*"
    r"(?:firebaseio\.com|firebasedatabase\.app|firebaseapp\.com|cloudfunctions\.net|"
    r"appspot\.com|storage\.googleapis\.com|s3\.amazonaws\.com|blob\.core\.windows\.net)"
    r"(?::\d{1,5})?(?:/[^\s<>\"']*)?"
)
IPV4_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_.])(?:\d{1,3}\.){3}\d{1,3}(?![A-Za-z0-9_.])"
)
VERSION_PREFIX_PATTERN = re.compile(r"(?i)\b(?:version|ver|v|build)\s*[=:]?\s*$")
HOST_LABEL_PATTERN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
TRAILING_URL_PUNCTUATION = ".,;:)]}'\""


def _normalized_domain(hostname: str) -> str | None:
    """Return an ASCII DNS hostname only when it meets the domain constraints."""
    candidate = hostname.replace("[.]", ".")
    if candidate.endswith("."):
        candidate = candidate[:-1]
    try:
        candidate = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    labels = candidate.split(".")
    if len(candidate) > 253 or len(labels) < 2:
        return None
    if not 2 <= len(labels[-1]) <= 24 or not labels[-1].isalpha():
        return None
    if any(not HOST_LABEL_PATTERN.fullmatch(label) for label in labels):
        return None
    return candidate


def is_valid_domain(hostname: str) -> bool:
    """Check a hostname against the bounded DNS-name rules used for domains."""
    return _normalized_domain(hostname) is not None


def _normalized_host(hostname: str) -> str | None:
    """Normalize an IPv4/IPv6 address or a valid DNS hostname."""
    try:
        return ipaddress.ip_address(hostname).compressed.lower()
    except ValueError:
        return _normalized_domain(hostname)


def _is_candidate_string(text: str) -> bool:
    """Use cheap substring checks before running indicator regexes."""
    if "://" in text:
        return True
    if ":" in text and BOT_TOKEN_PATTERN.search(text):
        return True
    if text.count(".") >= 3 and IPV4_PATTERN.search(text):
        return True
    if "." in text:
        folded = text.lower()
        return any(suffix in folded for suffix in CLOUD_HOST_SUFFIXES)
    return False


def prefilter_strings(strings: Iterable[str]) -> tuple[list[str], bool]:
    """Keep likely URL, IP, token, or cloud strings within scan budgets."""
    candidates: list[str] = []
    scanned_chars = 0
    for index, text in enumerate(strings):
        if index >= MAX_STRINGS_SCANNED:
            return candidates, True
        remaining = MAX_SCAN_CHARS - scanned_chars
        if remaining <= 0:
            return candidates, True
        scan_text = text if len(text) <= remaining else text[:remaining]
        scanned_chars += len(scan_text)
        if _is_candidate_string(scan_text):
            candidates.append(scan_text)
        if len(scan_text) < len(text):
            return candidates, True
    return candidates, False


def _host_path(url: str) -> tuple[str, str] | None:
    """Return a normalized, validated host and path from an HTTP/FTP URL."""
    value = url.replace("[.]", ".")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https", "ftp", "hxxp", "hxxps"} or not hostname:
        return None
    normalized_host = _normalized_host(hostname)
    if normalized_host is None:
        return None
    return normalized_host, parsed.path.lower()


def _is_ignored_url(url: str) -> bool:
    host_path = _host_path(url)
    if host_path is None:
        return True
    host, path = host_path
    return any(
        host == ignored_host and (not ignored_path or path.startswith(ignored_path))
        for ignored_host, ignored_path in IGNORED_URL_HOST_PATHS
    )


def _is_cloud_host(hostname: str) -> bool:
    return any(hostname == suffix or hostname.endswith("." + suffix) for suffix in CLOUD_HOST_SUFFIXES)


def _safe_hostname(hostname: str) -> str:
    """Defang dots in a normalized hostname."""
    if ":" in hostname:
        return f"[{hostname}]"
    return hostname.replace(".", "[.]")


def _remember_unique(values: set[str], value: str, maximum: int) -> None:
    """Keep a bounded set of unique values while continuing the caller's scan."""
    if value not in values and len(values) < maximum:
        values.add(value)


def _candidate_strings(strings: Iterable[str], prefiltered: bool) -> list[str]:
    if prefiltered:
        return list(strings)
    return prefilter_strings(strings)[0]


def _trim_url(value: str) -> str:
    """Remove punctuation commonly attached to URLs in prose."""
    return value.rstrip(TRAILING_URL_PUNCTUATION)


def defang(url: str) -> str:
    """Defang a URL and redact any bot token embedded in it."""
    safe_url = redact_tokens(url.strip())
    try:
        parsed = urlsplit(safe_url.replace("[.]", "."))
        hostname = parsed.hostname
    except ValueError:
        return ""
    if parsed.scheme.lower() not in {"http", "https", "ftp", "hxxp", "hxxps"} or not hostname:
        return ""
    normalized_host = _normalized_host(hostname)
    if normalized_host is None:
        return ""
    try:
        port = parsed.port
    except ValueError:
        port = None

    scheme = parsed.scheme.lower()
    if scheme == "http":
        scheme = "hxxp"
    elif scheme == "https":
        scheme = "hxxps"
    host = _safe_hostname(normalized_host)
    netloc = host if port is None else f"{host}:{port}"
    return urlunsplit((scheme, netloc, parsed.path, parsed.query, parsed.fragment))


def extract_urls(
    strings: Iterable[str],
    max_items: int = MAX_INDICATOR_ITEMS,
    *,
    prefiltered: bool = False,
) -> list[str]:
    """Find valid explicit HTTP, HTTPS, and FTP URLs and return defanged values."""
    if max_items <= 0:
        return []
    found: set[str] = set()
    for text in _candidate_strings(strings, prefiltered):
        for match in URL_PATTERN.finditer(text):
            candidate = _trim_url(match.group(0))
            if not candidate:
                continue
            host_path = _host_path(candidate)
            if host_path is None or _is_ignored_url(candidate):
                continue
            normalized = defang(candidate)
            if normalized:
                _remember_unique(found, normalized, max_items)
    return sorted(found)


def extract_domains(urls: Iterable[str], max_items: int = MAX_INDICATOR_ITEMS) -> list[str]:
    """Extract valid, defanged DNS hostnames from validated URL strings."""
    if max_items <= 0:
        return []
    found: set[str] = set()
    for url in urls:
        host_path = _host_path(url)
        if host_path is None:
            continue
        hostname, _ = host_path
        try:
            ipaddress.ip_address(hostname)
            continue
        except ValueError:
            pass
        domain = _normalized_domain(hostname)
        if domain is not None:
            _remember_unique(found, _safe_hostname(domain), max_items)
    return sorted(found)


def _public_ipv4(value: str) -> str | None:
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        return None
    if address.is_private or address.is_loopback or address.is_link_local:
        return None
    return str(address)


def _has_version_prefix(text: str, start: int) -> bool:
    # A dotted quad immediately following a version/build marker is treated as a version, not an IP.
    return VERSION_PREFIX_PATTERN.search(text[max(0, start - 24):start]) is not None


def extract_ip_addresses(
    strings: Iterable[str],
    max_items: int = MAX_INDICATOR_ITEMS,
    *,
    prefiltered: bool = False,
) -> list[str]:
    """Find public IPv4 addresses appearing alone or as a validated URL host."""
    if max_items <= 0:
        return []
    found: set[str] = set()
    for text in _candidate_strings(strings, prefiltered):
        url_spans: list[tuple[int, int]] = []
        for match in URL_PATTERN.finditer(text):
            url_spans.append(match.span())
            host_path = _host_path(_trim_url(match.group(0)))
            if host_path is None:
                continue
            host, _ = host_path
            try:
                address = ipaddress.IPv4Address(host)
            except ipaddress.AddressValueError:
                continue
            safe_address = _public_ipv4(str(address))
            if safe_address is not None:
                _remember_unique(found, safe_address, max_items)

        span_index = 0
        for match in IPV4_PATTERN.finditer(text):
            while span_index < len(url_spans) and url_spans[span_index][1] <= match.start():
                span_index += 1
            if span_index < len(url_spans):
                start, end = url_spans[span_index]
                if start <= match.start() < end:
                    continue
            if _has_version_prefix(text, match.start()):
                continue
            address = _public_ipv4(match.group(0))
            if address is not None:
                _remember_unique(found, address, max_items)
    return sorted(found)


def extract_cloud_endpoints(
    strings: Iterable[str],
    max_items: int = MAX_INDICATOR_ITEMS,
    *,
    prefiltered: bool = False,
) -> list[str]:
    """Find Firebase-style and selected cloud service endpoints, then defang them."""
    if max_items <= 0:
        return []
    found: set[str] = set()
    for text in _candidate_strings(strings, prefiltered):
        for match in URL_PATTERN.finditer(text):
            candidate = _trim_url(match.group(0))
            host_path = _host_path(candidate)
            if host_path is None or not _is_cloud_host(host_path[0]):
                continue
            _remember_unique(found, defang(candidate), max_items)

        for match in CLOUD_HOST_PATTERN.finditer(text):
            candidate = _trim_url(match.group(0))
            if "://" not in candidate:
                candidate = "https://" + candidate
            host_path = _host_path(candidate)
            if host_path is None or not _is_cloud_host(host_path[0]):
                continue
            endpoint = defang(candidate)
            if endpoint:
                _remember_unique(found, endpoint, max_items)
    return sorted(found)


def find_and_hash_tokens(
    strings: Iterable[str], max_items: int = MAX_INDICATOR_ITEMS
) -> list[str]:
    """Hash detected Telegram-style bot tokens and return only unique hashes."""
    if max_items <= 0:
        return []
    hashes: set[str] = set()
    scanned_chars = 0
    for index, text in enumerate(strings):
        if index >= MAX_STRINGS_SCANNED:
            break
        remaining = MAX_SCAN_CHARS - scanned_chars
        if remaining <= 0:
            break
        scan_text = text if len(text) <= remaining else text[:remaining]
        scanned_chars += len(scan_text)
        if ":" in scan_text:
            for match in BOT_TOKEN_PATTERN.finditer(scan_text):
                _remember_unique(
                    hashes,
                    hashlib.sha256(match.group(0).encode("utf-8")).hexdigest(),
                    max_items,
                )
        if len(scan_text) < len(text):
            break
    return sorted(hashes)


def redact_tokens(value: str) -> str:
    """Replace token-shaped substrings so raw tokens are never retained in output."""
    if ":" not in value:
        return value
    return BOT_TOKEN_PATTERN.sub("[redacted]", value)
