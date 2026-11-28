import hashlib
import io
import json
import re
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

import sg_analysis.analyze as analyzer
import sg_analysis.indicators as indicators
from sg_analysis.analyze import analyze_apk
from sg_analysis.indicators import (
    defang,
    extract_cloud_endpoints,
    extract_domains,
    extract_ip_addresses,
    extract_urls,
    find_and_hash_tokens,
    is_valid_domain,
)
from sg_analysis.strings import _hash_and_redact_tokens


ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples" / "benign"
SCHEMA = json.loads((ROOT / "shared" / "schemas" / "findings_record.schema.json").read_text(encoding="utf-8"))
JOB_ID = "12345678-1234-4abc-8def-1234567890ab"
RAW_TOKEN_PATTERN = re.compile(r"[0-9]+:[A-Za-z0-9_-]{30,}")


def test_extract_urls_from_normal_and_noisy_text_and_ignore_noise_urls():
    urls = extract_urls([
        "See https://Example.COM/help, then ftp://files.example.net/archive.tar.gz.",
        "https://example.com/help and https://schemas.android.com/apk/res/android",
        "https://www.w3.org/2000/svg and https://www.apache.org/licenses/LICENSE-2.0",
    ])
    assert urls == [
        "ftp://files[.]example[.]net/archive.tar.gz",
        "hxxps://example[.]com/help",
    ]


def test_domains_are_lowercase_deduplicated_and_sorted():
    domains = extract_domains([
        "hxxps://Z.example[.]net/page",
        "hxxp://a.example[.]com/path",
        "hxxps://z.example[.]net/other",
    ])
    assert domains == ["a[.]example[.]com", "z[.]example[.]net"]


def test_words_and_prose_do_not_become_urls_or_domains():
    strings = [
        "(api",
        "according",
        "addEventListenerResponsible",
        "ain",
        "an",
        "according to the api",
        "http://according",
        "http://[.]css",
    ]
    urls = extract_urls(strings)
    assert urls == []
    assert extract_domains(urls) == []


def test_urls_require_an_explicit_scheme_and_valid_fqdn_host():
    urls = extract_urls(["see http://example.com/a, and"])
    assert urls == ["hxxp://example[.]com/a"]
    assert extract_domains(urls) == ["example[.]com"]

    parenthesized = extract_urls(["(https://example.org/x)."])
    assert parenthesized == ["hxxps://example[.]org/x"]
    assert extract_domains(parenthesized) == ["example[.]org"]

    for candidate in ("http://localhost", "http://foo"):
        candidate_urls = extract_urls([candidate])
        assert extract_domains(candidate_urls) == []


def test_domain_validation_enforces_dns_label_rules():
    assert is_valid_domain("example[.]com")
    assert is_valid_domain("sub.example[.]co")
    assert not is_valid_domain("localhost")
    assert not is_valid_domain("foo")
    assert not is_valid_domain("(api[.]com")
    assert not is_valid_domain("bad_label[.]com")
    assert not is_valid_domain("-bad[.]com")
    assert not is_valid_domain("bad[.]com-")
    assert not is_valid_domain("example[.]com..")
    assert not is_valid_domain("example[.]toolongtldmorethan24characters")


def test_extract_only_valid_public_ipv4_and_skip_version_numbers():
    strings = [
        "public 8.8.8.8 and 1.1.1.1",
        "private 10.0.0.1 and 192.168.1.1",
        "loopback 127.0.0.1 and link-local 169.254.1.1",
        "invalid 999.1.1.1 and version v1.2.3.4",
    ]
    assert extract_ip_addresses(strings) == ["1.1.1.1", "8.8.8.8"]
    assert extract_ip_addresses(["1.2.3.4.5"]) == []
    assert extract_ip_addresses(["version 10.0.0.1"]) == []
    assert extract_ip_addresses(["version 8.8.8.8"]) == []


def test_duplicate_urls_do_not_consume_the_item_cap():
    repeated = ["https://example.com/path"] * 500
    assert extract_urls(repeated, max_items=1) == ["hxxps://example[.]com/path"]


def test_prefilter_reaches_a_url_after_many_junk_strings():
    strings = ["documentation without indicators"] * 200_000
    strings.append("final URL: http://example.com/found")
    urls = extract_urls(strings)
    assert urls == ["hxxp://example[.]com/found"]


def test_very_long_junk_string_is_rejected_without_regex_work():
    assert extract_urls(["x" * 5_000_000]) == []


def test_extract_firebase_and_similar_cloud_endpoints():
    endpoints = extract_cloud_endpoints([
        "Realtime DB: https://demo.firebaseio.com/data.json",
        "Also demo.firebasedatabase.app/users",
        "Ordinary https://example.com/resource",
    ])
    assert endpoints == [
        "hxxps://demo[.]firebasedatabase[.]app/users",
        "hxxps://demo[.]firebaseio[.]com/data.json",
    ]


def test_defang_changes_http_scheme_and_host():
    assert defang("https://Example.com/path") == "hxxps://example[.]com/path"
    assert defang("http://Example.com/path") == "hxxp://example[.]com/path"
    assert defang("http://Example.com:99999/path") == "hxxp://example[.]com/path"
    assert defang("http://[malformed.example/path") == ""


def test_indicator_results_are_capped_and_sorted():
    urls = [
        "https://z.example.test/a",
        "https://a.example.test/b",
        "https://m.example.test/c",
    ]
    assert extract_urls(urls, max_items=2) == [
        "hxxps://a[.]example[.]test/b",
        "hxxps://z[.]example[.]test/a",
    ]
    assert extract_domains(urls, max_items=2) == ["a[.]example[.]test", "z[.]example[.]test"]
    assert extract_ip_addresses(["8.8.8.8 1.1.1.1 9.9.9.9"], max_items=2) == [
        "1.1.1.1",
        "8.8.8.8",
    ]


def test_string_scan_cap_is_enforced(monkeypatch):
    monkeypatch.setattr(indicators, "MAX_STRINGS_SCANNED", 1)
    assert extract_urls([
        "https://first.example/path",
        "https://second.example/path",
    ]) == ["hxxps://first[.]example/path"]


def test_tokens_are_hashed_immediately_and_only_hashes_are_returned():
    fake_token = "123456789:" + "a" * 35
    result = find_and_hash_tokens([f"synthetic value {fake_token}"])
    hashes = set()
    sanitized, capped = _hash_and_redact_tokens(f"synthetic value {fake_token}", hashes)
    contains_raw_token_in_result = fake_token in repr(result)
    contains_raw_token = fake_token in sanitized
    assert len(result) == 1
    assert len(result[0]) == 64
    assert result[0] == hashlib.sha256(fake_token.encode("utf-8")).hexdigest()
    assert not contains_raw_token_in_result
    assert hashes == {result[0]}
    assert not capped
    assert not contains_raw_token


def make_minimal_apk(path: Path) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("AndroidManifest.xml", b"<manifest package='invalid.example.synthetic'/>")
        archive.writestr("classes.dex", b"dex")
    path.write_bytes(buffer.getvalue())


class MinimalAPK:
    def __init__(self, _path):
        pass

    def get_package(self):
        return "invalid.example.synthetic"

    def get_app_name(self):
        return "Synthetic"

    def get_androidversion_name(self):
        return "1.0"

    def get_min_sdk_version(self):
        return "23"

    def get_target_sdk_version(self):
        return "35"

    def get_permissions(self):
        return []

    def get_android_manifest_xml(self):
        return ET.fromstring("<manifest/>")

    def get_main_activities(self):
        return set()

    def get_files(self):
        return ["AndroidManifest.xml", "classes.dex"]

    def get_certificates(self):
        return []

    def is_signed(self):
        return False


def test_analyzer_turns_string_scan_caps_into_warnings_and_partial_status(tmp_path, monkeypatch):
    apk_path = tmp_path / "synthetic.apk"
    make_minimal_apk(apk_path)
    monkeypatch.setattr(analyzer, "APK", MinimalAPK)
    monkeypatch.setattr(analyzer, "MAX_INDICATOR_ITEMS", 2)
    monkeypatch.setattr(
        analyzer,
        "collect_strings",
        lambda _apk: (
            [
                "https://one.example/path",
                "https://two.example/path",
                "https://three.example/path",
            ],
            [],
            True,
            False,
        ),
    )

    record = analyze_apk(apk_path, JOB_ID)

    Draft202012Validator(SCHEMA).validate(record)
    assert record["analysis_status"] == "partial"
    assert record["failure_reason"] == "unpack_limit"
    assert record["indicators"]["urls"] == [
        "hxxps://one[.]example/path",
        "hxxps://three[.]example/path",
    ]
    assert "String scan limit reached." in record["warnings"]
    assert "Indicator item cap reached: urls." in record["warnings"]


def test_string_extraction_failure_returns_partial_record(tmp_path, monkeypatch):
    apk_path = tmp_path / "synthetic.apk"
    make_minimal_apk(apk_path)
    monkeypatch.setattr(analyzer, "APK", MinimalAPK)

    def fail_collection(_apk):
        raise RuntimeError("private parser details")

    monkeypatch.setattr(analyzer, "collect_strings", fail_collection)
    record = analyze_apk(apk_path, JOB_ID)

    Draft202012Validator(SCHEMA).validate(record)
    assert record["analysis_status"] == "partial"
    assert record["failure_reason"] == "analysis_error"
    assert record["indicators"] == {
        "urls": [],
        "domains": [],
        "ip_addresses": [],
        "cloud_endpoints": [],
        "token_hashes": [],
    }
    assert "String extraction failed." in record["warnings"]
    assert "private parser details" not in repr(record)


def test_real_benign_apks_have_deterministic_schema_valid_defanged_indicators():
    apk_paths = sorted(SAMPLES.glob("*.apk")) if SAMPLES.exists() else []
    if not apk_paths:
        pytest.skip("No APKs found in samples/benign/")

    for apk_path in apk_paths:
        first = analyze_apk(apk_path, JOB_ID)
        second = analyze_apk(apk_path, JOB_ID)
        Draft202012Validator(SCHEMA).validate(first)
        assert first == second
        assert "String scan limit reached." not in first["warnings"]
        if apk_path.name == "org.schabi.newpipe_1017.apk":
            assert "Indicator item cap reached: urls." not in first["warnings"]

        record_text = json.dumps(first, sort_keys=True)
        assert RAW_TOKEN_PATTERN.search(record_text) is None
        for url in first["indicators"]["urls"]:
            scheme, remainder = url.split("://", 1)
            assert scheme in {"hxxp", "hxxps", "ftp", "ftps", "sftp", "ws", "wss"}
            authority = remainder.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
            hostname = authority.rsplit("@", 1)[-1]
            if not hostname.startswith("["):
                assert "." not in hostname.replace("[.]", "")
        for domain in first["indicators"]["domains"]:
            assert is_valid_domain(domain)
            assert "." in domain.replace("[.]", ".")
