import copy
import json
import re
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "shared" / "schemas" / "findings_record.schema.json"
REASON_CODES_PATH = ROOT / "shared" / "reason_codes.json"
FIXTURE_DIR = ROOT / "shared" / "fixtures" / "findings"

UUID_V4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
RAW_BOT_TOKEN_RE = re.compile(r"[0-9]+:[A-Za-z0-9_-]{30,}")


@pytest.fixture(scope="module")
def schema():
    with SCHEMA_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


@pytest.fixture(scope="module")
def reason_codes():
    with REASON_CODES_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def fixture_files():
    return sorted(FIXTURE_DIR.glob("*.json"))


def walk_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from walk_strings(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from walk_strings(item)


def test_fixture_count_and_unique_identity():
    files = fixture_files()
    assert len(files) == 8

    job_ids = set()
    sha256_values = set()
    for path in files:
        with path.open("r", encoding="utf-8") as handle:
            fixture = json.load(handle)
        job_id = fixture["job_id"]
        sha256 = fixture["file"]["sha256"]
        assert UUID_V4_RE.fullmatch(job_id)
        assert job_id not in job_ids
        assert sha256 not in sha256_values
        job_ids.add(job_id)
        sha256_values.add(sha256)


@pytest.mark.parametrize("fixture_path", fixture_files(), ids=lambda path: path.name)
def test_fixture_validates_and_reason_codes_match(schema, reason_codes, fixture_path):
    with fixture_path.open("r", encoding="utf-8") as handle:
        fixture = json.load(handle)

    Draft202012Validator(schema).validate(fixture)

    master_codes = {entry["code"] for entry in reason_codes}
    for hit in fixture["rule_hits"]:
        assert hit["reason_code"] in master_codes
        category = hit["rule_id"].split("-")[1]
        assert category == hit["category"]


@pytest.mark.parametrize("fixture_path", fixture_files(), ids=lambda path: path.name)
def test_features_mirror_findings(fixture_path):
    with fixture_path.open("r", encoding="utf-8") as handle:
        fixture = json.load(handle)

    features = fixture["features"]
    assert features["num_requested_permissions"] == len(fixture["permissions"]["requested"])
    assert features["num_dangerous_permissions"] == len(fixture["permissions"]["dangerous"])
    assert features["num_urls"] == len(fixture["indicators"]["urls"])
    assert features["num_domains"] == len(fixture["indicators"]["domains"])
    assert features["num_ip_addresses"] == len(fixture["indicators"]["ip_addresses"])
    assert features["num_cloud_endpoints"] == len(fixture["indicators"]["cloud_endpoints"])
    assert features["num_token_hashes"] == len(fixture["indicators"]["token_hashes"])
    assert features["num_cert_fingerprints"] == len(fixture["certificate"]["sha256_fingerprints"])
    assert features["num_rule_hits"] == len(fixture["rule_hits"])

    hits = fixture["rule_hits"]
    assert features["num_high_severity_hits"] == sum(hit["severity"] == "high" for hit in hits)
    assert features["num_medium_severity_hits"] == sum(hit["severity"] == "medium" for hit in hits)
    assert features["num_low_severity_hits"] == sum(hit["severity"] == "low" for hit in hits)

    components = fixture["components"]
    boolean_mirrors = {
        "has_launcher_activity": "has_launcher_activity",
        "has_accessibility_service": "has_accessibility_service",
        "has_device_admin": "has_device_admin",
        "has_sms_receiver": "has_sms_receiver",
        "requests_install_packages": "requests_install_packages",
        "requests_overlay": "requests_overlay",
        "embedded_apk_or_dex": "embedded_apk_or_dex",
        "dynamic_code_loading": "dynamic_code_loading",
    }
    for feature_name, component_name in boolean_mirrors.items():
        assert features[feature_name] == components[component_name]

    certificate = fixture["certificate"]
    assert features["is_signed"] == bool(certificate["signed"])
    assert features["is_self_signed"] == bool(certificate["self_signed"])
    assert features["is_debug_cert"] == bool(certificate["debug_cert"])


@pytest.mark.parametrize("fixture_path", fixture_files(), ids=lambda path: path.name)
def test_no_raw_looking_tokens(fixture_path):
    with fixture_path.open("r", encoding="utf-8") as handle:
        fixture = json.load(handle)
    for text in walk_strings(fixture):
        assert not RAW_BOT_TOKEN_RE.search(text)


@pytest.mark.parametrize("fixture_path", fixture_files(), ids=lambda path: path.name)
def test_failed_and_partial_invariants(fixture_path):
    with fixture_path.open("r", encoding="utf-8") as handle:
        fixture = json.load(handle)

    status = fixture["analysis_status"]
    failure_reason = fixture["failure_reason"]
    if status == "ok":
        assert failure_reason is None
    else:
        assert status in {"partial", "failed"}
        assert failure_reason in {"packed_obfuscated", "invalid_apk", "timeout", "unpack_limit"}


@pytest.fixture(scope="module")
def benign_record(schema):
    with (FIXTURE_DIR / "benign_app.json").open("r", encoding="utf-8") as handle:
        return json.load(handle)


def assert_rejected(schema, record):
    errors = list(Draft202012Validator(schema).iter_errors(record))
    assert errors, "Invalid record was accepted"


def test_negative_status_sha_rule_and_extra_field_records(schema, benign_record):
    record = copy.deepcopy(benign_record)
    record["analysis_status"] = "ok"
    record["failure_reason"] = "invalid_apk"
    assert_rejected(schema, record)

    record = copy.deepcopy(benign_record)
    record["analysis_status"] = "failed"
    record["failure_reason"] = None
    assert_rejected(schema, record)

    record = copy.deepcopy(benign_record)
    record["file"]["sha256"] = "0" * 63
    assert_rejected(schema, record)

    record = copy.deepcopy(benign_record)
    record["file"]["sha256"] = "A" * 64
    assert_rejected(schema, record)

    record = copy.deepcopy(benign_record)
    record["rule_hits"] = [{
        "rule_id": "SG-XYZ-001",
        "category": "XYZ",
        "severity": "high",
        "reason_code": "SMS_INTERCEPTION",
        "params": {},
        "evidence_short": "Synthetic unknown-category rule."
    }]
    assert_rejected(schema, record)

    record = copy.deepcopy(benign_record)
    record["unknown_top_level"] = "unexpected"
    assert_rejected(schema, record)


def test_negative_free_text_safety(schema, benign_record):
    bot_like = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefgh"

    record = copy.deepcopy(benign_record)
    record["rule_hits"] = [{
        "rule_id": "SG-SMS-001",
        "category": "SMS",
        "severity": "high",
        "reason_code": "SMS_INTERCEPTION",
        "params": {},
        "evidence_short": bot_like
    }]
    assert_rejected(schema, record)

    record = copy.deepcopy(benign_record)
    record["warnings"] = [bot_like]
    assert_rejected(schema, record)

    record = copy.deepcopy(benign_record)
    record["rule_hits"] = [{
        "rule_id": "SG-SMS-001",
        "category": "SMS",
        "severity": "high",
        "reason_code": "SMS_INTERCEPTION",
        "params": {"value": bot_like},
        "evidence_short": "Synthetic parameter value."
    }]
    assert_rejected(schema, record)

    record = copy.deepcopy(benign_record)
    record["rule_hits"] = [{
        "rule_id": "SG-SMS-001",
        "category": "SMS",
        "severity": "high",
        "reason_code": "SMS_INTERCEPTION",
        "params": {},
        "evidence_short": "x" * 201
    }]
    assert_rejected(schema, record)


def test_positive_optional_filename_and_null_compatibility(schema, benign_record):
    record = copy.deepcopy(benign_record)
    record["file"].pop("claimed_filename")
    Draft202012Validator(schema).validate(record)

    record = copy.deepcopy(benign_record)
    record["file"]["claimed_filename"] = None
    Draft202012Validator(schema).validate(record)

    record = copy.deepcopy(benign_record)
    record["impersonation"]["match_basis"] = None
    record["impersonation"]["claimed_brand"] = None
    record["impersonation"]["cert_matches_reference"] = None
    Draft202012Validator(schema).validate(record)

    record = copy.deepcopy(benign_record)
    record["analysis_status"] = "failed"
    record["failure_reason"] = "invalid_apk"
    record["file"]["detected_type"] = "other"
    record["app"]["label"] = None
    record["app"]["package_name"] = None
    record["app"]["version_name"] = None
    record["app"]["min_sdk"] = None
    record["app"]["target_sdk"] = None
    record["certificate"]["subject"] = None
    record["certificate"]["signed"] = None
    record["certificate"]["self_signed"] = None
    record["certificate"]["debug_cert"] = None
    record["certificate"]["sha256_fingerprints"] = []
    Draft202012Validator(schema).validate(record)


def test_all_fixture_strings_reject_bot_tokens():
    for fixture_path in fixture_files():
        with fixture_path.open("r", encoding="utf-8") as handle:
            fixture = json.load(handle)
        for text in walk_strings(fixture):
            assert not RAW_BOT_TOKEN_RE.search(text), (
                f"Bot-token-like sequence found in {fixture_path.name}"
            )
