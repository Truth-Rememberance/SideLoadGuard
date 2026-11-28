import io
import json
from pathlib import Path
import xml.etree.ElementTree as ET
import zipfile

import pytest
from jsonschema import Draft202012Validator

import sg_analysis.analyze as analyzer
from sg_analysis.analyze import analyze_apk


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "shared" / "schemas" / "findings_record.schema.json").read_text(encoding="utf-8"))
JOB_ID = "12345678-1234-4abc-8def-1234567890ab"


def make_apk_like(path: Path, package_name: str) -> None:
    """Write a tiny APK-like ZIP from in-memory bytes."""
    manifest = f'<manifest package="{package_name}"/>'.encode("utf-8")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        archive.writestr("classes.dex", b"dex")
    path.write_bytes(buffer.getvalue())


class FakeAPK:
    package_name = "invalid.example.synthetic"

    def __init__(self, _path):
        pass

    def get_package(self):
        return self.package_name

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


@pytest.mark.parametrize("kind", ["corrupt", "plain"])
def test_corrupt_and_plain_never_raise(tmp_path, kind):
    path = tmp_path / f"{kind}.apk"
    if kind == "corrupt":
        path.write_bytes(b"PK\x03\x04broken")
    else:
        path.write_text("not an apk", encoding="utf-8")

    record = analyze_apk(path, JOB_ID)
    Draft202012Validator(SCHEMA).validate(record)
    assert record["analysis_status"] == "failed"
    assert record["failure_reason"] in {"invalid_apk", "timeout", "unpack_limit", "packed_obfuscated"}


def test_long_package_name_is_truncated_and_schema_valid(tmp_path, monkeypatch):
    path = tmp_path / "long-package.apk"
    package_name = "p" * 10_000
    make_apk_like(path, package_name)
    monkeypatch.setattr(analyzer, "APK", FakeAPK)
    monkeypatch.setattr(FakeAPK, "package_name", package_name)

    record = analyze_apk(path, JOB_ID)

    Draft202012Validator(SCHEMA).validate(record)
    assert record["app"]["package_name"] == "p" * 256
    assert "package_name truncated" in record["warnings"]
    assert package_name not in record["warnings"][0]


def test_unexpected_analysis_exception_uses_analysis_error(tmp_path, monkeypatch):
    path = tmp_path / "internal-error.apk"
    make_apk_like(path, "invalid.example.synthetic")

    def fail_analysis(_path, _record):
        raise RuntimeError("private exception text from D:/internal/sample.apk")

    monkeypatch.setattr(analyzer, "_extract", fail_analysis)
    record = analyze_apk(path, JOB_ID)

    Draft202012Validator(SCHEMA).validate(record)
    assert record["analysis_status"] == "failed"
    assert record["failure_reason"] == "analysis_error"
    assert "private exception text" not in " ".join(record["warnings"])
    assert "D:/internal/sample.apk" not in " ".join(record["warnings"])
    assert record["failure_reason"] != "packed_obfuscated"
