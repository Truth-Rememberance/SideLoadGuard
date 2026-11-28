import io
import zipfile

from sg_analysis.intake import INTAKE_LIMITS, validate_intake


def write_zip(tmp_path, name, entries):
    path = tmp_path / name
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for entry_name, content in entries:
            archive.writestr(entry_name, content)
    return path


def test_valid_minimal_apk_like_zip(tmp_path):
    path = write_zip(tmp_path, "sample.bin", [
        ("AndroidManifest.xml", b"<manifest/>"),
        ("classes.dex", b"dex"),
    ])
    result = validate_intake(path)
    assert result["ok"] is True
    assert result["detected_type"] == "apk"
    assert len(result["sha256"]) == 64


def test_plain_text_apk_extension(tmp_path):
    path = tmp_path / "sample.apk"
    path.write_text("plain text", encoding="utf-8")
    result = validate_intake(path)
    assert result["ok"] is False
    assert result["detected_type"] == "other"
    assert result["failure_reason"] == "invalid_apk"


def test_empty_file(tmp_path):
    path = tmp_path / "empty.apk"
    path.write_bytes(b"")
    result = validate_intake(path)
    assert result["ok"] is False
    assert result["failure_reason"] == "invalid_apk"


def test_truncated_zip(tmp_path):
    path = tmp_path / "broken.apk"
    path.write_bytes(b"PK\x03\x04truncated")
    result = validate_intake(path)
    assert result["ok"] is False
    assert result["detected_type"] == "other"
    assert result["failure_reason"] == "invalid_apk"


def test_zip_slip_rejected(tmp_path):
    path = write_zip(tmp_path, "sample.zip", [
        ("AndroidManifest.xml", b"<manifest/>"),
        ("classes.dex", b"dex"),
        ("../escape.txt", b"bad"),
    ])
    result = validate_intake(path)
    assert result["ok"] is False
    assert result["failure_reason"] == "unpack_limit"


def test_too_many_entries_with_small_test_limit(tmp_path, monkeypatch):
    monkeypatch.setitem(INTAKE_LIMITS, "max_entry_count", 2)
    path = write_zip(tmp_path, "sample.apk", [
        ("AndroidManifest.xml", b"<manifest/>"),
        ("classes.dex", b"dex"),
        ("extra.txt", b"x"),
    ])
    result = validate_intake(path)
    assert result["failure_reason"] == "unpack_limit"


def test_high_compression_ratio_with_small_limit(tmp_path, monkeypatch):
    monkeypatch.setitem(INTAKE_LIMITS, "max_compression_ratio", 2)
    path = write_zip(tmp_path, "sample.apk", [
        ("AndroidManifest.xml", b"<manifest/>"),
        ("classes.dex", b"A" * 100_000),
    ])
    result = validate_intake(path)
    assert result["failure_reason"] == "unpack_limit"


def test_wrong_extension_real_zip(tmp_path):
    path = write_zip(tmp_path, "sample.bin", [
        ("AndroidManifest.xml", b"<manifest/>"),
        ("classes2.dex", b"dex"),
    ])
    result = validate_intake(path)
    assert result["ok"] is True
    assert result["detected_type"] == "apk"
