import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from sg_analysis.analyze import analyze_apk


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "shared" / "schemas" / "findings_record.schema.json").read_text(encoding="utf-8"))
JOB_ID = "12345678-1234-4abc-8def-1234567890ab"


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
