import json
import re
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from sg_analysis.analyze import analyze_apk


ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples" / "benign"
SCHEMA = json.loads((ROOT / "shared" / "schemas" / "findings_record.schema.json").read_text(encoding="utf-8"))
JOB_ID = "12345678-1234-4abc-8def-1234567890ab"
RAW_TOKEN_RE = re.compile(r"[0-9]+:[A-Za-z0-9_-]{30,}")


def string_values(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from string_values(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from string_values(item)


def benign_apks():
    if not SAMPLES.exists():
        return []
    return sorted(SAMPLES.glob("*.apk"))


@pytest.mark.parametrize("apk_path", benign_apks(), ids=lambda path: path.name)
def test_real_benign_apks(apk_path):
    first = analyze_apk(apk_path, JOB_ID)
    second = analyze_apk(apk_path, JOB_ID)
    Draft202012Validator(SCHEMA).validate(first)
    assert first["analysis_status"] in {"ok", "partial"}
    assert first == second
    for text in string_values(first):
        assert not RAW_TOKEN_RE.search(text)
