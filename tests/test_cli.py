import json
import re
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples" / "benign"
SCHEMA = json.loads((ROOT / "shared" / "schemas" / "findings_record.schema.json").read_text(encoding="utf-8"))


def run_cli(tmp_path, input_path):
    output = tmp_path / "result.json"
    result = subprocess.run(
        [sys.executable, "-m", "sg_analysis.cli", "--input", str(input_path), "--job-id", str(uuid.uuid4()), "--out", str(output)],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert output.exists()
    record = json.loads(output.read_text(encoding="utf-8"))
    Draft202012Validator(SCHEMA).validate(record)
    return result.returncode, record


def test_cli_benign_sample_and_broken_file(tmp_path):
    apks = sorted(SAMPLES.glob("*.apk")) if SAMPLES.exists() else []
    if not apks:
        pytest.skip("No safe APK samples in samples/benign/")

    exit_code, record = run_cli(tmp_path, apks[0])
    assert exit_code in {0, 2}

    broken = tmp_path / "broken.apk"
    broken.write_text("broken", encoding="utf-8")
    exit_code, record = run_cli(tmp_path, broken)
    assert exit_code == 2
    assert record["analysis_status"] == "failed"


def test_cli_benign_sample_suppresses_androguard_logs(tmp_path):
    apks = sorted(SAMPLES.glob("*.apk")) if SAMPLES.exists() else []
    if not apks:
        pytest.skip("No safe APK samples in samples/benign/")

    output = tmp_path / "benign-findings.json"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "sg_analysis.cli",
            "--input",
            str(apks[0]),
            "--job-id",
            str(uuid.uuid4()),
            "--out",
            str(output),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    combined_output = result.stdout + result.stderr

    assert result.returncode == 0
    assert output.exists()
    Draft202012Validator(SCHEMA).validate(json.loads(output.read_text(encoding="utf-8")))
    assert len(combined_output) < 2_000
    assert len(combined_output.splitlines()) <= 1
    assert not re.search(
        r"(?m)^\d{4}-\d{2}-\d{2}.*\b(?:DEBUG|WARNING)\b",
        combined_output,
    )
