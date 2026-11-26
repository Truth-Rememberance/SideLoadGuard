"""Command-line entry point for static APK analysis."""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path

from jsonschema import Draft202012Validator

from sg_analysis.analyze import analyze_apk


def _schema_path() -> Path:
    return Path(__file__).resolve().parents[1] / "shared" / "schemas" / "findings_record.schema.json"


def main(argv: list[str] | None = None) -> int:
    """Write a Findings Record and return the contract exit code."""
    parser = argparse.ArgumentParser(description="SideloadGuard static APK analyzer")
    parser.add_argument("--input", required=True)
    parser.add_argument("--job-id")
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)

    job_id = args.job_id or str(uuid.uuid4())
    try:
        record = analyze_apk(args.input, job_id)
    except BaseException:
        record = {
            "schema_version": "1.0",
            "job_id": job_id if _valid_job_id(job_id) else str(uuid.uuid4()),
            "analysis_version": "v1.0",
            "analysis_status": "failed",
            "failure_reason": "invalid_apk",
            "file": {"sha256": "0" * 64, "size_bytes": 0, "detected_type": "unknown", "claimed_filename": None},
            "app": {"label": None, "package_name": None, "version_name": None, "min_sdk": None, "target_sdk": None},
            "certificate": {"signed": None, "sha256_fingerprints": [], "subject": None, "self_signed": None, "debug_cert": None},
            "permissions": {"requested": [], "dangerous": []},
            "components": {
                "has_launcher_activity": False, "has_accessibility_service": False,
                "has_device_admin": False, "has_sms_receiver": False,
                "requests_install_packages": False, "requests_overlay": False,
                "embedded_apk_or_dex": False, "dynamic_code_loading": False,
            },
            "indicators": {"urls": [], "domains": [], "ip_addresses": [], "cloud_endpoints": [], "token_hashes": []},
            "rule_hits": [],
            "impersonation": {"claimed_brand": None, "match_basis": None, "cert_matches_reference": None, "confidence": 0},
            "features": {},
            "warnings": ["Analysis failed safely."],
        }
        from sg_analysis.analyze import compute_features
        record["features"] = compute_features(record)

    output = Path(args.out)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    with _schema_path().open("r", encoding="utf-8") as handle:
        schema = json.load(handle)
    Draft202012Validator(schema).validate(record)

    if record["analysis_status"] == "ok":
        print("Analysis status: ok")
        return 0
    if record["failure_reason"] == "timeout":
        print("Analysis status: failed")
        return 3
    if record["failure_reason"] == "unpack_limit":
        print("Analysis status: failed")
        return 4
    print(f"Analysis status: {record['analysis_status']}")
    return 2


def _valid_job_id(value: str) -> bool:
    try:
        parsed = uuid.UUID(value)
        return parsed.version == 4
    except (ValueError, AttributeError):
        return False


if __name__ == "__main__":
    sys.exit(main())
