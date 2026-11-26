"""Deterministic static extraction of Android APK packages."""

from __future__ import annotations

import hashlib
import os
import re
import threading
import uuid
from pathlib import Path
from queue import Queue
from typing import Any

from androguard.core.apk import APK

from sg_analysis.intake import validate_intake


ANALYSIS_VERSION = "v1.0"
ANALYSIS_TIMEOUT_SECONDS = float(os.environ.get("SG_ANALYSIS_TIMEOUT_S", "60"))
RAW_BOT_TOKEN_RE = re.compile(r"[0-9]+:[A-Za-z0-9_-]{30,}")
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.CAMERA",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.USE_SIP",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.BODY_SENSORS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECEIVE_MMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.POST_NOTIFICATIONS",
}


def _job_id(value: str) -> str:
    """Accept a UUID v4 or make a deterministic v4-shaped UUID."""
    try:
        parsed = uuid.UUID(str(value))
        if parsed.version == 4:
            return str(parsed)
    except (ValueError, AttributeError):
        pass
    generated = uuid.uuid5(uuid.NAMESPACE_URL, f"sideloadguard:{value}")
    return str(uuid.UUID(hex=generated.hex, version=4))


def _safe_claimed_filename(value: str | None) -> str | None:
    if value is None:
        return None
    safe = RAW_BOT_TOKEN_RE.sub("[redacted]", str(value).replace("\\", "/").rsplit("/", 1)[-1])
    return safe[:100] or None


def _base_record(job_id: str, intake: dict, claimed_filename: str | None) -> dict:
    return {
        "schema_version": "1.0",
        "job_id": _job_id(job_id),
        "analysis_version": ANALYSIS_VERSION,
        "analysis_status": "failed",
        "failure_reason": "invalid_apk",
        "file": {
            "sha256": intake["sha256"],
            "size_bytes": intake["size_bytes"],
            "detected_type": intake["detected_type"],
            "claimed_filename": _safe_claimed_filename(claimed_filename),
        },
        "app": {"label": None, "package_name": None, "version_name": None, "min_sdk": None, "target_sdk": None},
        "certificate": {"signed": None, "sha256_fingerprints": [], "subject": None, "self_signed": None, "debug_cert": None},
        "permissions": {"requested": [], "dangerous": []},
        "components": {
            "has_launcher_activity": False,
            "has_accessibility_service": False,
            "has_device_admin": False,
            "has_sms_receiver": False,
            "requests_install_packages": False,
            "requests_overlay": False,
            "embedded_apk_or_dex": False,
            "dynamic_code_loading": False,
        },
        "indicators": {"urls": [], "domains": [], "ip_addresses": [], "cloud_endpoints": [], "token_hashes": []},
        "rule_hits": [],
        "impersonation": {"claimed_brand": None, "match_basis": None, "cert_matches_reference": None, "confidence": 0},
        "features": {},
        "warnings": [],
    }


def compute_features(record: dict) -> dict:
    """Compute the R2 feature map exactly from a Findings Record."""
    permissions = record["permissions"]
    indicators = record["indicators"]
    certificate = record["certificate"]
    components = record["components"]
    hits = record["rule_hits"]
    return {
        "num_requested_permissions": len(permissions["requested"]),
        "num_dangerous_permissions": len(permissions["dangerous"]),
        "num_urls": len(indicators["urls"]),
        "num_domains": len(indicators["domains"]),
        "num_ip_addresses": len(indicators["ip_addresses"]),
        "num_cloud_endpoints": len(indicators["cloud_endpoints"]),
        "num_token_hashes": len(indicators["token_hashes"]),
        "num_cert_fingerprints": len(certificate["sha256_fingerprints"]),
        "num_rule_hits": len(hits),
        "num_high_severity_hits": sum(hit["severity"] == "high" for hit in hits),
        "num_medium_severity_hits": sum(hit["severity"] == "medium" for hit in hits),
        "num_low_severity_hits": sum(hit["severity"] == "low" for hit in hits),
        "has_launcher_activity": bool(components["has_launcher_activity"]),
        "has_accessibility_service": bool(components["has_accessibility_service"]),
        "has_device_admin": bool(components["has_device_admin"]),
        "has_sms_receiver": bool(components["has_sms_receiver"]),
        "requests_install_packages": bool(components["requests_install_packages"]),
        "requests_overlay": bool(components["requests_overlay"]),
        "embedded_apk_or_dex": bool(components["embedded_apk_or_dex"]),
        "dynamic_code_loading": bool(components["dynamic_code_loading"]),
        "is_signed": bool(certificate["signed"]),
        "is_self_signed": bool(certificate["self_signed"]),
        "is_debug_cert": bool(certificate["debug_cert"]),
    }


def _safe_int(value: Any) -> int | None:
    try:
        parsed = int(value)
        return parsed if parsed >= 1 else None
    except (TypeError, ValueError):
        return None


def _certificate_summary(apk: APK) -> tuple[dict, list[str]]:
    warnings: list[str] = []
    try:
        certificates = apk.get_certificates()
        signed = apk.is_signed()
    except Exception as exc:
        return {"signed": None, "sha256_fingerprints": [], "subject": None, "self_signed": None, "debug_cert": None}, [
            f"Certificate extraction failed: {type(exc).__name__}"
        ]

    fingerprints: list[str] = []
    subject_text: str | None = None
    self_signed: bool | None = None
    debug_cert: bool | None = None
    for certificate in certificates:
        try:
            der = certificate.dump()
            fingerprints.append(hashlib.sha256(der).hexdigest())
        except Exception as exc:
            warnings.append(f"Certificate fingerprint failed: {type(exc).__name__}")
        try:
            native = certificate.subject.native
            subject_text = ", ".join(f"{key}={value}" for key, value in native.items()) if native else None
        except Exception:
            subject_text = None
        try:
            subject = certificate.subject.native
            issuer = certificate.issuer.native
            self_signed = subject == issuer
            subject_text_lower = str(subject).lower()
            issuer_text_lower = str(issuer).lower()
            debug_cert = "android debug" in subject_text_lower or "android debug" in issuer_text_lower
        except Exception as exc:
            warnings.append(f"Certificate identity check failed: {type(exc).__name__}")
    fingerprints = sorted(set(fingerprints))
    return {
        "signed": signed,
        "sha256_fingerprints": fingerprints,
        "subject": subject_text,
        "self_signed": self_signed if certificates else None,
        "debug_cert": debug_cert if certificates else None,
    }, warnings


def _manifest_components(apk: APK, permissions: list[str]) -> tuple[dict, list[str]]:
    warnings: list[str] = []
    try:
        manifest = apk.get_android_manifest_xml()
        android_ns = "{http://schemas.android.com/apk/res/android}"
        main_actions = apk.get_main_activities()
        has_launcher = bool(main_actions)
        if not has_launcher:
            for activity in manifest.iter("activity"):
                for intent in activity.findall("intent-filter"):
                    actions = {item.get(android_ns + "name") for item in intent.findall("action")}
                    categories = {item.get(android_ns + "name") for item in intent.findall("category")}
                    if "android.intent.action.MAIN" in actions and "android.intent.category.LAUNCHER" in categories:
                        has_launcher = True
                        break

        accessibility = any(
            service.find("meta-data") is not None
            and any(
                meta.get(android_ns + "resource") in {"@string/accessibility_service_description", "@xml/accessibility_service_config"}
                or meta.get(android_ns + "name") == "android.accessibilityservice"
                for meta in service.findall("meta-data")
            )
            for service in manifest.iter("service")
        )
        if not accessibility:
            accessibility = any(
                service.get(android_ns + "name", "").lower().endswith("accessibilityservice")
                for service in manifest.iter("service")
            )

        device_admin = False
        for receiver in manifest.iter("receiver"):
            for meta in receiver.findall("meta-data"):
                if meta.get(android_ns + "resource", "").endswith("device_admin") or meta.get(android_ns + "name") == "android.app.device_admin":
                    device_admin = True

        sms_receiver = False
        for receiver in manifest.iter("receiver"):
            for intent in receiver.findall("intent-filter"):
                actions = {item.get(android_ns + "name") for item in intent.findall("action")}
                if "android.provider.Telephony.SMS_RECEIVED" in actions:
                    sms_receiver = True
        sms_receiver = sms_receiver or "android.permission.RECEIVE_SMS" in permissions

        files = apk.get_files()
        embedded = any(
            name.lower().endswith(".apk")
            or (name.lower().endswith(".dex") and not name.lower().startswith("classes"))
            for name in files
        )
        # This is intentionally limited to manifest/static archive evidence.
        dynamic = any(name.lower().endswith(".jar") for name in files)
    except Exception as exc:
        return {
            "has_launcher_activity": False,
            "has_accessibility_service": False,
            "has_device_admin": False,
            "has_sms_receiver": False,
            "requests_install_packages": False,
            "requests_overlay": False,
            "embedded_apk_or_dex": False,
            "dynamic_code_loading": False,
        }, [f"Component extraction failed: {type(exc).__name__}"]

    return {
        "has_launcher_activity": has_launcher,
        "has_accessibility_service": accessibility,
        "has_device_admin": device_admin or "android.permission.BIND_DEVICE_ADMIN" in permissions,
        "has_sms_receiver": sms_receiver,
        "requests_install_packages": "android.permission.REQUEST_INSTALL_PACKAGES" in permissions,
        "requests_overlay": "android.permission.SYSTEM_ALERT_WINDOW" in permissions,
        "embedded_apk_or_dex": embedded,
        "dynamic_code_loading": dynamic,
    }, warnings


def _extract(apk_path: str, record: dict) -> dict:
    """Run one Androguard extraction pass."""
    apk = APK(apk_path)
    warnings: list[str] = []

    try:
        record["app"]["package_name"] = apk.get_package() or None
    except Exception as exc:
        warnings.append(f"Package extraction failed: {type(exc).__name__}")
    try:
        record["app"]["label"] = apk.get_app_name() or None
    except Exception as exc:
        warnings.append(f"Label extraction failed: {type(exc).__name__}")
    try:
        record["app"]["version_name"] = apk.get_androidversion_name() or None
    except Exception as exc:
        warnings.append(f"Version extraction failed: {type(exc).__name__}")
    try:
        record["app"]["min_sdk"] = _safe_int(apk.get_min_sdk_version())
    except Exception as exc:
        warnings.append(f"Minimum SDK extraction failed: {type(exc).__name__}")
    try:
        record["app"]["target_sdk"] = _safe_int(apk.get_target_sdk_version())
    except Exception as exc:
        warnings.append(f"Target SDK extraction failed: {type(exc).__name__}")

    try:
        requested = sorted(set(apk.get_permissions()))
    except Exception as exc:
        requested = []
        warnings.append(f"Permission extraction failed: {type(exc).__name__}")
    record["permissions"]["requested"] = requested
    record["permissions"]["dangerous"] = sorted(permission for permission in requested if permission in DANGEROUS_PERMISSIONS)

    components, component_warnings = _manifest_components(apk, requested)
    record["components"] = components
    warnings.extend(component_warnings)

    certificate, certificate_warnings = _certificate_summary(apk)
    record["certificate"] = certificate
    warnings.extend(certificate_warnings)

    record["warnings"] = warnings
    record["features"] = compute_features(record)
    record["analysis_status"] = "partial" if warnings else "ok"
    record["failure_reason"] = "packed_obfuscated" if warnings else None
    return record


def analyze_apk(path: str | os.PathLike[str], job_id: str, claimed_filename: str | None = None, timeout_seconds: float | None = None) -> dict:
    """Analyze an APK fully and never raise to the caller."""
    source = Path(path)
    intake = validate_intake(source)
    record = _base_record(job_id, intake, claimed_filename)
    record["features"] = compute_features(record)

    if not intake["ok"]:
        record["failure_reason"] = intake["failure_reason"]
        record["warnings"] = [intake.get("message", "Input validation failed.")]
        record["features"] = compute_features(record)
        return record

    budget = ANALYSIS_TIMEOUT_SECONDS if timeout_seconds is None else max(0.0, float(timeout_seconds))
    result_queue: Queue[dict | BaseException] = Queue(maxsize=1)

    def worker() -> None:
        try:
            result_queue.put(_extract(str(source), record))
        except BaseException as exc:
            result_queue.put(exc)

    # A daemon worker is the Windows-safe timeout mechanism: it avoids killing the process,
    # but prevents the worker thread from delaying process shutdown.
    worker_thread = threading.Thread(target=worker, daemon=True)
    worker_thread.start()
    worker_thread.join(budget)

    if worker_thread.is_alive():
        record["analysis_status"] = "failed"
        record["failure_reason"] = "timeout"
        record["warnings"] = ["Androguard analysis exceeded the time budget."]
        record["features"] = compute_features(record)
        return record

    try:
        outcome = result_queue.get_nowait()
    except Exception:
        record["analysis_status"] = "failed"
        record["failure_reason"] = "invalid_apk"
        record["warnings"] = ["Androguard returned no result."]
        record["features"] = compute_features(record)
        return record

    if isinstance(outcome, BaseException):
        record["analysis_status"] = "failed"
        record["failure_reason"] = "invalid_apk"
        record["warnings"] = [f"Androguard analysis failed: {type(outcome).__name__}"]
        record["features"] = compute_features(record)
        return record
    return outcome
