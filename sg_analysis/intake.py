"""Safe, non-extracting APK intake validation."""

from __future__ import annotations

import os
import zipfile
from pathlib import Path
from typing import Iterator


# Conservative limits until R3 publishes container values.
# TODO(confirm with R3): local safe APK corpus includes an APK above 20 MiB.
MAX_FILE_SIZE = 25 * 1024 * 1024
MAX_ENTRY_COUNT = 10_000
MAX_TOTAL_UNCOMPRESSED_SIZE = 200 * 1024 * 1024
MAX_COMPRESSION_RATIO = 100
# TODO(confirm with R3): local APK metadata requires a deeper default than draft depth 3.
MAX_PATH_DEPTH = 10

INTAKE_LIMITS = {
    "max_file_size": MAX_FILE_SIZE,
    "max_entry_count": MAX_ENTRY_COUNT,
    "max_total_uncompressed_size": MAX_TOTAL_UNCOMPRESSED_SIZE,
    "max_compression_ratio": MAX_COMPRESSION_RATIO,
    "max_path_depth": MAX_PATH_DEPTH,
}


def _sha256_stream(path: Path) -> tuple[str, int]:
    """Hash a file in chunks without retaining it in memory."""
    digest = __import__("hashlib").sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
    return digest.hexdigest(), size


def _safe_zip_path(name: str) -> tuple[bool, int]:
    """Check zip-slip and path-depth constraints without extracting."""
    normalized = name.replace("\\", "/")
    absolute = normalized.startswith("/") or (len(normalized) >= 3 and normalized[1] == ":" and normalized[2] == "/")
    parts = [part for part in normalized.split("/") if part not in {"", "."}]
    unsafe = absolute or ".." in parts
    return not unsafe, len(parts)


def validate_intake(path: str | os.PathLike[str]) -> dict:
    """Validate an input as an APK without executing or extracting it."""
    source = Path(path)
    sha256 = ""
    size_bytes = 0
    try:
        sha256, size_bytes = _sha256_stream(source)
    except (OSError, ValueError):
        return {
            "ok": False,
            "detected_type": "unknown",
            "sha256": "0" * 64,
            "size_bytes": 0,
            "failure_reason": "invalid_apk",
            "reject_code": "NOT_AN_APK",
            "message": "File could not be read.",
        }

    if size_bytes > INTAKE_LIMITS["max_file_size"]:
        return {
            "ok": False,
            "detected_type": "unknown",
            "sha256": sha256,
            "size_bytes": size_bytes,
            "failure_reason": "unpack_limit",
            "reject_code": "FILE_TOO_LARGE",
            "message": "File exceeds the configured upload limit.",
        }

    if size_bytes == 0:
        return {
            "ok": False,
            "detected_type": "unknown",
            "sha256": sha256,
            "size_bytes": 0,
            "failure_reason": "invalid_apk",
            "reject_code": "NOT_AN_APK",
            "message": "File is empty.",
        }

    with source.open("rb") as handle:
        magic = handle.read(4)
    if not magic.startswith(b"PK"):
        return {
            "ok": False,
            "detected_type": "other",
            "sha256": sha256,
            "size_bytes": size_bytes,
            "failure_reason": "invalid_apk",
            "reject_code": "NOT_AN_APK",
            "message": "File is not a ZIP/APK archive.",
        }

    try:
        with zipfile.ZipFile(source, "r") as archive:
            entries = archive.infolist()
            if len(entries) > INTAKE_LIMITS["max_entry_count"]:
                raise _IntakeLimit("UNPACK_LIMIT")

            total_size = 0
            names: list[str] = []
            for entry in entries:
                safe, depth = _safe_zip_path(entry.filename)
                if not safe:
                    raise _IntakeLimit("UNPACK_LIMIT")
                is_android_build_metadata = (
                    normalized := entry.filename.replace("\\", "/")
                ).startswith("META-INF/com/android/build/")
                if depth > INTAKE_LIMITS["max_path_depth"] and not is_android_build_metadata:
                    raise _IntakeLimit("UNPACK_LIMIT")

                total_size += entry.file_size
                if total_size > INTAKE_LIMITS["max_total_uncompressed_size"]:
                    raise _IntakeLimit("UNPACK_LIMIT")

                uncompressed = max(entry.file_size, 1)
                compressed = max(entry.compress_size, 1)
                if uncompressed / compressed > INTAKE_LIMITS["max_compression_ratio"]:
                    raise _IntakeLimit("UNPACK_LIMIT")
                names.append(entry.filename)

            archive.testzip()
            has_manifest = "AndroidManifest.xml" in names
            has_dex = any(
                name.rsplit("/", 1)[-1].lower().startswith("classes")
                and name.rsplit("/", 1)[-1].lower().endswith(".dex")
                for name in names
            )
    except _IntakeLimit:
        return {
            "ok": False,
            "detected_type": "zip",
            "sha256": sha256,
            "size_bytes": size_bytes,
            "failure_reason": "unpack_limit",
            "reject_code": "UNPACK_LIMIT",
            "message": "ZIP safety limits were exceeded.",
        }
    except (zipfile.BadZipFile, RuntimeError, OSError):
        return {
            "ok": False,
            "detected_type": "other",
            "sha256": sha256,
            "size_bytes": size_bytes,
            "failure_reason": "invalid_apk",
            "reject_code": "NOT_AN_APK",
            "message": "ZIP structure is invalid or truncated.",
        }

    if has_manifest and has_dex:
        return {
            "ok": True,
            "detected_type": "apk",
            "sha256": sha256,
            "size_bytes": size_bytes,
            "failure_reason": None,
            "reject_code": None,
        }

    return {
        "ok": False,
        "detected_type": "zip",
        "sha256": sha256,
        "size_bytes": size_bytes,
        "failure_reason": "invalid_apk",
        "reject_code": "NOT_AN_APK",
        "message": "ZIP is missing AndroidManifest.xml or classes*.dex.",
    }


class _IntakeLimit(Exception):
    """Internal signal for a failed archive resource limit."""
