"""Safe ZIP archive handling for Sentinel.

This module safely inspects and extracts ZIP files for scanning.

Security protections:
- Blocks path traversal / Zip Slip attacks.
- Blocks absolute paths and Windows drive paths.
- Limits number of extracted files.
- Limits total extracted size.
- Limits single extracted file size.
- Extracts only into a temporary folder.
- Does not execute extracted files.
"""

from __future__ import annotations

import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Any


MAX_ARCHIVE_FILES = 100
MAX_TOTAL_EXTRACTED_BYTES = 50 * 1024 * 1024
MAX_SINGLE_EXTRACTED_FILE_BYTES = 25 * 1024 * 1024


def is_zip_file(file_path: str) -> bool:
    """
    Returns True if the selected file appears to be a valid ZIP archive.
    """

    path = Path(file_path)

    if path.suffix.lower() != ".zip":
        return False

    return zipfile.is_zipfile(path)


def _is_safe_zip_member(member_name: str) -> bool:
    """
    Prevent Zip Slip/path traversal.

    Unsafe examples:
        ../../evil.exe
        /absolute/path/evil.exe
        C:\\Windows\\evil.exe
    """

    member_path = Path(member_name)

    if member_path.is_absolute():
        return False

    # Windows drive path check, e.g. C:/evil.exe or C:\\evil.exe
    if ":" in member_name:
        return False

    parts = member_path.parts

    if ".." in parts:
        return False

    return True


def safe_extract_zip(file_path: str) -> dict[str, Any]:
    """
    Safely extract a ZIP archive into a temporary folder.

    Returns:
        {
            "success": bool,
            "temp_dir": str | None,
            "extracted_files": list[str],
            "archive_notes": list[str],
            "error": str | None,
        }

    Caller is responsible for cleanup using cleanup_extracted_archive(temp_dir).
    """

    archive_path = Path(file_path).resolve()

    result: dict[str, Any] = {
        "success": False,
        "temp_dir": None,
        "extracted_files": [],
        "archive_notes": [],
        "error": None,
    }

    if not archive_path.exists():
        result["error"] = f"Archive file does not exist: {archive_path}"
        return result

    if not zipfile.is_zipfile(archive_path):
        result["error"] = "Selected file is not a valid ZIP archive."
        return result

    temp_dir = Path(tempfile.mkdtemp(prefix="sentinel_zip_scan_")).resolve()
    result["temp_dir"] = str(temp_dir)

    extracted_files: list[str] = []
    total_uncompressed_size = 0
    scanned_file_count = 0

    try:
        with zipfile.ZipFile(archive_path, "r") as zip_ref:
            members = zip_ref.infolist()

            file_members = [member for member in members if not member.is_dir()]

            if len(file_members) > MAX_ARCHIVE_FILES:
                result["archive_notes"].append(
                    f"Archive contains {len(file_members)} files. "
                    f"Only the first {MAX_ARCHIVE_FILES} files will be extracted."
                )

            for member in file_members:
                if scanned_file_count >= MAX_ARCHIVE_FILES:
                    break

                member_name = member.filename

                if not _is_safe_zip_member(member_name):
                    result["archive_notes"].append(
                        f"Skipped unsafe archive path: {member_name}"
                    )
                    continue

                if member.file_size > MAX_SINGLE_EXTRACTED_FILE_BYTES:
                    result["archive_notes"].append(
                        f"Skipped oversized file in archive: {member_name}"
                    )
                    continue

                if total_uncompressed_size + member.file_size > MAX_TOTAL_EXTRACTED_BYTES:
                    result["archive_notes"].append(
                        "Archive extraction stopped because the total extracted size limit was reached."
                    )
                    break

                target_path = (temp_dir / member_name).resolve()

                # Extra safety: make sure final path remains inside temp_dir.
                if not str(target_path).startswith(str(temp_dir)):
                    result["archive_notes"].append(
                        f"Skipped path escaping extraction folder: {member_name}"
                    )
                    continue

                target_path.parent.mkdir(parents=True, exist_ok=True)

                with zip_ref.open(member, "r") as source_file:
                    with target_path.open("wb") as destination_file:
                        shutil.copyfileobj(source_file, destination_file)

                extracted_files.append(str(target_path))
                total_uncompressed_size += member.file_size
                scanned_file_count += 1

        result["success"] = True
        result["extracted_files"] = extracted_files
        result["archive_notes"].insert(
            0,
            f"ZIP archive detected. Extracted {len(extracted_files)} file(s) safely for scanning.",
        )

        return result

    except Exception as error:
        result["error"] = str(error)
        cleanup_extracted_archive(str(temp_dir))
        result["temp_dir"] = None
        return result


def cleanup_extracted_archive(temp_dir: str | None) -> None:
    """
    Deletes the temporary archive extraction folder.
    """

    if not temp_dir:
        return

    try:
        path = Path(temp_dir).resolve()

        if path.exists() and path.is_dir() and path.name.startswith("sentinel_zip_scan_"):
            shutil.rmtree(path, ignore_errors=True)

    except Exception:
        pass