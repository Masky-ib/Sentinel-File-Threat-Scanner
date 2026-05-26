"""Safe ZIP archive handling for Sentinel.

This module is responsible for safely inspecting and extracting ZIP files
before Sentinel scans their contents.

Important security idea:
    Extracting a file is not the same as executing it.

Sentinel never runs files from an archive. It only extracts them into a
temporary controlled folder so antivirus and rule-based scanning can inspect
them.

Security protections included here:
- Blocks path traversal / Zip Slip attacks.
- Blocks absolute paths and Windows drive paths.
- Limits the number of extracted files.
- Limits total extracted size.
- Limits single extracted file size.
- Extracts only into a temporary Sentinel folder.
- Deletes the temporary folder after scanning.
- Does not execute extracted files.
"""

from __future__ import annotations

import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Any


# Maximum number of files Sentinel will extract from a ZIP.
# This protects the app from archives containing thousands of files.
MAX_ARCHIVE_FILES = 100


# Maximum total extracted size for one archive.
# This helps reduce the risk of ZIP bombs, where a small ZIP expands into
# a very large amount of data.
MAX_TOTAL_EXTRACTED_BYTES = 50 * 1024 * 1024


# Maximum size for a single extracted file.
# This prevents one huge file inside an archive from consuming too much disk
# space or slowing the scan too much.
MAX_SINGLE_EXTRACTED_FILE_BYTES = 25 * 1024 * 1024


def is_zip_file(file_path: str) -> bool:
    """Return True if the selected file appears to be a valid ZIP archive.

    Sentinel checks both:
    - the file extension
    - the actual ZIP structure

    The extension check is fast and avoids trying ZIP parsing on every file.
    The zipfile.is_zipfile check confirms that the file is really a ZIP,
    not just something renamed to .zip.
    """

    path = Path(file_path)

    # Sentinel only treats .zip files as archives for now.
    # This keeps the MVP simple and avoids adding more archive formats before
    # the ZIP flow is stable.
    if path.suffix.lower() != ".zip":
        return False

    # This checks the file header/structure and confirms it is actually a ZIP.
    return zipfile.is_zipfile(path)


def _is_safe_zip_member(member_name: str) -> bool:
    """Check whether a ZIP member path is safe to extract.

    This prevents Zip Slip/path traversal attacks.

    Unsafe examples:
        ../../evil.exe
        /absolute/path/evil.exe
        C:\\Windows\\evil.exe

    A malicious ZIP can contain paths that try to escape the extraction folder.
    Sentinel rejects those paths before writing anything to disk.
    """

    member_path = Path(member_name)

    # Absolute paths are not allowed because they could write outside the
    # temporary extraction folder.
    if member_path.is_absolute():
        return False

    # Windows drive paths are not allowed.
    # Example:
    #     C:/Windows/evil.exe
    #     C:\\Windows\\evil.exe
    #
    # The colon check is simple but effective for blocking drive-letter paths.
    if ":" in member_name:
        return False

    parts = member_path.parts

    # Parent directory references are not allowed.
    # This blocks paths like:
    #     ../../evil.exe
    #     folder/../../../evil.exe
    if ".." in parts:
        return False

    return True


def safe_extract_zip(file_path: str) -> dict[str, Any]:
    """Safely extract a ZIP archive into a temporary folder.

    The caller receives the extraction result and then scans the extracted files.

    Return structure:
        {
            "success": bool,
            "temp_dir": str | None,
            "extracted_files": list[str],
            "archive_notes": list[str],
            "error": str | None,
        }

    The caller is responsible for cleanup using:
        cleanup_extracted_archive(temp_dir)

    Sentinel intentionally returns notes instead of hiding skipped files.
    This makes archive scanning more transparent in the final report.
    """

    archive_path = Path(file_path).resolve()

    # Result object is prepared early so every exit path returns the same shape.
    # This makes scan_router.py easier to work with.
    result: dict[str, Any] = {
        "success": False,
        "temp_dir": None,
        "extracted_files": [],
        "archive_notes": [],
        "error": None,
    }

    # If the archive path no longer exists, stop cleanly instead of crashing.
    if not archive_path.exists():
        result["error"] = f"Archive file does not exist: {archive_path}"
        return result

    # Confirm that the selected file is really a valid ZIP before opening it.
    # This prevents Sentinel from trying to extract corrupted or fake archives.
    if not zipfile.is_zipfile(archive_path):
        result["error"] = "Selected file is not a valid ZIP archive."
        return result

    # Create a temporary folder specifically for this archive scan.
    # tempfile.mkdtemp gives us a unique folder name, reducing the risk of
    # collisions with other scans or user files.
    temp_dir = Path(tempfile.mkdtemp(prefix="sentinel_zip_scan_")).resolve()
    result["temp_dir"] = str(temp_dir)

    extracted_files: list[str] = []
    total_uncompressed_size = 0
    scanned_file_count = 0

    try:
        with zipfile.ZipFile(archive_path, "r") as zip_ref:
            members = zip_ref.infolist()

            # Directories do not need to be scanned.
            # Sentinel only extracts actual files.
            file_members = [member for member in members if not member.is_dir()]

            # If the archive contains too many files, Sentinel does not fail
            # immediately. It scans up to the configured limit and records a note.
            if len(file_members) > MAX_ARCHIVE_FILES:
                result["archive_notes"].append(
                    f"Archive contains {len(file_members)} files. "
                    f"Only the first {MAX_ARCHIVE_FILES} files will be extracted."
                )

            for member in file_members:
                # Stop once Sentinel reaches the file-count limit.
                # This protects the app from archives designed to overload scanning.
                if scanned_file_count >= MAX_ARCHIVE_FILES:
                    break

                member_name = member.filename

                # Reject unsafe paths before calculating or creating target paths.
                # This is the main Zip Slip protection.
                if not _is_safe_zip_member(member_name):
                    result["archive_notes"].append(
                        f"Skipped unsafe archive path: {member_name}"
                    )
                    continue

                # Skip very large individual files.
                # This keeps one large file from dominating the scan.
                if member.file_size > MAX_SINGLE_EXTRACTED_FILE_BYTES:
                    result["archive_notes"].append(
                        f"Skipped oversized file in archive: {member_name}"
                    )
                    continue

                # Stop if extracting this file would exceed the total archive limit.
                # This is one of the protections against ZIP bombs.
                if total_uncompressed_size + member.file_size > MAX_TOTAL_EXTRACTED_BYTES:
                    result["archive_notes"].append(
                        "Archive extraction stopped because the total extracted size limit was reached."
                    )
                    break

                # Build the final extraction path inside the temporary folder.
                target_path = (temp_dir / member_name).resolve()

                # Extra safety check:
                # Even after checking the member name, confirm the resolved final
                # path still starts inside the temporary extraction folder.
                #
                # This is a second layer of protection against weird path behavior.
                if not str(target_path).startswith(str(temp_dir)):
                    result["archive_notes"].append(
                        f"Skipped path escaping extraction folder: {member_name}"
                    )
                    continue

                # Create any needed subfolders inside the temporary directory.
                target_path.parent.mkdir(parents=True, exist_ok=True)

                # Extract by streaming bytes from the ZIP into the target file.
                # Sentinel does not execute the file; it only writes it so later
                # scanning layers can inspect it.
                with zip_ref.open(member, "r") as source_file:
                    with target_path.open("wb") as destination_file:
                        shutil.copyfileobj(source_file, destination_file)

                extracted_files.append(str(target_path))
                total_uncompressed_size += member.file_size
                scanned_file_count += 1

        # Extraction completed successfully.
        result["success"] = True
        result["extracted_files"] = extracted_files

        # Insert this at the top so the final scan report clearly explains that
        # archive scanning happened.
        result["archive_notes"].insert(
            0,
            f"ZIP archive detected. Extracted {len(extracted_files)} file(s) safely for scanning.",
        )

        return result

    except Exception as error:
        # If anything goes wrong during extraction, clean up immediately.
        # A failed archive extraction should not leave temporary files behind.
        result["error"] = str(error)
        cleanup_extracted_archive(str(temp_dir))
        result["temp_dir"] = None
        return result


def cleanup_extracted_archive(temp_dir: str | None) -> None:
    """Delete the temporary archive extraction folder.

    This is important because extracted files may be suspicious or malicious.
    Sentinel should not leave archive contents lying around after the scan.

    The folder-name prefix check is intentional:
        sentinel_zip_scan_

    It reduces the risk of accidentally deleting a folder that was not created
    by Sentinel's archive extraction process.
    """

    if not temp_dir:
        return

    try:
        path = Path(temp_dir).resolve()

        # Only delete folders that look like Sentinel-created ZIP scan folders.
        # This is a safety guard against accidental deletion of unrelated paths.
        if path.exists() and path.is_dir() and path.name.startswith("sentinel_zip_scan_"):
            shutil.rmtree(path, ignore_errors=True)

    except Exception:
        # Cleanup failure should not crash the UI.
        # The scan result itself is more important than raising another error here.
        pass