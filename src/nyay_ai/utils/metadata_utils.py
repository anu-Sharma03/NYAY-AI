"""Metadata extraction helpers."""

import mimetypes
import os


def extract_file_metadata(file_path: str) -> dict:
    """Return basic metadata attributes for a file."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    stat_result = os.stat(file_path)
    mime_type, _ = mimetypes.guess_type(file_path)

    return {
        "file_path": file_path,
        "file_name": os.path.basename(file_path),
        "file_size_bytes": stat_result.st_size,
        "file_extension": os.path.splitext(file_path)[1].lower(),
        "mime_type": mime_type,
        "created_at": stat_result.st_ctime,
        "modified_at": stat_result.st_mtime,
        "accessed_at": stat_result.st_atime,
    }
