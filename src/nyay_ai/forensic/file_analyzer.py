"""Concrete forensic analyzer implementation."""

from __future__ import annotations

import hashlib
import mimetypes
import os
from typing import Any, Dict

from nyay_ai.core.base_analyzer import BaseForensicAnalyzer


class FileForensicAnalyzer(BaseForensicAnalyzer):
    """Reference forensic implementation for file-based evidence."""

    CHUNK_SIZE = 65536

    def calculate_sha256(self, file_path: str) -> str:
        """Calculate a deterministic SHA-256 hash using streaming chunks."""
        digest = hashlib.sha256()
        with open(file_path, "rb") as handle:
            for chunk in iter(lambda: handle.read(self.CHUNK_SIZE), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def extract_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract metadata, file attributes, and evidence integrity values."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        stat_result = os.stat(file_path)
        guessed_mime, _ = mimetypes.guess_type(file_path)

        return {
            "file_path": file_path,
            "file_name": os.path.basename(file_path),
            "file_size_bytes": stat_result.st_size,
            "file_extension": os.path.splitext(file_path)[1].lower(),
            "mime_type": guessed_mime,
            "sha256": self.calculate_sha256(file_path),
            "created_at": stat_result.st_ctime,
            "modified_at": stat_result.st_mtime,
            "accessed_at": stat_result.st_atime,
            "inode": stat_result.st_ino,
            "is_regular_file": os.path.isfile(file_path),
            "owner_uid": stat_result.st_uid,
            "owner_gid": stat_result.st_gid,
        }

    def verify_file_signature(self, file_path: str, declared_mime: str) -> Dict[str, Any]:
        """Verify file magic bytes against the declared MIME type.

        This helps detect extension spoofing or mislabeled artifact files.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        with open(file_path, "rb") as handle:
            magic_bytes = handle.read(512)

        detected_mime = self._detect_mime_from_magic(magic_bytes)
        matches = detected_mime == declared_mime

        return {
            "file_path": file_path,
            "declared_mime": declared_mime,
            "detected_mime": detected_mime,
            "matches_declared_mime": matches,
            "magic_bytes_hex": magic_bytes[:16].hex(),
            "note": (
                "Signature verified against declared MIME type."
                if matches
                else "Declared MIME type does not match the file signature."
            ),
        }

    def _detect_mime_from_magic(self, header: bytes) -> str:
        """Infer MIME type from common magic bytes."""
        if header.startswith(b"\x89PNG\r\n\x1a\n"):
            return "image/png"
        if header.startswith(b"\xFF\xD8\xFF"):
            return "image/jpeg"
        if header.startswith(b"GIF87a") or header.startswith(b"GIF89a"):
            return "image/gif"
        if header.startswith(b"PK\x03\x04"):
            return "application/zip"
        if header.startswith(b"%PDF-"):
            return "application/pdf"
        if header.startswith(b"\x7FELF"):
            return "application/x-executable"
        if header.startswith(b"MZ"):
            return "application/x-msdownload"
        if header.startswith(b"\x25\x50\x44\x46"):
            return "application/pdf"
        return "application/octet-stream"
