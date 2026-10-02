"""
NYAYAI - Evidence Integrity Verifier
Module Lead: Anu Sharma (Forensic & AI Analysis Engineer)

Verifies evidence integrity by comparing a current SHA-256 hash
with a previously recorded SHA-256 hash.

The verifier:
- Reads the evidence file without modifying it.
- Calculates a fresh SHA-256 hash.
- Compares it with the recorded hash.
- Reports whether the hashes match.
- Does not claim that a matching hash proves authenticity.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict


class EvidenceIntegrityVerifier:
    """
    Verify evidence integrity using SHA-256 hash comparison.
    """

    CHUNK_SIZE = 65536

    def calculate_sha256(self, file_path: str) -> str:
        """
        Calculate the SHA-256 hash of an evidence file.
        """

        sha256 = hashlib.sha256()

        with open(file_path, "rb") as file:
            for chunk in iter(
                lambda: file.read(self.CHUNK_SIZE),
                b"",
            ):
                sha256.update(chunk)

        return sha256.hexdigest()

    def verify(
        self,
        file_path: str,
        recorded_sha256: str,
    ) -> Dict[str, Any]:
        """
        Compare the current evidence hash with a recorded SHA-256 hash.
        """

        current_sha256 = self.calculate_sha256(file_path)

        normalized_recorded = recorded_sha256.strip().lower()
        normalized_current = current_sha256.lower()

        hashes_match = (
            normalized_current == normalized_recorded
        )

        return {
            "file_path": file_path,
            "recorded_sha256": normalized_recorded,
            "current_sha256": normalized_current,
            "hashes_match": hashes_match,
            "integrity_status": (
                "hash_match"
                if hashes_match
                else "hash_mismatch"
            ),
            "assessment": "not_conclusive",
            "note": (
                "A matching SHA-256 hash indicates that the file "
                "content matches the recorded hash. It does not by "
                "itself prove the authenticity or origin of the "
                "evidence."
            ),
        }
