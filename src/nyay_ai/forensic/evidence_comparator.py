"""
NYAYAI - Evidence Comparator
Module Lead: Anu Sharma (Forensic & AI Analysis Engineer)

Compares cryptographic hashes associated with two evidence items.

The comparator:
- Normalizes SHA-256 hash values.
- Compares the hashes.
- Reports whether the hashes match.
- Does not claim authenticity or provenance.
"""

from __future__ import annotations

from typing import Any, Dict


class EvidenceComparator:
    """
    Compare SHA-256 hashes associated with evidence items.
    """

    def compare(
        self,
        evidence_a_id: str,
        evidence_a_sha256: str,
        evidence_b_id: str,
        evidence_b_sha256: str,
    ) -> Dict[str, Any]:
        """
        Compare two SHA-256 hash values.
        """

        normalized_a = evidence_a_sha256.strip().lower()
        normalized_b = evidence_b_sha256.strip().lower()

        hashes_match = normalized_a == normalized_b

        return {
            "evidence_a_id": evidence_a_id,
            "evidence_b_id": evidence_b_id,
            "evidence_a_sha256": normalized_a,
            "evidence_b_sha256": normalized_b,
            "hashes_match": hashes_match,
            "comparison_status": (
                "same_content_hash"
                if hashes_match
                else "different_content_hash"
            ),
            "assessment": "not_conclusive",
            "note": (
                "A matching SHA-256 hash indicates matching "
                "file content under the compared hashes. It does "
                "not by itself prove authenticity, origin, or "
                "chain of custody."
            ),
        }
