"""
NYAYAI - Unified Forensic Report
Module Lead: Anu Sharma (Forensic & AI Analysis Engineer)

Creates a common forensic report structure from media analysis results.

The report:
- Preserves the original evidence path.
- Records the evidence type.
- Includes SHA-256 integrity information.
- Includes forensic metadata.
- Includes tamper/forensic indicators.
- Does not claim that an indicator proves tampering.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict


class UnifiedForensicReport:
    """
    Build a standardized forensic report from an analyzer result.
    """

    def generate(
        self,
        file_path: str,
        evidence_type: str,
        analysis_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Generate a unified forensic report.

        The original evidence is not modified.
        """

        indicators = analysis_result.get(
            "tamper_indicators",
            analysis_result.get("anomalies", []),
        )

        return {
            "report_type": "unified_forensic_report",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "evidence": {
                "file_path": file_path,
                "evidence_type": evidence_type,
                "sha256": analysis_result.get("sha256"),
            },
            "analysis": analysis_result,
            "forensic_indicators": indicators,
            "integrity": {
                "sha256_available": bool(
                    analysis_result.get("sha256")
                ),
                "original_evidence_modified": False,
            },
            "assessment": {
                "status": (
                    "indicators_detected"
                    if indicators
                    else "no_indicators_detected"
                ),
                "certainty": "not_conclusive",
                "note": (
                    "Forensic indicators require further investigation "
                    "and do not by themselves prove that evidence was "
                    "tampered with."
                ),
            },
        }
