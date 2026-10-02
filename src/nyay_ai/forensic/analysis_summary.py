"""
NYAYAI - Forensic Analysis Summary
Module Lead: Anu Sharma (Forensic & AI Analysis Engineer)

Creates a concise, evidence-based summary from forensic analysis
results.

The summary:
- Preserves the evidence identifier.
- Reports the analysis type.
- Reports SHA-256 availability.
- Counts forensic indicators.
- Provides a neutral review status.
- Does not claim that indicators prove tampering.
"""

from __future__ import annotations

from typing import Any, Dict, List


class ForensicAnalysisSummary:
    """
    Create a structured summary of forensic analysis findings.
    """

    def create_summary(
        self,
        evidence_id: str,
        analysis_type: str,
        analysis_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Create a concise forensic analysis summary.
        """

        indicators: List[str] = analysis_result.get(
            "tamper_indicators",
            analysis_result.get("anomalies", []),
        )

        sha256 = analysis_result.get("sha256")

        if indicators:
            review_status = "further_review_required"
        else:
            review_status = "no_indicators_detected"

        return {
            "evidence_id": evidence_id,
            "analysis_type": analysis_type,
            "sha256_available": bool(sha256),
            "indicator_count": len(indicators),
            "forensic_indicators": indicators,
            "review_status": review_status,
            "assessment": "not_conclusive",
            "note": (
                "Forensic indicators are observations that may "
                "require further investigation. They do not by "
                "themselves prove tampering or authenticity."
            ),
        }
