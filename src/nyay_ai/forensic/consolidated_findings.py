"""
NYAYAI - Consolidated Forensic Findings
Module Lead: Anu Sharma (Forensic & AI Analysis Engineer)

Combines findings from multiple forensic analysis results into
one structured summary.

The consolidated result:
- Preserves the evidence identifier.
- Records all analysis types.
- Collects SHA-256 availability.
- Combines forensic indicators.
- Reports integrity statuses when available.
- Does not make a final tampering or authenticity decision.
"""

from __future__ import annotations

from typing import Any, Dict, List


class ConsolidatedForensicFindings:
    """
    Consolidate findings from multiple forensic analyses.
    """

    def consolidate(
        self,
        evidence_id: str,
        analysis_results: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Combine multiple forensic analysis results.

        Each analysis result may contain:
        - analysis_type
        - sha256
        - tamper_indicators
        - anomalies
        - integrity_status
        """

        analysis_types: List[str] = []
        indicators: List[str] = []
        integrity_statuses: List[str] = []
        sha256_available = False

        for result in analysis_results:
            analysis_type = result.get("analysis_type")

            if analysis_type:
                analysis_types.append(analysis_type)

            sha256 = result.get("sha256")

            if sha256:
                sha256_available = True

            result_indicators = result.get(
                "tamper_indicators",
                result.get("anomalies", []),
            )

            indicators.extend(result_indicators)

            integrity_status = result.get("integrity_status")

            if integrity_status:
                integrity_statuses.append(
                    integrity_status
                )

        if indicators:
            review_status = "further_review_required"
        else:
            review_status = "no_indicators_detected"

        return {
            "evidence_id": evidence_id,
            "analysis_count": len(analysis_results),
            "analysis_types": analysis_types,
            "sha256_available": sha256_available,
            "indicator_count": len(indicators),
            "forensic_indicators": indicators,
            "integrity_statuses": integrity_statuses,
            "review_status": review_status,
            "assessment": "not_conclusive",
            "note": (
                "Consolidated forensic findings represent "
                "observations from available analyses. They do "
                "not by themselves prove tampering, authenticity, "
                "or origin."
            ),
        }
