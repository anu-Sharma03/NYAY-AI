"""End-to-end integration tests for the NYAY-AI forensic pipeline."""

import os
import tempfile
import unittest

from PIL import Image

from nyay_ai.forensic.analysis_summary import ForensicAnalysisSummary
from nyay_ai.forensic.audit_trail import ForensicAuditTrail
from nyay_ai.forensic.consolidated_findings import (
    ConsolidatedForensicFindings,
)
from nyay_ai.forensic.evidence_record import EvidenceAnalysisRecord
from nyay_ai.forensic.image_analyzer import ForensicImageAnalyzer
from nyay_ai.forensic.forensic_report import UnifiedForensicReport


class TestForensicIntegration(unittest.TestCase):
    """Test the complete forensic analysis workflow."""

    def setUp(self) -> None:
        """Create a temporary evidence image."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.image_path = os.path.join(
            self.temp_dir.name,
            "evidence.png",
        )

        image = Image.new("RGB", (100, 100), "white")
        image.save(self.image_path)

        self.evidence_id = "EVIDENCE-001"

    def tearDown(self) -> None:
        """Remove the temporary evidence file."""
        self.temp_dir.cleanup()

    def test_complete_forensic_pipeline(self) -> None:
        """Verify that forensic modules work together."""

        # 1. Analyze the evidence image.
        analyzer = ForensicImageAnalyzer()
        analysis_result = analyzer.analyze(self.image_path)

        self.assertEqual(
            analysis_result["analysis_type"],
            "image",
        )
        self.assertTrue(analysis_result["sha256"])

        # 2. Create the evidence analysis record.
        record_builder = EvidenceAnalysisRecord()
        record = record_builder.create_record(
            evidence_id=self.evidence_id,
            file_path=self.image_path,
            analysis_type="image",
            analysis_result=analysis_result,
        )

        self.assertEqual(
            record["evidence_id"],
            self.evidence_id,
        )
        self.assertEqual(
            record["sha256"],
            analysis_result["sha256"],
        )

        # 3. Create the analysis summary.
        summary_builder = ForensicAnalysisSummary()
        summary = summary_builder.create_summary(
            evidence_id=self.evidence_id,
            analysis_type="image",
            analysis_result=analysis_result,
        )

        self.assertEqual(
            summary["evidence_id"],
            self.evidence_id,
        )
        self
