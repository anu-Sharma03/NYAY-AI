from nyay_ai.forensic.analysis_summary import ForensicAnalysisSummary


def test_create_summary_without_indicators():
    analyzer = ForensicAnalysisSummary()

    analysis_result = {
        "analysis_type": "image",
        "sha256": "a" * 64,
        "tamper_indicators": [],
    }

    summary = analyzer.create_summary(
        evidence_id="EVD-001",
        analysis_type="image",
        analysis_result=analysis_result,
    )

    assert summary["evidence_id"] == "EVD-001"
    assert summary["analysis_type"] == "image"
    assert summary["sha256_available"] is True
    assert summary["indicator_count"] == 0
    assert summary["review_status"] == "no_indicators_detected"
    assert summary["assessment"] == "not_conclusive"


def test_summary_detects_indicators():
    analyzer = ForensicAnalysisSummary()

    analysis_result = {
        "analysis_type": "image",
        "sha256": "b" * 64,
        "tamper_indicators": [
            "No EXIF metadata found."
        ],
    }

    summary = analyzer.create_summary(
        evidence_id="EVD-002",
        analysis_type="image",
        analysis_result=analysis_result,
    )

    assert summary["indicator_count"] == 1
    assert summary["review_status"] == "further_review_required"
    assert (
        "No EXIF metadata found."
        in summary["forensic_indicators"]
    )


def test_summary_without_sha256():
    analyzer = ForensicAnalysisSummary()

    analysis_result = {
        "analysis_type": "video",
        "sha256": None,
        "tamper_indicators": [],
    }

    summary = analyzer.create_summary(
        evidence_id="EVD-003",
        analysis_type="video",
        analysis_result=analysis_result,
    )

    assert summary["sha256_available"] is False
    assert summary["indicator_count"] == 0


def test_summary_preserves_multiple_indicators():
    analyzer = ForensicAnalysisSummary()

    analysis_result = {
        "analysis_type": "audio",
        "sha256": "c" * 64,
        "tamper_indicators": [
            "Invalid sample rate.",
            "Audio duration is zero.",
        ],
    }

    summary = analyzer.create_summary(
        evidence_id="EVD-004",
        analysis_type="audio",
        analysis_result=analysis_result,
    )

    assert summary["indicator_count"] == 2
    assert len(summary["forensic_indicators"]) == 2
    assert summary["review_status"] == "further_review_required"


def test_summary_is_not_conclusive():
    analyzer = ForensicAnalysisSummary()

    analysis_result = {
        "analysis_type": "file",
        "sha256": "d" * 64,
        "tamper_indicators": [
            "Declared MIME type does not match the file signature."
        ],
    }

    summary = analyzer.create_summary(
        evidence_id="EVD-005",
        analysis_type="file",
        analysis_result=analysis_result,
    )

    assert summary["assessment"] == "not_conclusive"
    assert "do not" in summary["note"].lower()
