from nyay_ai.forensic.consolidated_findings import (
    ConsolidatedForensicFindings,
)


def test_consolidates_multiple_analysis_results():
    analyzer = ConsolidatedForensicFindings()

    analysis_results = [
        {
            "analysis_type": "image",
            "sha256": "a" * 64,
            "tamper_indicators": [
                "No EXIF metadata found."
            ],
        },
        {
            "analysis_type": "video",
            "sha256": "b" * 64,
            "tamper_indicators": [],
        },
        {
            "analysis_type": "audio",
            "sha256": "c" * 64,
            "tamper_indicators": [
                "Invalid audio sample rate."
            ],
        },
    ]

    result = analyzer.consolidate(
        evidence_id="EVD-001",
        analysis_results=analysis_results,
    )

    assert result["evidence_id"] == "EVD-001"
    assert result["analysis_count"] == 3
    assert result["analysis_types"] == [
        "image",
        "video",
        "audio",
    ]
    assert result["sha256_available"] is True
    assert result["indicator_count"] == 2
    assert result["review_status"] == "further_review_required"


def test_consolidation_without_indicators():
    analyzer = ConsolidatedForensicFindings()

    analysis_results = [
        {
            "analysis_type": "image",
            "sha256": "a" * 64,
            "tamper_indicators": [],
        },
        {
            "analysis_type": "video",
            "sha256": "b" * 64,
            "tamper_indicators": [],
        },
    ]

    result = analyzer.consolidate(
        evidence_id="EVD-002",
        analysis_results=analysis_results,
    )

    assert result["analysis_count"] == 2
    assert result["indicator_count"] == 0
    assert result["forensic_indicators"] == []
    assert result["review_status"] == "no_indicators_detected"


def test_integrity_statuses_are_preserved():
    analyzer = ConsolidatedForensicFindings()

    analysis_results = [
        {
            "analysis_type": "file",
            "sha256": "a" * 64,
            "tamper_indicators": [],
            "integrity_status": "hash_match",
        },
        {
            "analysis_type": "image",
            "sha256": "b" * 64,
            "tamper_indicators": [],
            "integrity_status": "hash_mismatch",
        },
    ]

    result = analyzer.consolidate(
        evidence_id="EVD-003",
        analysis_results=analysis_results,
    )

    assert result["integrity_statuses"] == [
        "hash_match",
        "hash_mismatch",
    ]


def test_anomalies_are_supported():
    analyzer = ConsolidatedForensicFindings()

    analysis_results = [
        {
            "analysis_type": "image",
            "sha256": "a" * 64,
            "anomalies": [
                "Small image dimensions detected."
            ],
        }
    ]

    result = analyzer.consolidate(
        evidence_id="EVD-004",
        analysis_results=analysis_results,
    )

    assert result["indicator_count"] == 1
    assert (
        "Small image dimensions detected."
        in result["forensic_indicators"]
    )


def test_empty_analysis_results():
    analyzer = ConsolidatedForensicFindings()

    result = analyzer.consolidate(
        evidence_id="EVD-005",
        analysis_results=[],
    )

    assert result["analysis_count"] == 0
    assert result["analysis_types"] == []
    assert result["sha256_available"] is False
    assert result["indicator_count"] == 0
    assert result["review_status"] == "no_indicators_detected"


def test_assessment_is_not_conclusive():
    analyzer = ConsolidatedForensicFindings()

    analysis_results = [
        {
            "analysis_type": "file",
            "sha256": "a" * 64,
            "tamper_indicators": [
                "Declared MIME type does not match "
                "the file signature."
            ],
        }
    ]

    result = analyzer.consolidate(
        evidence_id="EVD-006",
        analysis_results=analysis_results,
    )

    assert result["assessment"] == "not_conclusive"
    assert "do not" in result["note"].lower()
