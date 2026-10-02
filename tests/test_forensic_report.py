from nyay_ai.forensic.forensic_report import UnifiedForensicReport


def test_unified_forensic_report():
    reporter = UnifiedForensicReport()

    analysis_result = {
        "analysis_type": "image",
        "sha256": "a" * 64,
        "format": "JPEG",
        "width": 100,
        "height": 100,
        "tamper_indicators": [],
    }

    report = reporter.generate(
        "evidence.jpg",
        "image",
        analysis_result,
    )

    assert report["report_type"] == "unified_forensic_report"
    assert report["evidence"]["file_path"] == "evidence.jpg"
    assert report["evidence"]["evidence_type"] == "image"
    assert report["evidence"]["sha256"] == "a" * 64


def test_forensic_indicators_are_preserved():
    reporter = UnifiedForensicReport()

    analysis_result = {
        "analysis_type": "image",
        "sha256": "b" * 64,
        "tamper_indicators": [
            "No EXIF metadata found."
        ],
    }

    report = reporter.generate(
        "photo.jpg",
        "image",
        analysis_result,
    )

    assert len(report["forensic_indicators"]) == 1
    assert "No EXIF metadata found." in report["forensic_indicators"]


def test_integrity_information_is_present():
    reporter = UnifiedForensicReport()

    analysis_result = {
        "analysis_type": "video",
        "sha256": "c" * 64,
        "tamper_indicators": [],
    }

    report = reporter.generate(
        "video.mp4",
        "video",
        analysis_result,
    )

    assert report["integrity"]["sha256_available"] is True
    assert report["integrity"]["original_evidence_modified"] is False


def test_assessment_is_not_conclusive():
    reporter = UnifiedForensicReport()

    analysis_result = {
        "analysis_type": "audio",
        "sha256": "d" * 64,
        "tamper_indicators": [
            "Invalid or unavailable audio sample rate detected."
        ],
    }

    report = reporter.generate(
        "audio.wav",
        "audio",
        analysis_result,
    )

    assert report["assessment"]["certainty"] == "not_conclusive"
    assert report["assessment"]["status"] == "indicators_detected"


def test_report_contains_generation_timestamp():
    reporter = UnifiedForensicReport()

    analysis_result = {
        "analysis_type": "image",
        "sha256": "e" * 64,
        "tamper_indicators": [],
    }

    report = reporter.generate(
        "evidence.png",
        "image",
        analysis_result,
    )

    assert "generated_at" in report
    assert report["generated_at"] is not None
