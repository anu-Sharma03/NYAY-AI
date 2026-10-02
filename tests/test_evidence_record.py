from nyay_ai.forensic.evidence_record import EvidenceAnalysisRecord


def test_create_evidence_record():
    recorder = EvidenceAnalysisRecord()

    analysis_result = {
        "analysis_type": "image",
        "sha256": "a" * 64,
        "format": "JPEG",
        "width": 1920,
        "height": 1080,
        "tamper_indicators": [],
    }

    record = recorder.create_record(
        evidence_id="EVD-001",
        file_path="evidence.jpg",
        analysis_type="image",
        analysis_result=analysis_result,
    )

    assert record["evidence_id"] == "EVD-001"
    assert record["file_path"] == "evidence.jpg"
    assert record["analysis_type"] == "image"
    assert record["sha256"] == "a" * 64


def test_evidence_integrity_is_verified_when_hash_exists():
    recorder = EvidenceAnalysisRecord()

    analysis_result = {
        "sha256": "b" * 64,
        "tamper_indicators": [],
    }

    record = recorder.create_record(
        evidence_id="EVD-002",
        file_path="video.mp4",
        analysis_type="video",
        analysis_result=analysis_result,
    )

    assert record["integrity_verified"] is True


def test_evidence_integrity_is_false_without_hash():
    recorder = EvidenceAnalysisRecord()

    analysis_result = {
        "sha256": None,
        "tamper_indicators": [],
    }

    record = recorder.create_record(
        evidence_id="EVD-003",
        file_path="audio.wav",
        analysis_type="audio",
        analysis_result=analysis_result,
    )

    assert record["integrity_verified"] is False


def test_forensic_indicators_are_preserved():
    recorder = EvidenceAnalysisRecord()

    analysis_result = {
        "sha256": "c" * 64,
        "tamper_indicators": [
            "No EXIF metadata found."
        ],
    }

    record = recorder.create_record(
        evidence_id="EVD-004",
        file_path="photo.jpg",
        analysis_type="image",
        analysis_result=analysis_result,
    )

    assert len(record["forensic_indicators"]) == 1
    assert (
        "No EXIF metadata found."
        in record["forensic_indicators"]
    )


def test_analysis_timestamp_is_created():
    recorder = EvidenceAnalysisRecord()

    analysis_result = {
        "sha256": "d" * 64,
        "tamper_indicators": [],
    }

    record = recorder.create_record(
        evidence_id="EVD-005",
        file_path="document.pdf",
        analysis_type="file",
        analysis_result=analysis_result,
    )

    assert "analysis_timestamp" in record
    assert record["analysis_timestamp"] is not None


def test_findings_contain_original_analysis_result():
    recorder = EvidenceAnalysisRecord()

    analysis_result = {
        "sha256": "e" * 64,
        "format": "PNG",
        "width": 100,
        "height": 100,
        "tamper_indicators": [],
    }

    record = recorder.create_record(
        evidence_id="EVD-006",
        file_path="evidence.png",
        analysis_type="image",
        analysis_result=analysis_result,
    )

    assert record["findings"] == analysis_result
