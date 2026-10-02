from nyay_ai.forensic.integrity_verifier import (
    EvidenceIntegrityVerifier,
)


def test_sha256_is_generated(tmp_path):
    verifier = EvidenceIntegrityVerifier()

    evidence_path = tmp_path / "evidence.txt"
    evidence_path.write_text("Original evidence data")

    sha256 = verifier.calculate_sha256(
        str(evidence_path)
    )

    assert sha256 is not None
    assert len(sha256) == 64


def test_matching_hash_returns_hash_match(tmp_path):
    verifier = EvidenceIntegrityVerifier()

    evidence_path = tmp_path / "evidence.txt"
    evidence_path.write_text("Original evidence data")

    recorded_hash = verifier.calculate_sha256(
        str(evidence_path)
    )

    result = verifier.verify(
        str(evidence_path),
        recorded_hash,
    )

    assert result["hashes_match"] is True
    assert result["integrity_status"] == "hash_match"


def test_changed_file_returns_hash_mismatch(tmp_path):
    verifier = EvidenceIntegrityVerifier()

    evidence_path = tmp_path / "evidence.txt"
    evidence_path.write_text("Original evidence data")

    recorded_hash = verifier.calculate_sha256(
        str(evidence_path)
    )

    evidence_path.write_text("Changed evidence data")

    result = verifier.verify(
        str(evidence_path),
        recorded_hash,
    )

    assert result["hashes_match"] is False
    assert result["integrity_status"] == "hash_mismatch"


def test_recorded_hash_is_normalized(tmp_path):
    verifier = EvidenceIntegrityVerifier()

    evidence_path = tmp_path / "evidence.txt"
    evidence_path.write_text("Evidence data")

    recorded_hash = verifier.calculate_sha256(
        str(evidence_path)
    )

    result = verifier.verify(
        str(evidence_path),
        recorded_hash.upper(),
    )

    assert result["hashes_match"] is True
    assert result["recorded_sha256"] == recorded_hash


def test_original_evidence_is_not_modified(tmp_path):
    verifier = EvidenceIntegrityVerifier()

    evidence_path = tmp_path / "evidence.txt"
    evidence_path.write_text("Original evidence data")

    original_hash = verifier.calculate_sha256(
        str(evidence_path)
    )

    verifier.verify(
        str(evidence_path),
        original_hash,
    )

    final_hash = verifier.calculate_sha256(
        str(evidence_path)
    )

    assert original_hash == final_hash


def test_assessment_is_not_conclusive(tmp_path):
    verifier = EvidenceIntegrityVerifier()

    evidence_path = tmp_path / "evidence.txt"
    evidence_path.write_text("Evidence data")

    recorded_hash = verifier.calculate_sha256(
        str(evidence_path)
    )

    result = verifier.verify(
        str(evidence_path),
        recorded_hash,
    )

    assert result["assessment"] == "not_conclusive"
    assert "does not by" in result["note"]


def test_missing_file_raises_error(tmp_path):
    verifier = EvidenceIntegrityVerifier()

    missing_path = tmp_path / "missing.txt"

    try:
        verifier.calculate_sha256(
            str(missing_path)
        )
        assert False, "Expected FileNotFoundError"
    except FileNotFoundError:
        assert True
