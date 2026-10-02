from nyay_ai.forensic.evidence_comparator import (
    EvidenceComparator,
)


def test_matching_hashes_are_detected():
    comparator = EvidenceComparator()

    result = comparator.compare(
        evidence_a_id="EVD-001",
        evidence_a_sha256="a" * 64,
        evidence_b_id="EVD-002",
        evidence_b_sha256="a" * 64,
    )

    assert result["evidence_a_id"] == "EVD-001"
    assert result["evidence_b_id"] == "EVD-002"
    assert result["hashes_match"] is True
    assert result["comparison_status"] == "same_content_hash"


def test_different_hashes_are_detected():
    comparator = EvidenceComparator()

    result = comparator.compare(
        evidence_a_id="EVD-003",
        evidence_a_sha256="a" * 64,
        evidence_b_id="EVD-004",
        evidence_b_sha256="b" * 64,
    )

    assert result["hashes_match"] is False
    assert result["comparison_status"] == (
        "different_content_hash"
    )


def test_hash_comparison_is_case_insensitive():
    comparator = EvidenceComparator()

    result = comparator.compare(
        evidence_a_id="EVD-005",
        evidence_a_sha256="A" * 64,
        evidence_b_id="EVD-006",
        evidence_b_sha256="a" * 64,
    )

    assert result["hashes_match"] is True
    assert result["evidence_a_sha256"] == "a" * 64
    assert result["evidence_b_sha256"] == "a" * 64


def test_hash_comparison_ignores_whitespace():
    comparator = EvidenceComparator()

    result = comparator.compare(
        evidence_a_id="EVD-007",
        evidence_a_sha256="  " + ("a" * 64) + "  ",
        evidence_b_id="EVD-008",
        evidence_b_sha256="a" * 64,
    )

    assert result["hashes_match"] is True


def test_assessment_is_not_conclusive():
    comparator = EvidenceComparator()

    result = comparator.compare(
        evidence_a_id="EVD-009",
        evidence_a_sha256="a" * 64,
        evidence_b_id="EVD-010",
        evidence_b_sha256="b" * 64,
    )

    assert result["assessment"] == "not_conclusive"
    assert "does not by itself prove" in result["note"]


def test_hash_values_are_preserved_in_result():
    comparator = EvidenceComparator()

    hash_a = "1" * 64
    hash_b = "2" * 64

    result = comparator.compare(
        evidence_a_id="EVD-011",
        evidence_a_sha256=hash_a,
        evidence_b_id="EVD-012",
        evidence_b_sha256=hash_b,
    )

    assert result["evidence_a_sha256"] == hash_a
    assert result["evidence_b_sha256"] == hash_b
