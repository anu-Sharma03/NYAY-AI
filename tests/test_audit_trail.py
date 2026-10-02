from nyay_ai.forensic.audit_trail import ForensicAuditTrail


def test_audit_trail_starts_empty():
    trail = ForensicAuditTrail()

    assert trail.event_count() == 0
    assert trail.get_events() == []


def test_record_event():
    trail = ForensicAuditTrail()

    event = trail.record_event(
        evidence_id="EVD-001",
        action="evidence_received",
        analysis_type="image",
        sha256="a" * 64,
        description="Evidence received for forensic analysis.",
    )

    assert event["evidence_id"] == "EVD-001"
    assert event["action"] == "evidence_received"
    assert event["analysis_type"] == "image"
    assert event["sha256"] == "a" * 64
    assert event["description"] == (
        "Evidence received for forensic analysis."
    )
    assert event["timestamp"] is not None
    assert trail.event_count() == 1


def test_multiple_events_are_kept_in_order():
    trail = ForensicAuditTrail()

    first = trail.record_event(
        evidence_id="EVD-002",
        action="hash_calculated",
        sha256="b" * 64,
    )

    second = trail.record_event(
        evidence_id="EVD-002",
        action="analysis_completed",
        analysis_type="image",
        sha256="b" * 64,
    )

    events = trail.get_events()

    assert len(events) == 2
    assert events[0] == first
    assert events[1] == second


def test_events_can_be_filtered_by_evidence_id():
    trail = ForensicAuditTrail()

    trail.record_event(
        evidence_id="EVD-003",
        action="evidence_received",
    )

    trail.record_event(
        evidence_id="EVD-004",
        action="evidence_received",
    )

    trail.record_event(
        evidence_id="EVD-003",
        action="analysis_completed",
        analysis_type="video",
    )

    events = trail.get_events_for_evidence("EVD-003")

    assert len(events) == 2
    assert all(
        event["evidence_id"] == "EVD-003"
        for event in events
    )


def test_optional_fields_can_be_empty():
    trail = ForensicAuditTrail()

    event = trail.record_event(
        evidence_id="EVD-005",
        action="evidence_received",
    )

    assert event["analysis_type"] is None
    assert event["sha256"] is None
    assert event["description"] is None


def test_get_events_returns_a_copy():
    trail = ForensicAuditTrail()

    trail.record_event(
        evidence_id="EVD-006",
        action="hash_calculated",
    )

    events = trail.get_events()
    events.clear()

    assert trail.event_count() == 1


def test_audit_event_has_timestamp():
    trail = ForensicAuditTrail()

    event = trail.record_event(
        evidence_id="EVD-007",
        action="report_generated",
    )

    assert "timestamp" in event
    assert event["timestamp"] != ""
