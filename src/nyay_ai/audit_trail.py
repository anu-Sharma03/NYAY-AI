"""
NYAYAI - Forensic Audit Trail
Module Lead: Anu Sharma (Forensic & AI Analysis Engineer)

Records a chronological audit trail of forensic evidence actions.

The audit trail:
- Records forensic actions without modifying evidence.
- Stores evidence identifiers and analysis information.
- Records SHA-256 values when available.
- Adds a UTC timestamp to every event.
- Supports chronological forensic activity tracking.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class ForensicAuditTrail:
    """
    Maintain a structured audit trail for forensic evidence.
    """

    def __init__(self) -> None:
        """Initialize an empty audit trail."""
        self._events: List[Dict[str, Any]] = []

    def record_event(
        self,
        evidence_id: str,
        action: str,
        analysis_type: Optional[str] = None,
        sha256: Optional[str] = None,
        description: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Record one forensic evidence action.
        """

        event = {
            "evidence_id": evidence_id,
            "action": action,
            "analysis_type": analysis_type,
            "sha256": sha256,
            "description": description,
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),
        }

        self._events.append(event)

        return event

    def get_events(self) -> List[Dict[str, Any]]:
        """
        Return all recorded audit events in chronological order.
        """

        return list(self._events)

    def get_events_for_evidence(
        self,
        evidence_id: str,
    ) -> List[Dict[str, Any]]:
        """
        Return audit events associated with one evidence item.
        """

        return [
            event
            for event in self._events
            if event["evidence_id"] == evidence_id
        ]

    def event_count(self) -> int:
        """
        Return the total number of recorded audit events.
        """

        return len(self._events)
