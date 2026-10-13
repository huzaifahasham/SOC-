
from datetime import datetime, timezone

from backend.database import (
    save_event,
    count_recent_failures,
    create_incident,
)


FAILED_LOGIN_EVENT_ID = 4625
FAILED_LOGIN_THRESHOLD = 12
TIME_WINDOW_MINUTES = 5


def analyze_event(event):
    """
    Analyze one normalized Windows security event.

    Event timestamps must be ISO-8601 strings.
    """
    required = (
        "event_key",
        "computer_name",
        "channel",
        "event_id",
        "timestamp",
    )

    missing = [key for key in required if key not in event]
    if missing:
        raise ValueError(f"Missing event fields: {missing}")

    try:
        parsed_time = datetime.fromisoformat(
            event["timestamp"].replace("Z", "+00:00")
        )
        if parsed_time.tzinfo is None:
            raise ValueError("Timestamp must include a timezone")
        if parsed_time > datetime.now(timezone.utc):
            raise ValueError("Future timestamps are not accepted")
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid event timestamp: {exc}") from exc

    if not save_event(event):
        return {
            "accepted": False,
            "reason": "Duplicate event ignored",
            "incident_id": None,
        }

    if event["event_id"] != FAILED_LOGIN_EVENT_ID:
        return {
            "accepted": True,
            "reason": "Event stored; no matching detection rule",
            "incident_id": None,
        }

    source_ip = event.get("source_ip")
    if not source_ip or source_ip in {"-", "0.0.0.0", "::"}:
        return {
            "accepted": True,
            "reason": "Failed login stored; no usable source IP",
            "incident_id": None,
        }

    count = count_recent_failures(
        computer_name=event["computer_name"],
        source_ip=source_ip,
        minutes=TIME_WINDOW_MINUTES,
    )

    incident_id = create_incident(
        event,
        count,
        threshold=FAILED_LOGIN_THRESHOLD,
    )

    return {
        "accepted": True,
        "reason": (
            "Detection threshold reached"
            if count >= FAILED_LOGIN_THRESHOLD
            else "Failed login recorded"
        ),
        "failed_attempts": count,
        "threshold": FAILED_LOGIN_THRESHOLD,
        "incident_id": incident_id,
    }
