
import datetime
import logging
import threading

try:
    import win32evtlog
except ImportError:
    win32evtlog = None


logger = logging.getLogger("CyberSentinel.LogCollector")

# In-memory checkpoints for each Windows event channel.
# These reset when the application process restarts.
_last_processed_record = {}
_checkpoint_lock = threading.Lock()


def _timestamp_to_iso(value):
    """Convert Windows event time to an ISO-8601 timestamp."""
    try:
        dt = datetime.datetime(
            value.year,
            value.month,
            value.day,
            value.hour,
            value.minute,
            value.second,
            getattr(value, "microsecond", 0),
        )
        return dt.astimezone().astimezone(
            datetime.timezone.utc
        ).isoformat()
    except (AttributeError, TypeError, ValueError):
        return datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat()


def _get_source_ip(event_id, inserts):
    # Event 4625 insertion-string positions can vary by event version.
    # Keep the existing extraction behavior for now.
    if event_id == 4625 and inserts and len(inserts) > 19:
        ip = str(inserts[19]).strip()
        if ip not in {"", "-", "0.0.0.0", "::"}:
            return ip
    return None


def _get_username(event_id, inserts):
    if event_id in {4624, 4625} and inserts and len(inserts) > 5:
        name = str(inserts[5]).strip()
        if name and name != "-":
            return name
    return None


def collect_events(channel="Security", limit=200):
    """
    Read recent events from a local Windows Event Log channel.

    Only events with record numbers newer than the last acknowledged
    checkpoint are returned. Call mark_events_processed() after
    successfully processing the returned events.
    """
    if win32evtlog is None:
        raise RuntimeError(
            "pywin32 is unavailable. Install it using "
            "'python -m pip install pywin32'."
        )

    allowed_channels = {"Security", "ForwardedEvents"}
    if channel not in allowed_channels:
        raise ValueError("Unsupported Windows event channel")

    if not 1 <= limit <= 2000:
        raise ValueError("limit must be between 1 and 2000")

    handle = win32evtlog.OpenEventLog(".", channel)
    records = []

    try:
        flags = (
            win32evtlog.EVENTLOG_BACKWARDS_READ
            | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        )

        while len(records) < limit:
            batch = win32evtlog.ReadEventLog(handle, flags, 0)
            if not batch:
                break

            records.extend(batch[:limit - len(records)])

    finally:
        win32evtlog.CloseEventLog(handle)

    # ReadEventLog returned newest-first. Process oldest-first.
    records.reverse()

    if not records:
        return []

    record_numbers = [int(item.RecordNumber) for item in records]
    newest_record = max(record_numbers)

    with _checkpoint_lock:
        checkpoint = _last_processed_record.get(channel)

        # Handle a channel that was cleared or whose record numbering
        # restarted. Re-scan the recent batch in that case.
        if checkpoint is not None and newest_record < checkpoint:
            logger.warning(
                "%s record numbering moved backwards; resetting checkpoint",
                channel,
            )
            checkpoint = None
            _last_processed_record.pop(channel, None)

    if checkpoint is not None:
        records = [
            item for item in records
            if int(item.RecordNumber) > checkpoint
        ]

        if records:
            first_new_record = min(
                int(item.RecordNumber) for item in records
            )
            if first_new_record > checkpoint + 1:
                logger.warning(
                    "%s may have a collection gap: checkpoint=%s, "
                    "first_available_new_record=%s. The newest-event "
                    "batch may not contain every event.",
                    channel,
                    checkpoint,
                    first_new_record,
                )

    normalized = []

    for item in records:
        event_id = item.EventID & 0xFFFF
        inserts = item.StringInserts or []
        computer = str(
            getattr(item, "ComputerName", None) or "Unknown"
        )

        normalized.append({
            "event_key": (
                f"{computer}:{channel}:{item.RecordNumber}"
            ),
            "computer_name": computer,
            "channel": channel,
            "event_id": event_id,
            "source_ip": _get_source_ip(event_id, inserts),
            "username": _get_username(event_id, inserts),
            "timestamp": _timestamp_to_iso(item.TimeGenerated),
            "details": {
                "source": str(
                    getattr(item, "SourceName", "Unknown")
                ),
                "record_number": int(item.RecordNumber),
                "event_type": str(
                    getattr(item, "EventType", "")
                ),
            },
        })

    return normalized


def mark_events_processed(channel, events):
    """
    Advance the channel checkpoint after event processing succeeds.
    """
    if not events:
        return

    record_numbers = [
        int(event["details"]["record_number"])
        for event in events
        if event.get("details", {}).get("record_number") is not None
    ]

    if not record_numbers:
        return

    newest_processed = max(record_numbers)

    with _checkpoint_lock:
        previous = _last_processed_record.get(channel)
        if previous is None or newest_processed > previous:
            _last_processed_record[channel] = newest_processed
