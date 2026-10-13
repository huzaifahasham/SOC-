
import asyncio
import logging
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from backend.database import (
    init_db,
    list_incidents,
    update_incident_status,
)
from backend.detection_engine import analyze_event
from backend.log_collector import (
    collect_events,
    mark_events_processed,
)


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("CyberSentinel")

MONITOR_INTERVAL_SECONDS = 30
MONITOR_BATCH_LIMIT = 200


def collect_channel(channel, limit):
    """Collect events, analyze them, then acknowledge the checkpoint."""
    try:
        events = collect_events(channel, limit)

        # Process all returned events before advancing the checkpoint.
        results = [analyze_event(event) for event in events]

        mark_events_processed(channel, events)

        return {
            "channel": channel,
            "events_read": len(events),
            "new_events": sum(
                1 for result in results if result["accepted"]
            ),
            "incidents": [
                result["incident_id"]
                for result in results
                if result["incident_id"] is not None
            ],
            "results": results,
        }

    except Exception as exc:
        logger.exception("Failed to collect or process %s events", channel)
        raise HTTPException(
            status_code=500,
            detail=f"Could not process {channel} events: {exc}",
        ) from exc


async def automatic_forwarded_monitor():
    logger.info(
        "Automatic ForwardedEvents monitoring started; interval=%s seconds",
        MONITOR_INTERVAL_SECONDS,
    )

    while True:
        try:
            summary = await asyncio.to_thread(
                collect_channel,
                "ForwardedEvents",
                MONITOR_BATCH_LIMIT,
            )

            logger.info(
                "ForwardedEvents check: read=%s, accepted=%s, incidents=%s",
                summary["events_read"],
                summary["new_events"],
                len(summary["incidents"]),
            )

        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Automatic event collection failed")

        await asyncio.sleep(MONITOR_INTERVAL_SECONDS)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()

    monitor_task = asyncio.create_task(
        automatic_forwarded_monitor()
    )
    app.state.monitor_task = monitor_task

    try:
        yield
    finally:
        monitor_task.cancel()
        try:
            await monitor_task
        except asyncio.CancelledError:
            logger.info("Automatic monitoring stopped")


app = FastAPI(
    title="CyberSentinel",
    description="Centralized security log monitoring API",
    version="1.2.0",
    lifespan=lifespan,
)


class StatusUpdate(BaseModel):
    status: str
    note: str = Field(default="", max_length=1000)


class TestEventRequest(BaseModel):
    computer_name: str = "TEST-WINDOWS-PC"
    source_ip: str = "192.168.1.50"


@app.get("/health")
def health():
    return {
        "status": "running",
        "application": "CyberSentinel",
        "automatic_monitoring": "enabled",
        "monitor_channel": "ForwardedEvents",
        "monitor_interval_seconds": MONITOR_INTERVAL_SECONDS,
    }


@app.get("/incidents")
def get_incidents():
    return list_incidents()


@app.patch("/incidents/{incident_id}/status")
def change_incident_status(
    incident_id: int,
    update: StatusUpdate,
):
    try:
        updated = update_incident_status(
            incident_id,
            update.status,
            update.note,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    if not updated:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    return {
        "updated": True,
        "incident_id": incident_id,
    }


@app.post("/collect/local")
def collect_local_security_events(limit: int = 200):
    return collect_channel("Security", limit)


@app.post("/collect/forwarded")
def collect_forwarded_security_events(limit: int = 200):
    return collect_channel("ForwardedEvents", limit)


@app.post("/events/test-failed-logins")
def test_failed_logins(data: TestEventRequest):
    """Generate synthetic test events; no actual logins are attempted."""
    now = datetime.now(timezone.utc)
    results = []

    for i in range(12):
        event = {
            "event_key": f"TEST:{uuid.uuid4()}",
            "computer_name": data.computer_name,
            "channel": "TEST",
            "event_id": 4625,
            "source_ip": data.source_ip,
            "username": "test-user",
            "timestamp": now.isoformat(),
            "details": {
                "synthetic": True,
                "test_attempt": i + 1,
            },
        }
        results.append(analyze_event(event))

    return {
        "test_only": True,
        "generated_events": len(results),
        "incident_ids": list(dict.fromkeys(
            result["incident_id"]
            for result in results
            if result["incident_id"] is not None
        )),
        "results": results,
    }
